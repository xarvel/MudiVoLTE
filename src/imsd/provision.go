package main

// Phone setup by QR code. Linphone (Android, iOS, desktop) supports remote
// provisioning: it fetches XML in the linphonerc format from the link in the
// QR code and applies it, with transient_provisioning=1 only once, without
// downloading it again at every start (wiki.linphone.org, "Remote
// Provisioning"). Link: http://<LAN>:<provision_port>/p/<token>, where the
// token is an HMAC-SHA256 of the phone's login and password under a random
// key from /etc/mudi-volte/provision.key. Once the password changes or the
// phone is removed, the old link stops working; it cannot be guessed (96
// bits). The server listens only on the LAN address and answers only
// addresses from the LAN subnet. Instead of the password the XML carries the
// digest HA1 (MD5 of login:realm:password), as in the Linphone sample. The
// link is plain HTTP: before it the phone has nothing to check a certificate
// of the router against, so the moment of setup is the one time the sign-in
// data crosses the Wi-Fi in the clear.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	defaultProvisionKeyFile = "/etc/mudi-volte/provision.key"
	provisionTokenLen       = 24 // hex characters: 96 bits
)

// provisionKey returns the link key from the file; when the file is missing
// or corrupted, a new one (0600). Two processes creating the key at the same
// time re-read the file after writing and get the same key.
func provisionKey(path string) ([]byte, error) {
	if path == "" {
		path = defaultProvisionKeyFile
	}
	if k, err := readProvisionKey(path); err == nil {
		return k, nil
	} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errBadKey) {
		return nil, err
	}
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, []byte(hex.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, err
	}
	return readProvisionKey(path)
}

var errBadKey = errors.New("provision key: bad file")

func readProvisionKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	k, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(k) < 16 {
		return nil, errBadKey
	}
	return k, nil
}

func provisionToken(key []byte, user, pass string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(user))
	m.Write([]byte{0})
	m.Write([]byte(pass))
	return hex.EncodeToString(m.Sum(nil))[:provisionTokenLen]
}

func provisionURL(ip net.IP, port int, token string) string {
	return "http://" + net.JoinHostPort(ip.String(), strconv.Itoa(port)) + "/p/" + token
}

// phoneProvisionURL returns the link for phone user from the daemon config
// (for the CLI).
func phoneProvisionURL(cfg *Config, user string) (string, error) {
	if cfg.SIP == nil {
		return "", errors.New("the SIP server for phones is not configured")
	}
	sc := cfg.SIP.withDefaults()
	if sc.ProvisionPort <= 0 {
		return "", errors.New("phone setup by QR code is turned off (provision_port 0)")
	}
	ip, _, err := sc.listenAddr()
	if err != nil {
		return "", err
	}
	for _, a := range sc.Accounts {
		if a.User != user {
			continue
		}
		key, err := provisionKey(sc.ProvisionKeyFile)
		if err != nil {
			return "", err
		}
		return provisionURL(ip, sc.ProvisionPort, provisionToken(key, a.User, a.Password)), nil
	}
	return "", fmt.Errorf("no phone named %q", user)
}

// provisioner is the HTTP server for the links from QR codes.
type provisioner struct {
	cfg     SIPConfig
	key     []byte
	ip      net.IP
	sipPort int
	tlsPort int        // 0: the phones get UDP without encryption
	lan     *net.IPNet // nil: subnet not found, everyone is let in (the socket is on the LAN address anyway)
	name    func() string
	log     *slog.Logger
	srv     *http.Server
	addr    net.Addr
	wrong   failLimiter // wrong links per address: guessing and noise in the log
}

// startProvisioning starts the link server. sipPort is the UDP port of the
// phones' SIP server and tlsPort its TLS port (0 = no TLS); name gives the
// account label on the phone (the SIM number, when known).
func startProvisioning(cfg SIPConfig, sipPort, tlsPort int, name func() string, log *slog.Logger) (*provisioner, error) {
	ip, _, err := cfg.listenAddr()
	if err != nil {
		return nil, err
	}
	key, err := provisionKey(cfg.ProvisionKeyFile)
	if err != nil {
		return nil, fmt.Errorf("provision key: %w", err)
	}
	ln, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(cfg.ProvisionPort)))
	if err != nil {
		return nil, err
	}
	p := &provisioner{cfg: cfg, key: key, ip: ip, sipPort: sipPort, tlsPort: tlsPort, lan: lanSubnet(ip), name: name, log: log, addr: ln.Addr()}
	p.srv = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          nil,
	}
	go func() { _ = p.srv.Serve(ln) }()
	if log != nil {
		log.Info("phone setup by QR code: ready", "listen", ln.Addr().String())
	}
	return p, nil
}

func (p *provisioner) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = p.srv.Shutdown(ctx)
}

func (p *provisioner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if from := net.ParseIP(host); p.lan != nil && (from == nil || !p.lan.Contains(from)) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if p.wrong.blocked(host) {
		http.Error(w, "too many wrong links, try again later", http.StatusTooManyRequests)
		return
	}
	tok, ok := strings.CutPrefix(r.URL.Path, "/p/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	acc, ok := p.account(strings.TrimSuffix(tok, ".xml"))
	if !ok {
		blocked := p.wrong.fail(host)
		if p.log != nil {
			if blocked {
				p.log.Warn("phone setup: too many wrong links, address blocked", "from", host, "for", authBlockFor.String())
			} else {
				p.log.Warn("phone setup: unknown or outdated link", "from", host)
			}
		}
		http.NotFound(w, r)
		return
	}
	display := "Mudi"
	if p.name != nil {
		if n := p.name(); n != "" {
			display = n
		}
	}
	body := linphoneXML(acc, p.cfg.Realm, p.ip, p.sipPort, p.tlsPort, display)
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
	if p.log != nil {
		p.log.Info("phone setup: settings sent to the phone", "user", acc.User, "from", host, "encrypted", p.tlsPort != 0)
	}
}

func (p *provisioner) account(tok string) (SIPAccount, bool) {
	if len(tok) != provisionTokenLen {
		return SIPAccount{}, false
	}
	for _, a := range p.cfg.Accounts {
		if subtle.ConstantTimeCompare([]byte(provisionToken(p.key, a.User, a.Password)), []byte(tok)) == 1 {
			return a, true
		}
	}
	return SIPAccount{}, false
}

// lanSubnet returns the subnet of the interface that holds address ip.
func lanSubnet(ip net.IP) *net.IPNet {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifs {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.Equal(ip) {
				return &net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}
			}
		}
	}
	return nil
}

// entry is one name and value of a section of the provisioning XML.
type entry struct{ name, value string }

// linphoneCodecSlots is how many audio_codec_N sections we write.
// liblinphone (coreapi/linphonecore.c, codecs_config_read) reads
// audio_codec_0, 1, … up to the first empty one and for each sets the
// enabled flag on the codec from its own list; a repeat of the same codec
// does not duplicate it in the list but sets the flag again, so the last one
// wins. Codecs missing from the config are appended at the end with their
// default flags (G.722 is off there). Hence G.722 first, then PCMU and PCMA,
// and the remaining slots up to 40 are G.722 again: that way the phone's old
// entries (where G.722 may have been off) cannot override enabling it, and
// Linphone brings back the omitted codecs (Opus and the like) by itself.
const linphoneCodecSlots = 40

// linphoneXML returns the account in Linphone's remote provisioning format
// (lpconfig.xsd): the phone's first account (proxy_0/auth_info_0) points to
// the router's SIP server, over TLS with SRTP when tlsPort is set, otherwise
// over UDP without encryption. transient_provisioning=1 means apply once.
// Also: G.722 is enabled and first (wideband audio; Linphone has it off by
// default, and a call would go through 8 kHz PCMU); keep_service_alive: on
// Android, Linphone keeps its service and registration running, so the phone
// rings at once and not after waking up; publish_presence=0: our server does
// not handle presence.
//
// Encryption lives in Linphone's [sip] section and so applies to all its
// accounts (liblinphone has no per-account setting for it): SRTP mandatory,
// so that a call never goes out without it, and no check of the server
// certificate, which is self-signed (lan_tls.go). Over UDP the same entries
// are set back to Linphone's defaults, or a phone moved off TLS would refuse
// every call.
func linphoneXML(acc SIPAccount, realm string, ip net.IP, sipPort, tlsPort int, display string) []byte {
	host := ip.String()
	proxy := host
	if sipPort != 0 && sipPort != 5060 {
		proxy = net.JoinHostPort(host, strconv.Itoa(sipPort))
	}
	regProxy := "<sip:" + proxy + ";transport=udp>"
	sipEntries := []entry{{"default_proxy", "0"},
		{"media_encryption", "none"}, {"media_encryption_mandatory", "0"},
		{"verify_server_certs", "1"}, {"verify_server_cn", "1"}}
	if tlsPort != 0 {
		regProxy = "<sip:" + net.JoinHostPort(host, strconv.Itoa(tlsPort)) + ";transport=tls>"
		sipEntries = []entry{{"default_proxy", "0"},
			{"media_encryption", "srtp"}, {"media_encryption_mandatory", "1"},
			{"verify_server_certs", "0"}, {"verify_server_cn", "0"}}
	}
	sections := []struct {
		name      string
		overwrite bool
		entries   []entry
	}{
		{"misc", false, []entry{{"transient_provisioning", "1"}}},
		{"app", false, []entry{{"keep_service_alive", "1"}, {"publish_presence", "0"}}},
		{"sip", false, sipEntries},
		{"auth_info_0", true, []entry{
			{"username", acc.User},
			{"ha1", md5hex(acc.User + ":" + realm + ":" + acc.Password)},
			{"realm", realm},
			{"domain", host},
			{"algorithm", "MD5"},
		}},
		{"proxy_0", true, []entry{
			{"reg_proxy", regProxy},
			{"reg_identity", fmt.Sprintf("\"%s\" <sip:%s@%s>", sipDisplayName(display), acc.User, host)},
			{"realm", realm},
			{"reg_expires", "3600"},
			{"reg_sendregister", "1"},
			{"publish", "0"},
		}},
	}
	codecs := []entry{{"G722", "8000"}, {"PCMU", "8000"}, {"PCMA", "8000"}}
	for i := 0; i < linphoneCodecSlots; i++ {
		c := codecs[0]
		if i < len(codecs) {
			c = codecs[i]
		}
		sections = append(sections, struct {
			name      string
			overwrite bool
			entries   []entry
		}{fmt.Sprintf("audio_codec_%d", i), true, []entry{
			{"mime", c.name}, {"rate", c.value}, {"channels", "1"}, {"enabled", "1"},
		}})
	}
	var b bytes.Buffer
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<config xmlns="http://www.linphone.org/xsds/lpconfig.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.linphone.org/xsds/lpconfig.xsd lpconfig.xsd">` + "\n")
	for _, s := range sections {
		if s.overwrite {
			fmt.Fprintf(&b, "  <section name=%q overwrite=\"true\">\n", s.name)
		} else {
			fmt.Fprintf(&b, "  <section name=%q>\n", s.name)
		}
		for _, e := range s.entries {
			fmt.Fprintf(&b, "    <entry name=%q overwrite=\"true\">", e.name)
			_ = xml.EscapeText(&b, []byte(e.value))
			b.WriteString("</entry>\n")
		}
		b.WriteString("  </section>\n")
	}
	b.WriteString("</config>\n")
	return b.Bytes()
}

// sipDisplayName returns the account label for a SIP quoted string: safe
// characters only.
func sipDisplayName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("+ ._-()", r):
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "Mudi"
	}
	return b.String()
}
