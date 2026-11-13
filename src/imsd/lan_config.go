package main

// S7: SIP bridge for the phones on the Mudi's Wi-Fi. The daemon works as a
// mini PBX: phones (Linphone and the like) register with a login and
// password, an incoming call from the network rings all registered devices,
// and a call from a phone goes out to the network through IMS (Dial). Only
// the LAN address (br-lan) is listened on.

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type SIPAccount struct {
	User     string `json:"user"`
	Password string `json:"password"`
	// Ext is the phone's short number for calls from other phones (201…); when
	// empty, the phone is called by its login.
	Ext string `json:"ext"`
}

type SIPConfig struct {
	Listen         string       `json:"listen"`          // "192.168.8.1:5060": a specific LAN IP (it also goes into the SDP)
	Transports     []string     `json:"transports"`      // ["udp","tcp","tls"]
	Realm          string       `json:"realm"`           // digest authentication realm
	Accounts       []SIPAccount `json:"accounts"`        // phone logins
	RTPPortMin     int          `json:"rtp_port_min"`    // 40000
	RTPPortMax     int          `json:"rtp_port_max"`    // 40199
	Codecs         []string     `json:"codecs"`          // order of preference: G722, PCMU, PCMA
	RingSec        int          `json:"ring_sec"`        // how long to ring the phones, s
	DialAllow      []string     `json:"dial_allow"`      // allowed outgoing prefixes (+44, +33…); "*" = any; empty = no outgoing calls
	DefaultCountry string       `json:"default_country"` // country code for numbers with a leading 0 ("44")
	EchoExt        string       `json:"echo_ext"`        // echo test number ("600"); empty = off
	JitterFrames   int          `json:"jitter_frames"`   // jitter prebuffer, in 20 ms frames
	// Phone setup by QR code (provision.go): the HTTP port on the LAN address,
	// 0 = off; the link key, empty = /etc/mudi-volte/provision.key.
	ProvisionPort    int    `json:"provision_port"`
	ProvisionKeyFile string `json:"provision_key_file"`
	// SIP over TLS (transport "tls", lan_tls.go) on its own port, 5061 by
	// default. Calls of phones signed in over TLS carry SRTP keys (lan_srtp.go).
	// The certificate and key files are made by the daemon when missing;
	// empty = /etc/mudi-volte/tls.crt and tls.key.
	TLSPort     int    `json:"tls_port"`
	TLSCertFile string `json:"tls_cert_file"`
	TLSKeyFile  string `json:"tls_key_file"`
	// Pushes that wake Linphone on an iPhone for a call (flexiapi.go,
	// ringer.go): a linphone.org account; no login = no pushes.
	Push PushConfig `json:"push"`

	PhonesFile string `json:"-"` // phone registrations file (service mode), from Config.PhonesFile
	PushFile   string `json:"-"` // phones' push parameters (service mode), from Config.PushFile
}

const (
	defaultRingSec      = 45
	defaultJitterFrames = 3
	minSIPPassword      = 10
	defaultTLSPort      = 5061
	defaultTLSCertFile  = "/etc/mudi-volte/tls.crt"
	defaultTLSKeyFile   = "/etc/mudi-volte/tls.key"
)

var knownLANCodecs = map[string]bool{"G722": true, "PCMU": true, "PCMA": true}

// withDefaults returns a copy of the config with the defaults filled in.
func (c SIPConfig) withDefaults() SIPConfig {
	if len(c.Transports) == 0 {
		c.Transports = []string{"udp", "tcp"}
	}
	if c.Realm == "" {
		c.Realm = "mudi"
	}
	if c.RTPPortMin == 0 && c.RTPPortMax == 0 {
		c.RTPPortMin, c.RTPPortMax = 40000, 40199
	}
	if len(c.Codecs) == 0 {
		c.Codecs = []string{"G722", "PCMU", "PCMA"}
	}
	for i := range c.Codecs {
		c.Codecs[i] = strings.ToUpper(strings.TrimSpace(c.Codecs[i]))
	}
	if c.RingSec <= 0 {
		c.RingSec = defaultRingSec
	}
	if c.JitterFrames <= 0 {
		c.JitterFrames = defaultJitterFrames
	}
	if c.TLSPort == 0 {
		c.TLSPort = defaultTLSPort
	}
	if c.TLSCertFile == "" {
		c.TLSCertFile = defaultTLSCertFile
	}
	if c.TLSKeyFile == "" {
		c.TLSKeyFile = defaultTLSKeyFile
	}
	return c
}

// hasTransport reports whether the server listens on transport t.
func (c SIPConfig) hasTransport(t string) bool {
	for _, x := range c.Transports {
		if x == t {
			return true
		}
	}
	return false
}

// listenAddr returns the IP and port from Listen; 0.0.0.0 will not do: the
// address goes into the SDP.
func (c SIPConfig) listenAddr() (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return nil, 0, fmt.Errorf("sip.listen %q: %w", c.Listen, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() {
		return nil, 0, fmt.Errorf("sip.listen %q: a specific LAN IPv4 address is needed (it also goes into SDP)", c.Listen)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return nil, 0, fmt.Errorf("sip.listen %q: bad port", c.Listen)
	}
	return ip.To4(), port, nil
}

func (c SIPConfig) validate() error {
	if _, _, err := c.listenAddr(); err != nil {
		return err
	}
	for _, t := range c.Transports {
		if t != "udp" && t != "tcp" && t != "tls" {
			return fmt.Errorf("sip.transports: %q is not supported (udp|tcp|tls)", t)
		}
	}
	if c.hasTransport("tls") {
		_, port, _ := c.listenAddr()
		if c.TLSPort < 0 || c.TLSPort > 65535 {
			return fmt.Errorf("sip.tls_port: bad port %d", c.TLSPort)
		}
		if c.TLSPort != 0 && c.TLSPort == port && c.hasTransport("tcp") {
			return fmt.Errorf("sip.tls_port %d: TCP already listens there", c.TLSPort)
		}
	}
	if len(c.Accounts) == 0 {
		return errors.New("sip.accounts is empty: the phones have nothing to sign in with")
	}
	seen, exts := map[string]bool{}, map[string]bool{}
	for _, a := range c.Accounts {
		if a.Ext != "" {
			if err := validExt(a.Ext, c.EchoExt); err != nil {
				return fmt.Errorf("sip.accounts: %q: %v", a.User, err)
			}
			if exts[a.Ext] {
				return fmt.Errorf("sip.accounts: short number %s is used twice", a.Ext)
			}
			exts[a.Ext] = true
		}
		if a.User == "" || strings.ContainsAny(a.User, " @:;\"") {
			return fmt.Errorf("sip.accounts: bad login %q", a.User)
		}
		if len(a.Password) < minSIPPassword {
			return fmt.Errorf("sip.accounts: the password of %q is shorter than %d characters", a.User, minSIPPassword)
		}
		if seen[a.User] {
			return fmt.Errorf("sip.accounts: login %q is used twice", a.User)
		}
		seen[a.User] = true
	}
	if c.ProvisionPort < 0 || c.ProvisionPort > 65535 {
		return fmt.Errorf("sip.provision_port: bad port %d", c.ProvisionPort)
	}
	if c.RTPPortMin <= 1024 || c.RTPPortMax <= c.RTPPortMin || c.RTPPortMax > 65535 {
		return fmt.Errorf("sip.rtp_port_min/max: bad range %d..%d", c.RTPPortMin, c.RTPPortMax)
	}
	for _, name := range c.Codecs {
		if !knownLANCodecs[name] {
			return fmt.Errorf("sip.codecs: %q is not supported (G722|PCMU|PCMA)", name)
		}
	}
	for _, p := range c.DialAllow {
		if p == "*" {
			continue
		}
		body := strings.TrimPrefix(p, "+")
		if body == "" || digitsOnly(body) != body {
			return fmt.Errorf("sip.dial_allow: %q: a prefix like +44 or an exact short number is needed", p)
		}
	}
	if c.DefaultCountry != "" && digitsOnly(c.DefaultCountry) != c.DefaultCountry {
		return fmt.Errorf("sip.default_country %q: the digits of the country code only", c.DefaultCountry)
	}
	return nil
}

// validExt checks a short number: 2–6 digits, not starting with 0 or 1 and
// not 911/999, so that no emergency, national or operator short number (112,
// 192…) ever stays inside the home; it must not clash with the echo test.
func validExt(ext, echo string) error {
	switch {
	case len(ext) < 2 || len(ext) > 6 || digitsOnly(ext) != ext:
		return fmt.Errorf("short number %q: 2 to 6 digits are needed", ext)
	case ext[0] == '0' || ext[0] == '1' || ext == "911" || ext == "999":
		return fmt.Errorf("short number %q: it cannot start with 0 or 1 or be 911/999 (emergency and service numbers)", ext)
	case ext == echo:
		return fmt.Errorf("short number %q is taken by the echo test", ext)
	}
	return nil
}

// phoneFor returns the login of the phone being called: by login
// (case-insensitive) or by short number. ok=false means the number is not
// internal.
func (c SIPConfig) phoneFor(target string) (string, bool) {
	for _, a := range c.Accounts {
		if strings.EqualFold(a.User, target) || (a.Ext != "" && a.Ext == target) {
			return a.User, true
		}
	}
	return "", false
}
