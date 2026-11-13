package main

import (
	"bytes"
	"encoding/xml"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type lpEntry struct {
	Name      string `xml:"name,attr"`
	Overwrite string `xml:"overwrite,attr"`
	Value     string `xml:",chardata"`
}

type lpSection struct {
	Name    string    `xml:"name,attr"`
	Entries []lpEntry `xml:"entry"`
}

type lpConfig struct {
	XMLName  xml.Name    `xml:"config"`
	Sections []lpSection `xml:"section"`
}

func (c lpConfig) get(section, name string) string {
	for _, s := range c.Sections {
		if s.Name != section {
			continue
		}
		for _, e := range s.Entries {
			if e.Name == name {
				return e.Value
			}
		}
	}
	return ""
}

func provisionTestConfig(t *testing.T) SIPConfig {
	t.Helper()
	return SIPConfig{
		Listen:           "127.0.0.1:5060",
		Accounts:         []SIPAccount{{User: "pixel", Password: "s3cret-pass-1"}, {User: "laptop", Password: "an0ther-pass-2"}},
		ProvisionKeyFile: filepath.Join(t.TempDir(), "mudi-volte", "provision.key"),
	}.withDefaults()
}

func TestProvisionKeyAndToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "provision.key")
	k1, err := provisionKey(path)
	if err != nil || len(k1) != 32 {
		t.Fatalf("new key: %v (%d bytes)", err, len(k1))
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode: %v %v", st, err)
	}
	k2, err := provisionKey(path)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("key is not stable: %v", err)
	}
	// A corrupted file is replaced with a new key.
	if err := os.WriteFile(path, []byte("not hex\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	k3, err := provisionKey(path)
	if err != nil || len(k3) != 32 || bytes.Equal(k3, k1) {
		t.Fatalf("broken key file not replaced: %v", err)
	}
	a := provisionToken(k1, "pixel", "pw-one-1234")
	if len(a) != provisionTokenLen || a != provisionToken(k1, "pixel", "pw-one-1234") {
		t.Fatalf("token %q", a)
	}
	if a == provisionToken(k1, "pixel", "pw-two-1234") || a == provisionToken(k1, "pixe", "lpw-one-1234") || a == provisionToken(k3, "pixel", "pw-one-1234") {
		t.Fatal("token must change with the password, the user and the key")
	}
}

func TestPhoneProvisionURL(t *testing.T) {
	sc := provisionTestConfig(t)
	sc.ProvisionPort = 8060
	cfg := &Config{SIP: &sc}
	url, err := phoneProvisionURL(cfg, "pixel")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := provisionKey(sc.ProvisionKeyFile)
	if want := "http://127.0.0.1:8060/p/" + provisionToken(key, "pixel", "s3cret-pass-1"); url != want {
		t.Fatalf("url %q, want %q", url, want)
	}
	if _, err := phoneProvisionURL(cfg, "nobody"); err == nil {
		t.Fatal("unknown phone must fail")
	}
	sc.ProvisionPort = 0
	if _, err := phoneProvisionURL(&Config{SIP: &sc}, "pixel"); err == nil {
		t.Fatal("provisioning off must fail")
	}
}

// A phone fetches its settings by the link, and the HA1 in them passes our own digest.
func TestProvisioningServesLinphoneConfig(t *testing.T) {
	sc := provisionTestConfig(t)
	p, err := startProvisioning(sc, 5062, 0, func() string { return "+447700900789" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	key, _ := provisionKey(sc.ProvisionKeyFile)
	port := p.addr.(*net.TCPAddr).Port
	base := "http://" + p.addr.String()
	client := &http.Client{Timeout: 5 * time.Second}

	res, err := client.Get(provisionURL(net.IPv4(127, 0, 0, 1), port, provisionToken(key, "pixel", "s3cret-pass-1")))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/xml") {
		t.Fatalf("status %d, type %q", res.StatusCode, res.Header.Get("Content-Type"))
	}
	var lp lpConfig
	if err := xml.Unmarshal(body, &lp); err != nil {
		t.Fatalf("xml: %v\n%s", err, body)
	}
	checks := map[[2]string]string{
		{"misc", "transient_provisioning"}: "1",
		{"sip", "default_proxy"}:           "0",
		{"auth_info_0", "username"}:        "pixel",
		{"auth_info_0", "realm"}:           "mudi",
		{"auth_info_0", "domain"}:          "127.0.0.1",
		{"auth_info_0", "algorithm"}:       "MD5",
		{"proxy_0", "reg_proxy"}:           "<sip:127.0.0.1:5062;transport=udp>",
		{"proxy_0", "reg_identity"}:        `"+447700900789" <sip:pixel@127.0.0.1>`,
		{"proxy_0", "reg_sendregister"}:    "1",
		{"app", "keep_service_alive"}:      "1",
		{"audio_codec_0", "mime"}:          "G722",
		{"audio_codec_0", "enabled"}:       "1",
		{"audio_codec_1", "mime"}:          "PCMU",
		{"audio_codec_2", "mime"}:          "PCMA",
		{"audio_codec_39", "mime"}:         "G722",
	}
	for k, want := range checks {
		if got := lp.get(k[0], k[1]); got != want {
			t.Errorf("%s/%s = %q, want %q", k[0], k[1], got, want)
		}
	}
	if bytes.Contains(body, []byte("s3cret-pass-1")) {
		t.Fatal("the plain password must not be in the XML")
	}
	// A phone with this HA1 passes the digest of our registrar.
	auth := newDigestAuth(sc.Realm, sc.Accounts)
	ha1 := lp.get("auth_info_0", "ha1")
	ch := parseDigestParams(strings.TrimPrefix(auth.challenge(false, "127.0.0.1"), "Digest "))
	nonce, uri, nc, cnonce := ch["nonce"], "sip:127.0.0.1", "00000001", "abcdef"
	resp := md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + md5hex("REGISTER:"+uri))
	hdr := `Digest username="pixel", realm="mudi", nonce="` + nonce + `", uri="` + uri + `", response="` + resp +
		`", algorithm=MD5, qop=auth, nc=` + nc + `, cnonce="` + cnonce + `"`
	if user, ok, _ := auth.verify("REGISTER", hdr, "127.0.0.1", uri); !ok || user != "pixel" {
		t.Fatalf("HA1 from the XML is rejected by the registrar (user %q)", user)
	}

	for _, path := range []string{"/p/" + strings.Repeat("0", provisionTokenLen), "/p/short", "/", "/p/"} {
		res, err := client.Get(base + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != http.StatusNotFound {
			t.Errorf("%s: status %d, want 404", path, res.StatusCode)
		}
	}
	res, err = client.Post(base+"/p/x", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: status %d", res.StatusCode)
	}
}

func TestProvisioningRejectsOtherSubnets(t *testing.T) {
	p := &provisioner{lan: &net.IPNet{IP: net.IPv4(192, 168, 8, 0), Mask: net.CIDRMask(24, 32)}}
	req, _ := http.NewRequest(http.MethodGet, "http://192.168.8.1:8060/p/x", nil)
	req.RemoteAddr = "192.168.9.20:5555"
	rec := &recorder{h: http.Header{}}
	p.ServeHTTP(rec, req)
	if rec.code != http.StatusForbidden {
		t.Fatalf("guest subnet: status %d", rec.code)
	}
}

// Wrong links from one address: after the tenth the address is blocked, even
// with the right link; other addresses are not affected.
func TestProvisioningLimitsWrongLinks(t *testing.T) {
	sc := provisionTestConfig(t)
	p, err := startProvisioning(sc, 5062, 0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.lan = nil
	key, _ := provisionKey(sc.ProvisionKeyFile)
	get := func(from, tok string) int {
		req, _ := http.NewRequest(http.MethodGet, "http://192.168.8.1:8060/p/"+tok, nil)
		req.RemoteAddr = from + ":5555"
		rec := &recorder{h: http.Header{}, code: http.StatusOK}
		p.ServeHTTP(rec, req)
		return rec.code
	}
	good := provisionToken(key, "pixel", "s3cret-pass-1")
	for i := 0; i < authFailLimit; i++ {
		if code := get("192.168.8.50", strings.Repeat("0", provisionTokenLen)); code != http.StatusNotFound {
			t.Fatalf("wrong link %d: status %d", i+1, code)
		}
	}
	if code := get("192.168.8.50", good); code != http.StatusTooManyRequests {
		t.Errorf("blocked address with the right link: status %d", code)
	}
	if code := get("192.168.8.51", good); code != http.StatusOK {
		t.Errorf("another address: status %d", code)
	}
}

type recorder struct {
	h    http.Header
	code int
	buf  bytes.Buffer
}

func (r *recorder) Header() http.Header         { return r.h }
func (r *recorder) Write(b []byte) (int, error) { return r.buf.Write(b) }
func (r *recorder) WriteHeader(code int)        { r.code = code }

func TestQRRendering(t *testing.T) {
	const url = "http://192.168.8.1:8060/p/0123456789abcdef01234567"
	c, err := qrEncode(url)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := writeQRTerminal(&b, url); err != nil {
		t.Fatal(err)
	}
	n := c.Size + 2*qrQuiet
	if lines := strings.Count(b.String(), "\n"); lines != (n+1)/2 {
		t.Fatalf("terminal QR: %d lines, want %d", lines, (n+1)/2)
	}
	svg, err := qrSVG(url)
	if err != nil || !strings.HasPrefix(svg, "<svg") || !strings.Contains(svg, "h1v1h-1z") {
		t.Fatalf("svg: %v %.80s", err, svg)
	}
}

func TestRotatingLogFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log", "mudi-volte.log")
	r, err := openRotatingFile(path, 100)
	if err != nil {
		t.Fatal(err)
	}
	line := []byte(strings.Repeat("x", 39) + "\n")
	for i := 0; i < 6; i++ {
		if _, err := r.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()
	cur, _ := os.ReadFile(path)
	old, _ := os.ReadFile(path + ".1")
	if len(cur) != 80 || len(old) != 80 {
		t.Fatalf("current %d bytes, .1 %d bytes; want 80 and 80", len(cur), len(old))
	}
	// Opening again appends rather than truncates.
	r, _ = openRotatingFile(path, 1000)
	r.Write(line)
	r.Close()
	if cur, _ = os.ReadFile(path); len(cur) != 120 {
		t.Fatalf("append after reopen: %d bytes", len(cur))
	}
}
