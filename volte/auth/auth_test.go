package auth

import (
	"bytes"
	"strings"
	"testing"
)

const (
	testRealm = "ims.mnc001.mcc001.3gppnetwork.org"
	testIMPI  = "001010123456789@ims.mnc001.mcc001.3gppnetwork.org"
	testNonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" // base64(0x00..0x1f)
)

// RFC 2617 §3.5 worked example.
func TestDigestResponseRFC2617(t *testing.T) {
	r := Request{Username: "Mufasa", Method: "GET", URI: "/dir/index.html"}
	got := digestResponse(r, "testrealm@host.com", "dcd98b7102dd2f0e8b11d0f600bfb0c093",
		[]byte("Circle Of Life"), "auth", "00000001", "0a4f113b")
	if want := "6629fae49393a05397450978507c4ef1"; got != want {
		t.Fatalf("response = %s, want %s", got, want)
	}
}

func TestParseChallengeAndRandAutn(t *testing.T) {
	h := `Digest realm="` + testRealm + `", nonce="` + testNonce + `", algorithm=AKAv1-MD5, qop="auth,auth-int", opaque="x,y"`
	c, err := ParseChallenge(h)
	if err != nil {
		t.Fatal(err)
	}
	if c.Realm != testRealm || c.Algorithm != AlgAKAv1MD5 || c.Opaque != "x,y" {
		t.Fatalf("parsed %+v", c)
	}
	if len(c.Qop) != 2 || c.pickQop() != "auth" {
		t.Fatalf("qop %v", c.Qop)
	}
	rand, autn, err := c.RandAutn()
	if err != nil {
		t.Fatal(err)
	}
	if rand[0] != 0x00 || rand[15] != 0x0f || autn[0] != 0x10 || autn[15] != 0x1f {
		t.Fatalf("rand %x autn %x", rand, autn)
	}
}

// Expected values computed independently with Python hashlib.
func TestAnswerAKAv1(t *testing.T) {
	c := &Challenge{Realm: testRealm, Nonce: testNonce, Algorithm: AlgAKAv1MD5, Qop: []string{"auth"}}
	r := Request{Username: testIMPI, Method: "REGISTER", URI: "sip:" + testRealm}
	res := []byte{0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf}
	h, err := c.Answer(r, res, 1, "deadbeef")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`response="9a3e1c7782bff7befd90654e8bc342cc"`,
		`username="` + testIMPI + `"`,
		`algorithm=AKAv1-MD5`, `qop=auth`, `nc=00000001`, `cnonce="deadbeef"`,
	} {
		if !strings.Contains(h, want) {
			t.Errorf("missing %s in %s", want, h)
		}
	}
}

func TestSyncFailureUsesEmptyPassword(t *testing.T) {
	c := &Challenge{Realm: testRealm, Nonce: testNonce, Algorithm: AlgAKAv1MD5, Qop: []string{"auth"}}
	r := Request{Username: testIMPI, Method: "REGISTER", URI: "sip:" + testRealm}
	h := c.SyncFailure(r, bytes.Repeat([]byte{0xab}, 14), 2, "cafe")
	if !strings.Contains(h, `response="92423b71ec7d92a7f0eb1786aa791e15"`) || !strings.Contains(h, `auts="q6urq6urq6urq6urq6s="`) {
		t.Fatal(h)
	}
}

func TestAnswerRejectsPlainMD5(t *testing.T) {
	c := &Challenge{Realm: testRealm, Nonce: testNonce, Algorithm: "MD5"}
	if _, err := c.Answer(Request{}, nil, 1, "x"); err == nil {
		t.Fatal("expected error")
	}
}

func TestInitialAuthorization(t *testing.T) {
	got := InitialAuthorization(testIMPI, testRealm, "sip:"+testRealm)
	want := `Digest username="` + testIMPI + `", realm="` + testRealm + `", uri="sip:` + testRealm + `", nonce="", response=""`
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}

// Shape of a live Security-Server (FINDINGS §72), SPIs replaced.
func TestSecAgreeLive(t *testing.T) {
	srv := "ipsec-3gpp;alg=hmac-md5-96;prot=esp;mod=trans;ealg=null;spi-c=11111;spi-s=22222;port-c=9950;port-s=9900"
	ms, err := ParseMechanisms(srv)
	if err != nil {
		t.Fatal(err)
	}
	m, err := Choose(ms)
	if err != nil {
		t.Fatal(err)
	}
	if m.SPIc != 11111 || m.SPIs != 22222 || m.PortC != 9950 || m.PortS != 9900 || m.Alg != "hmac-md5-96" {
		t.Fatalf("%+v", m)
	}
	if VerifyHeader(ms) != srv {
		t.Fatalf("verify %q", VerifyHeader(ms))
	}
}

func TestChoosePrefersHighestSupportedQ(t *testing.T) {
	ms, err := ParseMechanisms("digest;q=0.9, ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;q=0.5, ipsec-3gpp;alg=hmac-md5-96;ealg=null;q=0.7, ipsec-3gpp;alg=foo;q=1")
	if err != nil {
		t.Fatal(err)
	}
	m, err := Choose(ms)
	if err != nil {
		t.Fatal(err)
	}
	if m.Alg != "hmac-md5-96" || m.Q != 0.7 {
		t.Fatalf("chose %+v", m)
	}
}

func TestClientMechanismString(t *testing.T) {
	m := Mechanism{Name: MechIPsec3GPP, Alg: "hmac-md5-96", Ealg: "null", Prot: "esp", Mode: "trans",
		SPIc: 1, SPIs: 2, PortC: 5100, PortS: 5101, Q: -1}
	want := "ipsec-3gpp;alg=hmac-md5-96;ealg=null;spi-c=1;spi-s=2;port-c=5100;port-s=5101;prot=esp;mod=trans"
	if m.String() != want {
		t.Fatal(m.String())
	}
}

func TestKeys(t *testing.T) {
	ik := bytes.Repeat([]byte{1}, 16)
	ck := append(bytes.Repeat([]byte{2}, 8), bytes.Repeat([]byte{3}, 8)...)
	if k, _ := IntegrityKey("hmac-md5-96", ik); !bytes.Equal(k, ik) {
		t.Error("md5 key")
	}
	if k, _ := IntegrityKey("hmac-sha-1-96", ik); len(k) != 20 || !bytes.Equal(k[16:], []byte{0, 0, 0, 0}) {
		t.Error("sha1 key")
	}
	if k, _ := EncryptionKey("null", ck); k != nil {
		t.Error("null key")
	}
	if k, _ := EncryptionKey("des-ede3-cbc", ck); len(k) != 24 || !bytes.Equal(k[16:], ck[:8]) {
		t.Error("3des key")
	}
	if _, err := IntegrityKey("hmac-md5-96", ik[:8]); err == nil {
		t.Error("short IK accepted")
	}
}

// A hostile 401 must not be able to smuggle a header through realm/opaque.
func TestQuoteStripsLineBreaks(t *testing.T) {
	got := quote("ims\r\nVia: SIP/2.0/TCP evil\n")
	if strings.ContainsAny(got, "\r\n") || got != `"imsVia: SIP/2.0/TCP evil"` {
		t.Fatalf("quote = %q", got)
	}
	if got := quote(`a"b\c`); got != `"a\"b\\c"` {
		t.Fatalf("quote escaping = %q", got)
	}
}
