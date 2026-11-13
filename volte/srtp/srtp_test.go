package srtp

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 3711 Appendix B.2: the AES-CM keystream for a session key and salt,
// SSRC 0 and packet index 0, at the start and at the end of a 65282-block
// segment.
func TestAESCMKeystreamRFC3711(t *testing.T) {
	block, err := aes.NewCipher(unhex(t, "2B7E151628AED2A6ABF7158809CF4F3C"))
	if err != nil {
		t.Fatal(err)
	}
	c := &Context{suite: AES128CMSHA1_80, block: block}
	copy(c.salt[:], unhex(t, "F0F1F2F3F4F5F6F7F8F9FAFBFCFD"))
	ks := make([]byte, 65282*16)
	c.crypt(ks, 0, 0)
	want := map[int]string{
		0:      "E03EAD0935C95E80E166B16DD92B4EB4",
		1:      "D23513162B02D0F72A43A2FE4A5F97AB",
		2:      "41E95B3BB0A2E8DD477901E4FCA894C0",
		0xfeff: "EC8CDF7398607CB0F2D21675EA9EA1E4",
		0xff00: "362B7C3C6773516318A077D7FC5073AE",
		0xff01: "6A2CC3787889374FBEB4C81B17BA6C44",
	}
	for blk, hexWant := range want {
		if got := ks[blk*16 : blk*16+16]; !bytes.Equal(got, unhex(t, hexWant)) {
			t.Errorf("block %#x: %X, want %s", blk, got, hexWant)
		}
	}
}

// RFC 3711 Appendix B.3: the session keys of the default key derivation.
func TestKeyDerivationRFC3711(t *testing.T) {
	master, err := aes.NewCipher(unhex(t, "E1F97A0D3E018BE0D64FA32C06DE4139"))
	if err != nil {
		t.Fatal(err)
	}
	salt := unhex(t, "0EC675AD498AFEEBB6960B3AABE6")
	for _, tc := range []struct {
		label byte
		n     int
		want  string
	}{
		{labelEncryption, 16, "C61E7A93744F39EE10734AFE3FF7A087"},
		{labelSalt, 14, "30CBBC08863D8C85D49DB34A9AE1"},
		{labelAuth, 20, "CEBE321F6FF7716B6FD4AB49AF256A15 6D38BAA4"},
	} {
		if got := derive(master, salt, tc.label, tc.n); !bytes.Equal(got, unhex(t, tc.want)) {
			t.Errorf("label %d: %X, want %s", tc.label, got, tc.want)
		}
	}
}

// The reference packets of libsrtp (test/srtp_driver.c, srtp_validate and
// srtp_validate_aes_256): SSRC 0xcafebabe, sequence number 0x1234, 16 bytes
// of 0xab.
func TestReferencePacketsLibsrtp(t *testing.T) {
	plain := unhex(t, "800f1234 decafbad cafebabe abababab abababab abababab abababab")
	for _, tc := range []struct {
		suite      Suite
		key, salt  string
		ciphertext string
	}{
		{AES128CMSHA1_80, "e1f97a0d3e018be0d64fa32c06de4139", "0ec675ad498afeebb6960b3aabe6",
			"800f1234 decafbad cafebabe 4e55dc4c e79978d8 8ca4d215 949d2402 b78d6acc 99ea179b 8dbb"},
		{AES256CMSHA1_80, "f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6", "3b04803de51ee7c96423ab5b78d2",
			"800f1234 decafbad cafebabe f1d9de17 ff251ff1 aa007774 b0b4b40d a08d9d9a 5b3a55d8 873b"},
	} {
		t.Run(tc.suite.Name, func(t *testing.T) {
			snd, err := NewContext(tc.suite, unhex(t, tc.key), unhex(t, tc.salt))
			if err != nil {
				t.Fatal(err)
			}
			got, err := snd.Protect(nil, plain)
			if err != nil {
				t.Fatal(err)
			}
			if want := unhex(t, tc.ciphertext); !bytes.Equal(got, want) {
				t.Fatalf("protect:\n got %X\nwant %X", got, want)
			}
			rcv, _ := NewContext(tc.suite, unhex(t, tc.key), unhex(t, tc.salt))
			back, err := rcv.Unprotect(nil, got)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(back, plain) {
				t.Fatalf("unprotect: %X", back)
			}
		})
	}
}

func rtpPacket(seq uint16, ts, ssrc uint32, payload []byte) []byte {
	p := make([]byte, 12, 12+len(payload))
	p[0], p[1] = 0x80, 9
	binary.BigEndian.PutUint16(p[2:], seq)
	binary.BigEndian.PutUint32(p[4:], ts)
	binary.BigEndian.PutUint32(p[8:], ssrc)
	return append(p, payload...)
}

func pair(t *testing.T, s Suite) (*Context, *Context) {
	t.Helper()
	k, err := NewCrypto(1, s)
	if err != nil {
		t.Fatal(err)
	}
	snd, err := k.Context()
	if err != nil {
		t.Fatal(err)
	}
	rcv, err := k.Context()
	if err != nil {
		t.Fatal(err)
	}
	return snd, rcv
}

// Every suite round-trips, across a sequence number wrap (the rollover
// counter goes to 1 on both sides) and with a CSRC and a header extension.
func TestRoundTripAndRollover(t *testing.T) {
	for _, s := range suites {
		t.Run(s.Name, func(t *testing.T) {
			snd, rcv := pair(t, s)
			for i := 0; i < 40; i++ {
				seq := uint16(65520 + i) // wraps after 16 packets
				payload := bytes.Repeat([]byte{byte(i)}, 80)
				pkt := rtpPacket(seq, uint32(i*160), 0x1234abcd, payload)
				sp, err := snd.Protect(nil, pkt)
				if err != nil {
					t.Fatal(err)
				}
				if len(sp) != len(pkt)+s.TagLen || bytes.Equal(sp[12:12+80], payload) {
					t.Fatalf("packet %d is not protected", i)
				}
				back, err := rcv.Unprotect(nil, sp)
				if err != nil {
					t.Fatalf("packet %d (seq %d): %v", i, seq, err)
				}
				if !bytes.Equal(back, pkt) {
					t.Fatalf("packet %d differs", i)
				}
			}
			if st := rcv.streams[0x1234abcd]; st.roc != 1 || st.lastSeq != 23 {
				t.Fatalf("receiver roc=%d s_l=%d, want 1 and 23", st.roc, st.lastSeq)
			}
		})
	}
	// CSRC count 1 and an extension of one word stay in the clear.
	snd, rcv := pair(t, AES128CMSHA1_80)
	pkt := []byte{0x91, 9, 0, 1, 0, 0, 0, 0, 0, 0, 0, 7, 0xde, 0xad, 0xbe, 0xef, 0xbe, 0xde, 0, 1, 1, 2, 3, 4, 'h', 'i'}
	sp, err := snd.Protect(nil, pkt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sp[:24], pkt[:24]) || bytes.Equal(sp[24:26], pkt[24:]) {
		t.Fatalf("header must stay, payload must change: %X", sp)
	}
	if back, err := rcv.Unprotect(nil, sp); err != nil || !bytes.Equal(back, pkt) {
		t.Fatalf("unprotect: %X %v", back, err)
	}
}

func TestReplayAndReorder(t *testing.T) {
	snd, rcv := pair(t, AES128CMSHA1_80)
	var sent [][]byte
	for i := 0; i < 100; i++ {
		sp, err := snd.Protect(nil, rtpPacket(uint16(1000+i), 0, 42, []byte("voice")))
		if err != nil {
			t.Fatal(err)
		}
		sent = append(sent, sp)
	}
	for _, i := range []int{0, 1, 3, 2, 10, 9, 99} { // late packets within the window are fine
		if _, err := rcv.Unprotect(nil, sent[i]); err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
	}
	for _, i := range []int{3, 99, 10} {
		if _, err := rcv.Unprotect(nil, sent[i]); !errors.Is(err, ErrReplay) {
			t.Fatalf("repeat of %d: %v, want ErrReplay", i, err)
		}
	}
	if _, err := rcv.Unprotect(nil, sent[20]); !errors.Is(err, ErrReplay) { // 79 behind the newest
		t.Fatalf("packet behind the window: %v, want ErrReplay", err)
	}
	if _, err := rcv.Unprotect(nil, sent[40]); err != nil { // 59 behind: still inside
		t.Fatalf("packet inside the window: %v", err)
	}
}

func TestTamperedPacketsChangeNothing(t *testing.T) {
	snd, rcv := pair(t, AES128CMSHA1_32)
	a, _ := snd.Protect(nil, rtpPacket(7, 0, 5, []byte("first")))
	b, _ := snd.Protect(nil, rtpPacket(8, 0, 5, []byte("second")))
	for i := range b {
		bad := bytes.Clone(b)
		bad[i] ^= 0x01
		if _, err := rcv.Unprotect(nil, bad); err == nil {
			t.Fatalf("a flip in byte %d went through", i)
		}
	}
	if _, err := rcv.Unprotect(nil, b[:len(b)-1]); err == nil {
		t.Fatal("a truncated tag went through")
	}
	if len(rcv.streams) != 0 {
		t.Fatal("a forged packet created stream state")
	}
	if _, err := rcv.Unprotect(nil, a); err != nil {
		t.Fatal(err)
	}
	if _, err := rcv.Unprotect(nil, b); err != nil {
		t.Fatal(err)
	}
	other, _ := pair(t, AES128CMSHA1_32)
	c, _ := other.Protect(nil, rtpPacket(9, 0, 5, []byte("third")))
	if _, err := rcv.Unprotect(nil, c); !errors.Is(err, ErrAuth) {
		t.Fatalf("a packet under another key: %v, want ErrAuth", err)
	}
	if _, err := rcv.Unprotect(nil, []byte{0x80, 9, 0}); !errors.Is(err, ErrShort) {
		t.Fatalf("short packet: %v", err)
	}
	if _, err := rcv.Unprotect(nil, make([]byte, 30)); !errors.Is(err, ErrNotRTP) {
		t.Fatalf("version 0: %v", err)
	}
}

func TestNewContextChecksLengths(t *testing.T) {
	if _, err := NewContext(AES128CMSHA1_80, make([]byte, 32), make([]byte, 14)); err == nil {
		t.Fatal("a 32-byte key for AES-128 was accepted")
	}
	if _, err := NewContext(AES256CMSHA1_80, make([]byte, 32), make([]byte, 12)); err == nil {
		t.Fatal("a 12-byte salt was accepted")
	}
	if _, err := NewContext(Suite{Name: "NULL", KeyLen: 16, TagLen: 10}, make([]byte, 16), make([]byte, 14)); err == nil {
		t.Fatal("an unknown suite was accepted")
	}
}

func TestParseCrypto(t *testing.T) {
	// RFC 4568 §4 example without the MKI, and the same key with it.
	c, err := ParseCrypto("1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20")
	if err != nil {
		t.Fatal(err)
	}
	if c.Tag != 1 || c.Suite != AES128CMSHA1_80 || len(c.Key) != 16 || len(c.Salt) != 14 {
		t.Fatalf("parsed %+v", c)
	}
	if string(c.Key)+string(c.Salt) != "YS___semctl () {\t220;}\n}\nunles" {
		t.Fatalf("key and salt: %q", string(c.Key)+string(c.Salt))
	}
	for _, v := range []string{
		"1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|2^20|1:4",
		"1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz|1:4",
		"2 F8_128_HMAC_SHA1_80 inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5QUJjZGVm",
		"1 AEAD_AES_128_GCM inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5",
		"1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz UNENCRYPTED_SRTP",
		"1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz KDR=1",
		"1 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz;inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",
	} {
		if _, err := ParseCrypto(v); !errors.Is(err, ErrUnsupported) {
			t.Errorf("%q: %v, want ErrUnsupported", v, err)
		}
	}
	for _, v := range []string{
		"",
		"x AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",
		"1 AES_CM_128_HMAC_SHA1_80 outline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",
		"1 AES_CM_128_HMAC_SHA1_80 inline:c2hvcnQ=",
		"1 AES_256_CM_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",
		"1234567890 AES_CM_128_HMAC_SHA1_80 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz",
	} {
		if _, err := ParseCrypto(v); err == nil || errors.Is(err, ErrUnsupported) {
			t.Errorf("%q: %v, want a parse error", v, err)
		}
	}
	if c, err := ParseCrypto("3 AES_CM_128_HMAC_SHA1_32 inline:WVNfX19zZW1jdGwgKCkgewkyMjA7fQp9CnVubGVz WSH=128 UNENCRYPTED_SRTCP"); err != nil || c.Tag != 3 {
		t.Errorf("harmless session parameters: %+v %v", c, err)
	}
}

func TestCryptoStringRoundTrip(t *testing.T) {
	for _, s := range suites {
		c, err := NewCrypto(7, s)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ParseCrypto(c.String())
		if err != nil {
			t.Fatalf("%s: %v (%s)", s.Name, err, c.String())
		}
		if !back.Equal(c) {
			t.Fatalf("%s: %+v != %+v", s.Name, back, c)
		}
		// Unpadded base64 (46 bytes of AES-256 need padding) is accepted too.
		raw := strings.TrimRight(c.String(), "=")
		if back, err := ParseCrypto(raw); err != nil || !back.Equal(c) {
			t.Fatalf("%s unpadded: %v", s.Name, err)
		}
	}
	a, _ := NewCrypto(1, AES128CMSHA1_80)
	b, _ := NewCrypto(1, AES128CMSHA1_80)
	if a.Equal(b) {
		t.Fatal("two fresh keys are equal")
	}
}
