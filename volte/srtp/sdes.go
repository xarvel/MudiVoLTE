package srtp

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Crypto is one SDES attribute (RFC 4568 §9.1):
//
//	a=crypto:<tag> <crypto-suite> inline:<base64 of key||salt>[|lifetime]
//
// Every side announces the key of the stream it sends. The answer repeats the
// tag of the offer line it accepts, with its own key (§6.1).
type Crypto struct {
	Tag   int
	Suite Suite
	Key   []byte // master key
	Salt  []byte // master salt
}

// NewCrypto returns an attribute with a fresh random master key and salt.
func NewCrypto(tag int, s Suite) (Crypto, error) {
	if _, ok := SuiteByName(s.Name); !ok {
		return Crypto{}, fmt.Errorf("srtp: unknown suite %q", s.Name)
	}
	b := make([]byte, s.KeyLen+SaltLen)
	if _, err := rand.Read(b); err != nil {
		return Crypto{}, err
	}
	return Crypto{Tag: tag, Suite: s, Key: b[:s.KeyLen], Salt: b[s.KeyLen:]}, nil
}

// String renders the value of the attribute, without "a=crypto:".
func (c Crypto) String() string {
	key := make([]byte, 0, len(c.Key)+len(c.Salt))
	key = append(append(key, c.Key...), c.Salt...)
	return fmt.Sprintf("%d %s inline:%s", c.Tag, c.Suite.Name, base64.StdEncoding.EncodeToString(key))
}

// Context returns the SRTP context of the stream this key protects.
func (c Crypto) Context() (*Context, error) {
	return NewContext(c.Suite, c.Key, c.Salt)
}

// Equal reports the same tag, suite and key.
func (c Crypto) Equal(o Crypto) bool {
	return c.Tag == o.Tag && c.Suite == o.Suite && string(c.Key) == string(o.Key) && string(c.Salt) == string(o.Salt)
}

// ErrUnsupported marks an attribute that is valid SDES but uses something this
// package does not do: an unknown suite, an MKI, several keys, or a session
// parameter that changes the protection. The offerer may have other lines.
var ErrUnsupported = errors.New("srtp: unsupported crypto attribute")

// ParseCrypto parses the value of an a=crypto attribute (the part after
// "a=crypto:"). Lifetimes are accepted and ignored: a call never comes near
// them. The session parameters UNENCRYPTED_SRTCP and WSH do not concern RTP
// and are accepted too.
func ParseCrypto(v string) (Crypto, error) {
	f := strings.Fields(v)
	if len(f) < 3 {
		return Crypto{}, fmt.Errorf("srtp: bad crypto attribute %q", v)
	}
	tag, err := strconv.Atoi(f[0])
	if err != nil || tag < 0 || tag > 999999999 || len(f[0]) > 9 {
		return Crypto{}, fmt.Errorf("srtp: bad crypto tag %q", f[0])
	}
	suite, ok := SuiteByName(f[1])
	if !ok {
		return Crypto{}, fmt.Errorf("%w: suite %s", ErrUnsupported, f[1])
	}
	if strings.Contains(f[2], ";") {
		return Crypto{}, fmt.Errorf("%w: several keys", ErrUnsupported)
	}
	params, ok := strings.CutPrefix(f[2], "inline:")
	if !ok {
		return Crypto{}, fmt.Errorf("srtp: key method other than inline in %q", f[2])
	}
	parts := strings.Split(params, "|")
	if len(parts) > 2 || (len(parts) == 2 && strings.Contains(parts[1], ":")) {
		return Crypto{}, fmt.Errorf("%w: MKI", ErrUnsupported)
	}
	key, err := decodeKey(parts[0])
	if err != nil || len(key) != suite.KeyLen+SaltLen {
		return Crypto{}, fmt.Errorf("srtp: %s needs a %d-byte key and salt", suite.Name, suite.KeyLen+SaltLen)
	}
	for _, p := range f[3:] {
		if p != "UNENCRYPTED_SRTCP" && !strings.HasPrefix(p, "WSH=") {
			return Crypto{}, fmt.Errorf("%w: session parameter %s", ErrUnsupported, p)
		}
	}
	return Crypto{Tag: tag, Suite: suite, Key: key[:suite.KeyLen], Salt: key[suite.KeyLen:]}, nil
}

// decodeKey accepts base64 with or without padding.
func decodeKey(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
