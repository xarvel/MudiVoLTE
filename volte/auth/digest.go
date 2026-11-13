package auth

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// AlgAKAv1MD5 is the only Digest algorithm we answer (RFC 3310 §3.1).
const AlgAKAv1MD5 = "AKAv1-MD5"

// Challenge is a parsed WWW-Authenticate / Proxy-Authenticate Digest challenge.
type Challenge struct {
	Realm     string
	Nonce     string
	Algorithm string
	Opaque    string
	Qop       []string
	Stale     bool
}

// ParseChallenge parses a `Digest ...` challenge header value.
func ParseChallenge(h string) (*Challenge, error) {
	h = strings.TrimSpace(h)
	scheme, rest, _ := strings.Cut(h, " ")
	if !strings.EqualFold(scheme, "Digest") {
		return nil, fmt.Errorf("auth scheme %q is not Digest", scheme)
	}
	ps, err := parseParams(rest, ',')
	if err != nil {
		return nil, err
	}
	c := &Challenge{Algorithm: "MD5"}
	c.Realm, _ = lookup(ps, "realm")
	c.Nonce, _ = lookup(ps, "nonce")
	c.Opaque, _ = lookup(ps, "opaque")
	if v, ok := lookup(ps, "algorithm"); ok {
		c.Algorithm = v
	}
	if v, ok := lookup(ps, "qop"); ok {
		for _, q := range strings.Split(v, ",") {
			if q = strings.TrimSpace(q); q != "" {
				c.Qop = append(c.Qop, strings.ToLower(q))
			}
		}
	}
	if v, ok := lookup(ps, "stale"); ok {
		c.Stale = strings.EqualFold(v, "true")
	}
	if c.Nonce == "" {
		return nil, errors.New("challenge has no nonce")
	}
	return c, nil
}

// RandAutn extracts RAND and AUTN from the nonce: base64(RAND ‖ AUTN ‖ server-data)
// (RFC 3310 §3.2).
func (c *Challenge) RandAutn() (rand, autn [16]byte, err error) {
	raw, err := base64.StdEncoding.DecodeString(c.Nonce)
	if err != nil {
		return rand, autn, fmt.Errorf("nonce is not base64: %w", err)
	}
	if len(raw) < 32 {
		return rand, autn, fmt.Errorf("nonce is %d bytes, need at least 32", len(raw))
	}
	copy(rand[:], raw[:16])
	copy(autn[:], raw[16:32])
	return rand, autn, nil
}

// Request describes the SIP request being authorized.
type Request struct {
	Username string // private user identity (IMPI)
	Method   string // e.g. REGISTER
	URI      string // Request-URI, e.g. sip:ims.mnc001.mcc001.3gppnetwork.org
	Body     []byte // only used for qop=auth-int
}

// Answer builds the Authorization header value for a successful AKA run,
// using RES as the Digest password (RFC 3310 §3.3).
func (c *Challenge) Answer(r Request, res []byte, nc uint32, cnonce string) (string, error) {
	if !strings.EqualFold(c.Algorithm, AlgAKAv1MD5) {
		return "", fmt.Errorf("unsupported digest algorithm %q", c.Algorithm)
	}
	return c.authorization(r, res, nc, cnonce, nil), nil
}

// SyncFailure builds the Authorization header reporting an AKA
// synchronisation failure: auts is set and the password is empty (RFC 3310 §3.4).
func (c *Challenge) SyncFailure(r Request, auts []byte, nc uint32, cnonce string) string {
	return c.authorization(r, nil, nc, cnonce, auts)
}

func (c *Challenge) authorization(r Request, password []byte, nc uint32, cnonce string, auts []byte) string {
	qop := c.pickQop()
	ncs := fmt.Sprintf("%08x", nc)
	resp := digestResponse(r, c.Realm, c.Nonce, password, qop, ncs, cnonce)

	parts := []string{
		"username=" + quote(r.Username),
		"realm=" + quote(c.Realm),
		"nonce=" + quote(c.Nonce),
		"uri=" + quote(r.URI),
		"response=" + quote(resp),
		"algorithm=" + c.Algorithm,
	}
	if qop != "" {
		parts = append(parts, "cnonce="+quote(cnonce), "qop="+qop, "nc="+ncs)
	}
	if c.Opaque != "" {
		parts = append(parts, "opaque="+quote(c.Opaque))
	}
	if auts != nil {
		parts = append(parts, "auts="+quote(base64.StdEncoding.EncodeToString(auts)))
	}
	return "Digest " + strings.Join(parts, ", ")
}

// pickQop prefers auth over auth-int; empty means the RFC 2069 form.
func (c *Challenge) pickQop() string {
	has := func(q string) bool {
		for _, v := range c.Qop {
			if v == q {
				return true
			}
		}
		return false
	}
	switch {
	case has("auth"):
		return "auth"
	case has("auth-int"):
		return "auth-int"
	}
	return ""
}

// digestResponse is the RFC 2617 §3.2.2.1 request-digest.
func digestResponse(r Request, realm, nonce string, password []byte, qop, nc, cnonce string) string {
	ha1 := md5hex([]byte(r.Username+":"+realm+":"), password)
	a2 := r.Method + ":" + r.URI
	if qop == "auth-int" {
		a2 += ":" + md5hex(r.Body)
	}
	ha2 := md5hex([]byte(a2))
	if qop == "" {
		return md5hex([]byte(ha1 + ":" + nonce + ":" + ha2))
	}
	return md5hex([]byte(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2))
}

func md5hex(parts ...[]byte) string {
	h := md5.New()
	for _, p := range parts {
		h.Write(p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// InitialAuthorization is the Authorization header of the first, unprotected
// REGISTER (TS 24.229 §5.1.1.2.1): identities only, empty nonce and response.
func InitialAuthorization(impi, realm, uri string) string {
	return "Digest username=" + quote(impi) + ", realm=" + quote(realm) +
		", uri=" + quote(uri) + `, nonce="", response=""`
}
