package auth

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// MechIPsec3GPP is the sec-agree mechanism name used by IMS (TS 33.203 Annex H).
const MechIPsec3GPP = "ipsec-3gpp"

// Mechanism is one entry of a Security-Client / -Server / -Verify header
// (RFC 3329 §2.2) carrying the ipsec-3gpp parameters of TS 33.203 §7.2.
type Mechanism struct {
	Name  string
	Alg   string // integrity: hmac-md5-96, hmac-sha-1-96
	Ealg  string // encryption: null, aes-cbc, des-ede3-cbc; "" means null
	Prot  string // esp
	Mode  string // trans
	SPIc  uint32
	SPIs  uint32
	PortC uint16
	PortS uint16
	Q     float64 // preference; -1 when absent

	raw string // exact wire text, echoed back in Security-Verify
}

// String renders the mechanism for a Security-Client header.
func (m Mechanism) String() string {
	var b strings.Builder
	b.WriteString(m.Name)
	add := func(k, v string) {
		if v != "" {
			b.WriteString(";" + k + "=" + v)
		}
	}
	add("alg", m.Alg)
	add("ealg", m.Ealg)
	add("spi-c", strconv.FormatUint(uint64(m.SPIc), 10))
	add("spi-s", strconv.FormatUint(uint64(m.SPIs), 10))
	add("port-c", strconv.FormatUint(uint64(m.PortC), 10))
	add("port-s", strconv.FormatUint(uint64(m.PortS), 10))
	add("prot", m.Prot)
	add("mod", m.Mode)
	if m.Q >= 0 {
		add("q", strconv.FormatFloat(m.Q, 'f', -1, 64))
	}
	return b.String()
}

// Raw is the mechanism exactly as received (for Security-Verify).
func (m Mechanism) Raw() string {
	if m.raw != "" {
		return m.raw
	}
	return m.String()
}

// ParseMechanisms parses one Security-* header value; several mechanisms may
// be comma-separated.
func ParseMechanisms(h string) ([]Mechanism, error) {
	var out []Mechanism
	for _, item := range strings.Split(h, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		name, rest, _ := strings.Cut(item, ";")
		ps, err := parseParams(rest, ';')
		if err != nil {
			return nil, err
		}
		m := Mechanism{Name: strings.ToLower(strings.TrimSpace(name)), Q: -1, raw: item}
		for _, p := range ps {
			switch p.name {
			case "alg":
				m.Alg = strings.ToLower(p.value)
			case "ealg":
				m.Ealg = strings.ToLower(p.value)
			case "prot":
				m.Prot = strings.ToLower(p.value)
			case "mod":
				m.Mode = strings.ToLower(p.value)
			case "spi-c":
				m.SPIc, err = parseU32(p)
			case "spi-s":
				m.SPIs, err = parseU32(p)
			case "port-c":
				m.PortC, err = parseU16(p)
			case "port-s":
				m.PortS, err = parseU16(p)
			case "q":
				m.Q, err = strconv.ParseFloat(p.value, 64)
			}
			if err != nil {
				return nil, fmt.Errorf("%s: bad %s=%q: %w", m.Name, p.name, p.value, err)
			}
		}
		out = append(out, m)
	}
	return out, nil
}

func parseU32(p param) (uint32, error) {
	v, err := strconv.ParseUint(p.value, 10, 32)
	return uint32(v), err
}

func parseU16(p param) (uint16, error) {
	v, err := strconv.ParseUint(p.value, 10, 16)
	return uint16(v), err
}

// Supported reports whether we can install an SA for this mechanism.
func (m Mechanism) Supported() bool {
	if m.Name != MechIPsec3GPP {
		return false
	}
	if m.Prot != "" && m.Prot != "esp" {
		return false
	}
	if m.Mode != "" && m.Mode != "trans" {
		return false
	}
	if _, err := IntegrityKey(m.Alg, make([]byte, 16)); err != nil {
		return false
	}
	_, err := EncryptionKey(m.Ealg, make([]byte, 16))
	return err == nil
}

// Choose picks the server mechanism to use: the supported one with the
// highest q (RFC 3329 §2.3); ties keep server order.
func Choose(server []Mechanism) (Mechanism, error) {
	best, found := Mechanism{}, false
	for _, m := range server {
		if !m.Supported() {
			continue
		}
		if !found || m.Q > best.Q {
			best, found = m, true
		}
	}
	if !found {
		return Mechanism{}, errors.New("no supported ipsec-3gpp mechanism offered")
	}
	return best, nil
}

// VerifyHeader renders Security-Verify: the Security-Server list echoed verbatim.
func VerifyHeader(server []Mechanism) string {
	parts := make([]string, len(server))
	for i, m := range server {
		parts[i] = m.Raw()
	}
	return strings.Join(parts, ", ")
}
