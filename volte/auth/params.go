package auth

import (
	"fmt"
	"strings"
)

// param is one name=value pair of an auth-param or mechanism-parameter list.
type param struct {
	name   string
	value  string
	quoted bool
}

// parseParams splits `a=1, b="x, y", c` on sep, honouring quoted strings
// (RFC 3261 §25.1 quoted-string with backslash escapes).
func parseParams(s string, sep byte) ([]param, error) {
	var out []param
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == sep) {
			i++
		}
		if i >= len(s) {
			break
		}
		start := i
		for i < len(s) && s[i] != '=' && s[i] != sep {
			i++
		}
		p := param{name: strings.ToLower(strings.TrimSpace(s[start:i]))}
		if i < len(s) && s[i] == '=' {
			i++
			for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
			}
			if i < len(s) && s[i] == '"' {
				i++
				var b strings.Builder
				closed := false
				for i < len(s) {
					c := s[i]
					if c == '\\' && i+1 < len(s) {
						b.WriteByte(s[i+1])
						i += 2
						continue
					}
					i++
					if c == '"' {
						closed = true
						break
					}
					b.WriteByte(c)
				}
				if !closed {
					return nil, fmt.Errorf("unterminated quoted value for %q", p.name)
				}
				p.value, p.quoted = b.String(), true
			} else {
				vs := i
				for i < len(s) && s[i] != sep {
					i++
				}
				p.value = strings.TrimSpace(s[vs:i])
			}
		}
		if p.name != "" {
			out = append(out, p)
		}
	}
	return out, nil
}

func lookup(ps []param, name string) (string, bool) {
	for _, p := range ps {
		if p.name == name {
			return p.value, true
		}
	}
	return "", false
}

// quote renders a quoted-string, escaping '"' and '\'. CR and LF can never
// appear inside a quoted-string (RFC 3261 §25.1), and the values quoted here
// (realm, nonce, opaque) come from the network's 401: dropping them closes a
// header-injection path through a hostile or spoofed P-CSCF.
func quote(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\r", "", "\n", "")
	return `"` + r.Replace(s) + `"`
}
