package sipnet

import (
	"strings"

	"github.com/emiago/sipgo/sip"
)

// ListValues splits comma-separated name-addr lists (Service-Route,
// P-Associated-URI, Record-Route) at commas outside <> and quotes.
func ListValues(m sip.Message, name string) []string {
	var out []string
	for _, h := range m.GetHeaders(name) {
		v := h.Value()
		depth, quoted, start := 0, false, 0
		for i := 0; i <= len(v); i++ {
			if i < len(v) {
				switch v[i] {
				case '"':
					quoted = !quoted
				case '<':
					if !quoted {
						depth++
					}
				case '>':
					if !quoted && depth > 0 {
						depth--
					}
				}
				if v[i] != ',' || quoted || depth > 0 {
					continue
				}
			}
			if item := strings.TrimSpace(v[start:i]); item != "" {
				out = append(out, item)
			}
			start = i + 1
		}
	}
	return out
}
