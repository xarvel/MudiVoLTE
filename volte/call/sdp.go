package call

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Format is one RTP payload format of an audio m-line (RFC 4566 §6, RFC 3551).
type Format struct {
	PT        int
	Name      string // encoding name as written, e.g. AMR-WB
	ClockRate int
	Fmtp      string
}

// Param returns one fmtp parameter, e.g. mode-set.
func (f Format) Param(name string) (string, bool) {
	for _, p := range strings.Split(f.Fmtp, ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// OctetAligned reports RFC 4867 §8.1 octet-align=1.
func (f Format) OctetAligned() bool { v, _ := f.Param("octet-align"); return v == "1" }

// Audio is the audio m-line of a session description.
type Audio struct {
	Addr      netip.AddrPort // connection address and RTP port
	Formats   []Format       // in m-line order (preference)
	Ptime     int
	Direction string // sendrecv, sendonly, recvonly, inactive
}

// ParseSDP extracts the first audio stream (RFC 4566).
func ParseSDP(body []byte) (Audio, error) {
	var a Audio
	var sessionAddr, mediaAddr netip.Addr
	inAudio, seenAudio := false, false
	byPT := map[int]*Format{}
	for _, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		k, v := line[0], strings.TrimSpace(line[2:])
		switch {
		case k == 'm':
			inAudio = false
			if seenAudio {
				continue
			}
			f := strings.Fields(v)
			if len(f) < 4 || f[0] != "audio" {
				continue
			}
			port, err := strconv.Atoi(f[1])
			if err != nil || port < 0 || port > 65535 {
				return a, fmt.Errorf("bad m= port %q", f[1])
			}
			a.Addr = netip.AddrPortFrom(netip.Addr{}, uint16(port))
			for _, s := range f[3:] {
				pt, err := strconv.Atoi(s)
				if err != nil {
					continue
				}
				a.Formats = append(a.Formats, Format{PT: pt})
			}
			for i := range a.Formats {
				byPT[a.Formats[i].PT] = &a.Formats[i]
				staticFormat(&a.Formats[i])
			}
			inAudio, seenAudio = true, true
		case k == 'c':
			f := strings.Fields(v)
			if len(f) < 3 {
				continue
			}
			ip, err := netip.ParseAddr(strings.Split(f[2], "/")[0])
			if err != nil {
				return a, fmt.Errorf("bad c= address %q", f[2])
			}
			if inAudio {
				mediaAddr = ip
			} else if !seenAudio {
				sessionAddr = ip
			}
		case k == 'a' && inAudio:
			name, val, _ := strings.Cut(v, ":")
			switch name {
			case "rtpmap":
				ptS, enc, _ := strings.Cut(val, " ")
				pt, _ := strconv.Atoi(ptS)
				if f := byPT[pt]; f != nil {
					parts := strings.Split(enc, "/")
					f.Name = parts[0]
					if len(parts) > 1 {
						f.ClockRate, _ = strconv.Atoi(parts[1])
					}
				}
			case "fmtp":
				ptS, params, _ := strings.Cut(val, " ")
				pt, _ := strconv.Atoi(ptS)
				if f := byPT[pt]; f != nil {
					f.Fmtp = strings.TrimSpace(params)
				}
			case "ptime":
				a.Ptime, _ = strconv.Atoi(val)
			case "sendrecv", "sendonly", "recvonly", "inactive":
				a.Direction = name
			}
		case k == 'a' && !seenAudio:
			switch v {
			case "sendrecv", "sendonly", "recvonly", "inactive":
				a.Direction = v
			}
		}
	}
	if !seenAudio {
		return a, errors.New("no audio stream in SDP")
	}
	addr := mediaAddr
	if !addr.IsValid() {
		addr = sessionAddr
	}
	if !addr.IsValid() {
		return a, errors.New("no connection address in SDP")
	}
	a.Addr = netip.AddrPortFrom(addr, a.Addr.Port())
	if a.Direction == "" {
		a.Direction = "sendrecv"
	}
	return a, nil
}

// staticFormat fills static payload types (RFC 3551 Table 4).
func staticFormat(f *Format) {
	switch f.PT {
	case 0:
		f.Name, f.ClockRate = "PCMU", 8000
	case 8:
		f.Name, f.ClockRate = "PCMA", 8000
	case 9:
		f.Name, f.ClockRate = "G722", 8000
	}
}

// Negotiated is the outcome of offer/answer for the audio stream.
type Negotiated struct {
	Remote netip.AddrPort
	Codec  Format
	DTMF   *Format // telephone-event at the codec's clock rate, if any
	Ptime  int
}

// DefaultCodecs is our preference: wideband first, G.711 as a fallback.
var DefaultCodecs = []string{"AMR-WB", "PCMA", "PCMU"}

// Negotiate picks the codec for an answer: the first offered format we
// support, keeping the offerer's order (RFC 3264 §6.1).
func Negotiate(offer Audio, supported []string) (Negotiated, error) {
	if offer.Addr.Port() == 0 {
		return Negotiated{}, errors.New("audio stream rejected by offerer (port 0)")
	}
	n := Negotiated{Remote: offer.Addr, Ptime: offer.Ptime}
	if n.Ptime == 0 {
		n.Ptime = 20
	}
	found := false
	for _, f := range offer.Formats {
		for _, s := range supported {
			if strings.EqualFold(f.Name, s) && !found {
				n.Codec, found = f, true
			}
		}
	}
	if !found {
		return Negotiated{}, errors.New("no common audio codec")
	}
	for _, f := range offer.Formats {
		if strings.EqualFold(f.Name, "telephone-event") && f.ClockRate == n.Codec.ClockRate {
			f := f
			n.DTMF = &f
			break
		}
	}
	return n, nil
}

// SessionDescription renders our side (offer or answer) for one audio stream.
type SessionDescription struct {
	ID, Version uint64
	Local       netip.AddrPort
	Formats     []Format
	Ptime       int
	Direction   string
}

func (d SessionDescription) Bytes() []byte {
	ipver := "IP4"
	if d.Local.Addr().Is6() {
		ipver = "IP6"
	}
	ip := d.Local.Addr().String()
	var b strings.Builder
	w := func(s string) { b.WriteString(s + "\r\n") }
	w("v=0")
	w(fmt.Sprintf("o=- %d %d IN %s %s", d.ID, d.Version, ipver, ip))
	w("s=-")
	w("c=IN " + ipver + " " + ip)
	w("t=0 0")
	pts := make([]string, len(d.Formats))
	for i, f := range d.Formats {
		pts[i] = strconv.Itoa(f.PT)
	}
	w(fmt.Sprintf("m=audio %d RTP/AVP %s", d.Local.Port(), strings.Join(pts, " ")))
	if as := bandwidthAS(d.Formats); as > 0 {
		w("b=AS:" + strconv.Itoa(as))
	}
	for _, f := range d.Formats {
		if f.PT >= 96 || f.Name != "" {
			w(fmt.Sprintf("a=rtpmap:%d %s/%d", f.PT, f.Name, f.ClockRate))
		}
		if f.Fmtp != "" {
			w(fmt.Sprintf("a=fmtp:%d %s", f.PT, f.Fmtp))
		}
	}
	ptime := d.Ptime
	if ptime == 0 {
		ptime = 20
	}
	w("a=ptime:" + strconv.Itoa(ptime))
	dir := d.Direction
	if dir == "" {
		dir = "sendrecv"
	}
	w("a=" + dir)
	return []byte(b.String())
}

// bandwidthAS is the application-specific bandwidth in kbps for the main codec
// including IPv4/UDP/RTP overhead at 20 ms (TS 26.114 Annex K order of magnitude).
func bandwidthAS(fs []Format) int {
	if len(fs) == 0 {
		return 0
	}
	switch strings.ToUpper(fs[0].Name) {
	case "AMR-WB":
		return 38
	case "PCMA", "PCMU":
		return 80
	}
	return 0
}

// Answer builds our answer for a negotiated offer.
func (n Negotiated) Answer(local netip.AddrPort, id, version uint64, offerDirection string) SessionDescription {
	fs := []Format{n.Codec}
	if n.DTMF != nil {
		d := *n.DTMF
		if d.Fmtp == "" {
			d.Fmtp = "0-15"
		}
		fs = append(fs, d)
	}
	dir := map[string]string{"sendonly": "recvonly", "recvonly": "sendonly", "inactive": "inactive"}[offerDirection]
	return SessionDescription{ID: id, Version: version, Local: local, Formats: fs, Ptime: n.Ptime, Direction: dir}
}

// OfferFormats is what we put in our own offers (TS 26.114 §6.2.2: AMR-WB
// bandwidth-efficient with mode changes allowed, plus telephone-event),
// limited to codecs (nil = all) in their order of preference.
func OfferFormats(codecs []string) []Format {
	all := []Format{
		{PT: 104, Name: "AMR-WB", ClockRate: 16000, Fmtp: "mode-change-capability=2;max-red=0"},
		{PT: 8, Name: "PCMA", ClockRate: 8000},
		{PT: 0, Name: "PCMU", ClockRate: 8000},
		{PT: 105, Name: "telephone-event", ClockRate: 16000, Fmtp: "0-15"},
		{PT: 101, Name: "telephone-event", ClockRate: 8000, Fmtp: "0-15"},
	}
	if codecs == nil {
		return all
	}
	var out []Format
	rates := map[int]bool{}
	for _, name := range codecs {
		for _, f := range all {
			if strings.EqualFold(f.Name, name) {
				out = append(out, f)
				rates[f.ClockRate] = true
			}
		}
	}
	for _, f := range all {
		if f.Name == "telephone-event" && rates[f.ClockRate] {
			out = append(out, f)
		}
	}
	return out
}
