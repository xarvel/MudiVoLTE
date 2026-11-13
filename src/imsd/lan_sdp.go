package main

// SDP for the LAN side: parsing the phone's offer/answer (the first m=audio)
// and building our own. SRTP keys travel in a=crypto lines (SDES, RFC 4568);
// which offers get them and which are accepted is decided in lan_srtp.go.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/xarvel/MudiVoLTE/volte/srtp"
)

type lanFormat struct {
	Name  string // G722 | PCMU | PCMA
	PT    int
	Clock int // RTP clock rate from the SDP (8000 for G.722 per RFC 3551)
}

// staticLANFormats are the static payload types of RFC 3551.
var staticLANFormats = map[string]lanFormat{
	"PCMU": {Name: "PCMU", PT: 0, Clock: 8000},
	"PCMA": {Name: "PCMA", PT: 8, Clock: 8000},
	"G722": {Name: "G722", PT: 9, Clock: 8000},
}

const defaultDTMFPT = 101

type sdpAudio struct {
	IP        net.IP
	Port      int
	Proto     string
	Payloads  []int
	RTPMap    map[int]string // pt → "G722/8000"
	Direction string         // sendrecv | sendonly | recvonly | inactive
	// Crypto are the a=crypto lines we can use, in the order of the SDP (the
	// offerer's preference); CryptoLines counts every a=crypto line.
	Crypto      []srtp.Crypto
	CryptoLines int
}

func parseSDP(body []byte) (*sdpAudio, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, errors.New("sdp: empty")
	}
	var sessIP net.IP
	var a *sdpAudio
	sessDir := "sendrecv"
	inAudio := false
	for _, raw := range strings.Split(string(body), "\n") {
		line := strings.TrimSpace(raw)
		if len(line) < 2 || line[1] != '=' {
			continue
		}
		k, v := line[0], line[2:]
		switch k {
		case 'm':
			if a != nil {
				inAudio = false // only the first audio section is needed
				continue
			}
			f := strings.Fields(v)
			if len(f) < 4 || f[0] != "audio" {
				inAudio = false
				continue
			}
			port, err := strconv.Atoi(f[1])
			if err != nil {
				return nil, fmt.Errorf("sdp: port %q", f[1])
			}
			a = &sdpAudio{Port: port, Proto: f[2], RTPMap: map[int]string{}, Direction: ""}
			for _, p := range f[3:] {
				if pt, err := strconv.Atoi(p); err == nil {
					a.Payloads = append(a.Payloads, pt)
				}
			}
			inAudio = true
		case 'c':
			f := strings.Fields(v)
			if len(f) >= 3 && f[0] == "IN" && f[1] == "IP4" {
				ip := net.ParseIP(strings.Split(f[2], "/")[0])
				if inAudio && a != nil {
					a.IP = ip
				} else if a == nil {
					sessIP = ip
				}
			}
		case 'a':
			switch {
			case v == "sendrecv" || v == "sendonly" || v == "recvonly" || v == "inactive":
				if inAudio && a != nil {
					a.Direction = v
				} else if a == nil {
					sessDir = v
				}
			case strings.HasPrefix(v, "rtpmap:") && inAudio && a != nil:
				ptStr, enc, ok := strings.Cut(strings.TrimPrefix(v, "rtpmap:"), " ")
				if pt, err := strconv.Atoi(ptStr); ok && err == nil {
					a.RTPMap[pt] = strings.TrimSpace(enc)
				}
			case strings.HasPrefix(v, "crypto:") && inAudio && a != nil:
				a.CryptoLines++
				if c, err := srtp.ParseCrypto(strings.TrimPrefix(v, "crypto:")); err == nil {
					a.Crypto = append(a.Crypto, c)
				}
			}
		}
	}
	if a == nil {
		return nil, errors.New("sdp: no m=audio")
	}
	if a.IP == nil {
		a.IP = sessIP
	}
	if a.Direction == "" {
		a.Direction = sessDir
	}
	if a.IP == nil || a.IP.To4() == nil {
		return nil, errors.New("sdp: no IPv4 in c=")
	}
	return a, nil
}

// formatName returns the codec name for pt: from rtpmap, otherwise from the static PT.
func (a *sdpAudio) formatName(pt int) (name string, clock int) {
	if enc, ok := a.RTPMap[pt]; ok {
		n, c, _ := strings.Cut(enc, "/")
		clock, _ = strconv.Atoi(strings.Split(c, "/")[0])
		return strings.ToUpper(n), clock
	}
	for _, f := range staticLANFormats {
		if f.PT == pt {
			return f.Name, f.Clock
		}
	}
	return "", 0
}

// dtmfPT returns the payload type of telephone-event/8000 (0 when absent).
func (a *sdpAudio) dtmfPT() int {
	for _, pt := range a.Payloads {
		if name, clock := a.formatName(pt); name == "TELEPHONE-EVENT" && (clock == 8000 || clock == 0) {
			return pt
		}
	}
	return 0
}

// chooseByPreference returns the first codec of prefs that the phone's offer has.
func (a *sdpAudio) chooseByPreference(prefs []string) (lanFormat, bool) {
	for _, want := range prefs {
		for _, pt := range a.Payloads {
			if name, _ := a.formatName(pt); name == want {
				f := staticLANFormats[want]
				f.PT = pt
				return f, true
			}
		}
	}
	return lanFormat{}, false
}

// chooseFirstKnown is for the phone's answer to our offer: the first known format in m=.
func (a *sdpAudio) chooseFirstKnown(allowed []string) (lanFormat, bool) {
	ok := map[string]bool{}
	for _, n := range allowed {
		ok[n] = true
	}
	for _, pt := range a.Payloads {
		name, _ := a.formatName(pt)
		if ok[name] {
			f := staticLANFormats[name]
			f.PT = pt
			return f, true
		}
	}
	return lanFormat{}, false
}

// savp reports the SRTP profile with keys in the SDP: RTP/SAVP or RTP/SAVPF.
func (a *sdpAudio) savp() bool {
	p := strings.ToUpper(a.Proto)
	return p == "RTP/SAVP" || p == "RTP/SAVPF"
}

// avp reports plain RTP: RTP/AVP or RTP/AVPF (keys may still come as a=crypto,
// the best-effort SRTP of RFC 4568 §3.1.4).
func (a *sdpAudio) avp() bool {
	p := strings.ToUpper(a.Proto)
	return p == "RTP/AVP" || p == "RTP/AVPF"
}

// answerDirection returns the mirrored direction for the answer.
func answerDirection(offer string) string {
	switch offer {
	case "sendonly":
		return "recvonly"
	case "recvonly":
		return "sendonly"
	case "inactive":
		return "inactive"
	}
	return "sendrecv"
}

// sdpSecurity is the SRTP part of our SDP: the profile of m= and our keys.
type sdpSecurity struct {
	Profile string        // RTP/SAVP, or RTP/AVP when answering keys in an RTP/AVP offer
	Keys    []srtp.Crypto // ours: one line per suite in an offer, the accepted one in an answer
}

// buildSDP builds our SDP: one m=audio with the formats in order of
// preference; sec nil means plain RTP/AVP.
func buildSDP(ip net.IP, port int, sessID, version uint64, formats []lanFormat, dtmfPT int, direction string, sec *sdpSecurity) []byte {
	var b strings.Builder
	b.WriteString("v=0\r\n")
	fmt.Fprintf(&b, "o=mudi %d %d IN IP4 %s\r\n", sessID, version, ip)
	b.WriteString("s=mudi-imsd\r\n")
	fmt.Fprintf(&b, "c=IN IP4 %s\r\n", ip)
	b.WriteString("t=0 0\r\n")
	profile := "RTP/AVP"
	if sec != nil && sec.Profile != "" {
		profile = sec.Profile
	}
	fmt.Fprintf(&b, "m=audio %d %s", port, profile)
	for _, f := range formats {
		fmt.Fprintf(&b, " %d", f.PT)
	}
	if dtmfPT > 0 {
		fmt.Fprintf(&b, " %d", dtmfPT)
	}
	b.WriteString("\r\n")
	for _, f := range formats {
		fmt.Fprintf(&b, "a=rtpmap:%d %s/%d\r\n", f.PT, f.Name, f.Clock)
	}
	if dtmfPT > 0 {
		fmt.Fprintf(&b, "a=rtpmap:%d telephone-event/8000\r\n", dtmfPT)
		fmt.Fprintf(&b, "a=fmtp:%d 0-15\r\n", dtmfPT)
	}
	if sec != nil {
		for _, k := range sec.Keys {
			fmt.Fprintf(&b, "a=crypto:%s\r\n", k)
		}
	}
	b.WriteString("a=ptime:20\r\n")
	if direction == "" {
		direction = "sendrecv"
	}
	fmt.Fprintf(&b, "a=%s\r\n", direction)
	return []byte(b.String())
}

// offerFormats returns our offer to the phone: the configured codecs with static PTs.
func offerFormats(prefs []string) []lanFormat {
	out := make([]lanFormat, 0, len(prefs))
	for _, n := range prefs {
		if f, ok := staticLANFormats[n]; ok {
			out = append(out, f)
		}
	}
	return out
}
