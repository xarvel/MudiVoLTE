package sms

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Address is a TP or RP address (TS 23.040 §9.1.2.5, TS 24.008 §10.5.4.7).
type Address struct {
	Number string // digits, with leading + for international; text for alphanumeric
	TON    byte   // type of number: 1 international, 5 alphanumeric
	NPI    byte
}

func (a Address) String() string { return a.Number }

// ParseNumber builds an E.164/ISDN address from "+447700…" or "07700…".
func ParseNumber(s string) Address {
	if strings.HasPrefix(s, "+") {
		return Address{Number: s, TON: 1, NPI: 1}
	}
	return Address{Number: s, TON: 0, NPI: 1}
}

func toa(a Address) byte { return 0x80 | (a.TON&7)<<4 | a.NPI&0x0f }

func bcd(digits string) ([]byte, error) {
	out := make([]byte, (len(digits)+1)/2)
	for i, d := range digits {
		var v byte
		switch {
		case d >= '0' && d <= '9':
			v = byte(d - '0')
		case d == '*':
			v = 0xa
		case d == '#':
			v = 0xb
		default:
			return nil, fmt.Errorf("not a dialable digit: %q", d)
		}
		if i%2 == 0 {
			out[i/2] = 0xf0 | v
		} else {
			out[i/2] = out[i/2]&0x0f | v<<4
		}
	}
	return out, nil
}

func unbcd(b []byte, n int) string {
	var s strings.Builder
	for i := 0; i < n; i++ {
		v := b[i/2]
		if i%2 == 1 {
			v >>= 4
		}
		switch v &= 0x0f; {
		case v <= 9:
			s.WriteByte('0' + v)
		case v == 0xa:
			s.WriteByte('*')
		case v == 0xb:
			s.WriteByte('#')
		}
	}
	return s.String()
}

func digitsOf(a Address) string { return strings.TrimPrefix(a.Number, "+") }

// encodeTPAddress: length in digits, type, semi-octets (§9.1.2.5).
func encodeTPAddress(a Address) ([]byte, error) {
	d := digitsOf(a)
	v, err := bcd(d)
	if err != nil {
		return nil, err
	}
	return append([]byte{byte(len(d)), toa(a)}, v...), nil
}

func decodeTPAddress(b []byte) (Address, int, error) {
	if len(b) < 2 {
		return Address{}, 0, errors.New("short TP address")
	}
	n, t := int(b[0]), b[1]
	octets := (n + 1) / 2
	if len(b) < 2+octets {
		return Address{}, 0, errors.New("truncated TP address")
	}
	a := Address{TON: t >> 4 & 7, NPI: t & 0x0f}
	if a.TON == 5 { // alphanumeric: n counts semi-octets of packed 7-bit text
		sep, err := unpackSeptets(b[2:2+octets], octets*8/7, 0)
		if err != nil {
			return Address{}, 0, err
		}
		a.Number = strings.TrimRight(fromSeptets(sep), "@")
	} else {
		a.Number = unbcd(b[2:], n)
		if a.TON == 1 {
			a.Number = "+" + a.Number
		}
	}
	return a, 2 + octets, nil
}

// Alphabet of the user data (TS 23.038 §4).
type Alphabet int

const (
	GSM7 Alphabet = iota
	Data8
	UCS2
)

func alphabetOf(dcs byte) (Alphabet, error) {
	switch {
	case dcs&0xc0 == 0x00 || dcs&0xc0 == 0x40: // general data coding / auto-deletion groups
		switch dcs >> 2 & 3 {
		case 0:
			return GSM7, nil
		case 1:
			return Data8, nil
		case 2:
			return UCS2, nil
		}
		return 0, fmt.Errorf("reserved alphabet in DCS %#x", dcs)
	case dcs&0xf0 == 0xf0:
		if dcs&0x04 != 0 {
			return Data8, nil
		}
		return GSM7, nil
	case dcs&0xf0 == 0xc0 || dcs&0xf0 == 0xd0: // message waiting, discard/store, GSM 7-bit
		return GSM7, nil
	case dcs&0xf0 == 0xe0: // message waiting, store, UCS2
		return UCS2, nil
	}
	return 0, fmt.Errorf("unsupported DCS %#x", dcs)
}

// Part identifies one segment of a concatenated message (TS 23.040 §9.2.3.24.1/8).
type Part struct {
	Ref          uint16
	Total, Index int // 1-based
}

// Deliver is an SMS-DELIVER (TS 23.040 §9.2.2.1).
type Deliver struct {
	From                              Address
	PID, DCS                          byte
	Timestamp                         time.Time
	Text                              string // decoded text (empty for 8-bit data)
	Data                              []byte // raw user data for 8-bit messages
	Part                              *Part
	MoreToCome, StatusReportRequested bool
}

func parseUDH(udh []byte) *Part {
	for i := 0; i+2 <= len(udh); {
		iei, l := udh[i], int(udh[i+1])
		if i+2+l > len(udh) {
			return nil
		}
		v := udh[i+2 : i+2+l]
		switch {
		case iei == 0x00 && l == 3 && v[1] > 0:
			return &Part{Ref: uint16(v[0]), Total: int(v[1]), Index: int(v[2])}
		case iei == 0x08 && l == 4 && v[2] > 0:
			return &Part{Ref: uint16(v[0])<<8 | uint16(v[1]), Total: int(v[2]), Index: int(v[3])}
		}
		i += 2 + l
	}
	return nil
}

func decodeSCTS(b []byte) time.Time {
	d := func(x byte) int { return int(x&0x0f)*10 + int(x>>4) }
	quarters := int(b[6]&0x07)*10 + int(b[6]>>4)
	if b[6]&0x08 != 0 {
		quarters = -quarters
	}
	loc := time.FixedZone("", quarters*15*60)
	return time.Date(2000+d(b[0]), time.Month(d(b[1])), d(b[2]), d(b[3]), d(b[4]), d(b[5]), 0, loc)
}

// ParseDeliver decodes an SMS-DELIVER TPDU.
func ParseDeliver(t []byte) (*Deliver, error) {
	if len(t) < 1 || t[0]&3 != 0 {
		return nil, errors.New("not an SMS-DELIVER")
	}
	first := t[0]
	m := &Deliver{MoreToCome: first&0x04 == 0, StatusReportRequested: first&0x20 != 0}
	from, n, err := decodeTPAddress(t[1:])
	if err != nil {
		return nil, err
	}
	m.From = from
	p := 1 + n
	if len(t) < p+10 {
		return nil, errors.New("truncated SMS-DELIVER")
	}
	m.PID, m.DCS = t[p], t[p+1]
	m.Timestamp = decodeSCTS(t[p+2 : p+9])
	udl := int(t[p+9])
	ud := t[p+10:]
	alpha, err := alphabetOf(m.DCS)
	if err != nil {
		return nil, err
	}
	udhLen := 0
	if first&0x40 != 0 { // UDHI
		if len(ud) < 1 || len(ud) < 1+int(ud[0]) {
			return nil, errors.New("truncated user data header")
		}
		udhLen = 1 + int(ud[0])
		m.Part = parseUDH(ud[1:udhLen])
	}
	switch alpha {
	case GSM7:
		fill := (7 - udhLen*8%7) % 7
		skip := (udhLen*8 + fill) / 7
		n := udl - skip
		if n < 0 {
			// UDL short of the header it claims to carry: malformed, not ours to guess.
			return nil, errors.New("SMS-DELIVER: UDL smaller than the user data header")
		}
		sep, err := unpackSeptets(ud[udhLen:], n, fill)
		if err != nil {
			return nil, err
		}
		m.Text = fromSeptets(sep)
	case UCS2:
		if udl > len(ud) || udhLen > udl {
			return nil, errors.New("truncated UCS-2 user data")
		}
		m.Text = decodeUCS2(ud[udhLen:udl])
	case Data8:
		if udl > len(ud) || udhLen > udl {
			return nil, errors.New("truncated 8-bit user data")
		}
		m.Data = append([]byte(nil), ud[udhLen:udl]...)
	}
	return m, nil
}

// Submit builds the SMS-SUBMIT TPDUs for text, split with concatenation
// headers when it does not fit one message (TS 23.040 §9.2.2.2, §9.2.3.24.1).
func Submit(to Address, text string, mr byte, ref byte) ([][]byte, error) {
	da, err := encodeTPAddress(to)
	if err != nil {
		return nil, err
	}
	sep, gsm := toSeptets(text)
	var chunks [][]byte // septets or UCS-2 bytes per part
	if gsm {
		chunks = splitSeptets(sep, 160, 153)
	} else {
		u := encodeUCS2(text)
		chunks = splitUCS2(u, 140, 134)
	}
	var out [][]byte
	for i, c := range chunks {
		first := byte(0x01) // SMS-SUBMIT, no validity period
		var udh []byte
		if len(chunks) > 1 {
			first |= 0x40
			udh = []byte{5, 0x00, 3, ref, byte(len(chunks)), byte(i + 1)}
		}
		dcs := byte(0x00)
		if !gsm {
			dcs = 0x08
		}
		t := append([]byte{first, mr + byte(i)}, da...)
		t = append(t, 0x00, dcs)
		if gsm {
			fill := 0
			if udh != nil {
				fill = (7 - len(udh)*8%7) % 7
			}
			// Header octets first, then fill bits so the text starts on a septet boundary.
			body := append(append([]byte(nil), udh...), packSeptets(c, fill)...)
			udl := len(c) + (len(udh)*8+fill)/7
			t = append(t, byte(udl))
			t = append(t, body...)
		} else {
			ud := append(append([]byte(nil), udh...), c...)
			t = append(t, byte(len(ud)))
			t = append(t, ud...)
		}
		out = append(out, t)
	}
	return out, nil
}

// splitSeptets splits without separating an escape from its character.
func splitSeptets(s []byte, single, part int) [][]byte {
	if len(s) <= single {
		return [][]byte{s}
	}
	var out [][]byte
	for len(s) > 0 {
		n := min(part, len(s))
		if n < len(s) && s[n-1] == 0x1b {
			n--
		}
		out = append(out, s[:n])
		s = s[n:]
	}
	return out
}

// splitUCS2 splits UTF-16 bytes without cutting a surrogate pair.
func splitUCS2(u []byte, single, part int) [][]byte {
	if len(u) <= single {
		return [][]byte{u}
	}
	var out [][]byte
	for len(u) > 0 {
		n := min(part, len(u))
		if n < len(u) && u[n-2] >= 0xd8 && u[n-2] <= 0xdb {
			n -= 2
		}
		out = append(out, u[:n])
		u = u[n:]
	}
	return out
}
