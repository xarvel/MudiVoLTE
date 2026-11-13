package sms

import (
	"errors"
	"fmt"
)

// RP message types (TS 24.011 §8.2.2).
const (
	RPDataMSToN  = 0
	RPDataNToMS  = 1
	RPAckMSToN   = 2
	RPAckNToMS   = 3
	RPErrorMSToN = 4
	RPErrorNToMS = 5
	RPSMMA       = 6
)

// RP cause values we send (TS 24.011 Table 8.4).
const (
	CauseMemoryExceeded = 22
	CauseInvalidMessage = 95
	CauseProtocolError  = 111
)

// RP is one relay-layer message.
type RP struct {
	MTI   byte
	MR    byte
	OA    *Address // RP-DATA network→MS: the service centre
	DA    *Address // RP-DATA MS→network: the service centre
	Cause byte     // RP-ERROR
	TPDU  []byte   // RP-User-Data
}

func encodeRPAddress(a *Address) ([]byte, error) {
	if a == nil {
		return []byte{0}, nil
	}
	v, err := bcd(digitsOf(*a))
	if err != nil {
		return nil, err
	}
	return append([]byte{byte(1 + len(v)), toa(*a)}, v...), nil
}

func decodeRPAddress(b []byte) (*Address, int, error) {
	if len(b) < 1 {
		return nil, 0, errors.New("short RP address")
	}
	n := int(b[0])
	if n == 0 {
		return nil, 1, nil
	}
	if len(b) < 1+n {
		return nil, 0, errors.New("truncated RP address")
	}
	t := b[1]
	digits := 2 * (n - 1)
	if b[n]>>4 == 0x0f {
		digits--
	}
	a := &Address{TON: t >> 4 & 7, NPI: t & 0x0f, Number: unbcd(b[2:], digits)}
	if a.TON == 1 {
		a.Number = "+" + a.Number
	}
	return a, 1 + n, nil
}

// Marshal renders the RP message (TS 24.011 §7.3).
func (m RP) Marshal() ([]byte, error) {
	out := []byte{m.MTI & 7, m.MR}
	switch m.MTI {
	case RPDataMSToN, RPDataNToMS:
		oa, err := encodeRPAddress(m.OA)
		if err != nil {
			return nil, err
		}
		da, err := encodeRPAddress(m.DA)
		if err != nil {
			return nil, err
		}
		out = append(append(out, oa...), da...)
		out = append(out, byte(len(m.TPDU)))
		return append(out, m.TPDU...), nil
	case RPAckMSToN, RPAckNToMS:
		if len(m.TPDU) > 0 {
			out = append(out, 0x41, byte(len(m.TPDU)))
			out = append(out, m.TPDU...)
		}
		return out, nil
	case RPErrorMSToN, RPErrorNToMS:
		out = append(out, 1, m.Cause)
		if len(m.TPDU) > 0 {
			out = append(out, 0x41, byte(len(m.TPDU)))
			out = append(out, m.TPDU...)
		}
		return out, nil
	case RPSMMA:
		return out, nil
	}
	return nil, fmt.Errorf("unknown RP-MTI %d", m.MTI)
}

// ParseRP decodes an RP message.
func ParseRP(b []byte) (RP, error) {
	if len(b) < 2 {
		return RP{}, errors.New("short RP message")
	}
	m := RP{MTI: b[0] & 7, MR: b[1]}
	rest := b[2:]
	switch m.MTI {
	case RPDataMSToN, RPDataNToMS:
		var n int
		var err error
		if m.OA, n, err = decodeRPAddress(rest); err != nil {
			return RP{}, err
		}
		rest = rest[n:]
		if m.DA, n, err = decodeRPAddress(rest); err != nil {
			return RP{}, err
		}
		rest = rest[n:]
		if len(rest) < 1 || len(rest) < 1+int(rest[0]) {
			return RP{}, errors.New("truncated RP-User-Data")
		}
		m.TPDU = append([]byte(nil), rest[1:1+int(rest[0])]...)
	case RPErrorMSToN, RPErrorNToMS:
		if len(rest) < 2 || rest[0] < 1 || len(rest) < 1+int(rest[0]) {
			return RP{}, errors.New("truncated RP-Cause")
		}
		m.Cause = rest[1] & 0x7f
		rest = rest[1+int(rest[0]):]
		fallthrough
	case RPAckMSToN, RPAckNToMS:
		if len(rest) >= 2 && rest[0] == 0x41 && len(rest) >= 2+int(rest[1]) {
			m.TPDU = append([]byte(nil), rest[2:2+int(rest[1])]...)
		}
	case RPSMMA:
	default:
		return RP{}, fmt.Errorf("unknown RP-MTI %d", m.MTI)
	}
	return m, nil
}
