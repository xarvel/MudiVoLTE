package media

import (
	"encoding/binary"
	"errors"
	"strings"
)

// DTMF events of RFC 4733 §3.2: 0–9, *, #, A–D.
const dtmfDigits = "0123456789*#ABCD"

// DTMFEvent is the 4-byte telephone-event payload.
type DTMFEvent struct {
	Event    uint8
	End      bool
	Volume   uint8 // dBm0 below 0, 0–63
	Duration uint16
}

func (e DTMFEvent) Marshal() []byte {
	b := make([]byte, 4)
	b[0] = e.Event
	b[1] = e.Volume & 0x3f
	if e.End {
		b[1] |= 0x80
	}
	binary.BigEndian.PutUint16(b[2:], e.Duration)
	return b
}

func ParseDTMF(b []byte) (DTMFEvent, error) {
	if len(b) < 4 {
		return DTMFEvent{}, errors.New("short telephone-event payload")
	}
	return DTMFEvent{Event: b[0], End: b[1]&0x80 != 0, Volume: b[1] & 0x3f, Duration: binary.BigEndian.Uint16(b[2:])}, nil
}

// DigitEvent maps a key to its event code.
func DigitEvent(d rune) (uint8, bool) {
	i := strings.IndexRune(dtmfDigits, d)
	if i < 0 {
		i = strings.IndexRune(dtmfDigits, d-'a'+'A')
	}
	return uint8(i), i >= 0
}

// EventDigit maps an event code to its key.
func EventDigit(e uint8) (rune, bool) {
	if int(e) < len(dtmfDigits) {
		return rune(dtmfDigits[e]), true
	}
	return 0, false
}
