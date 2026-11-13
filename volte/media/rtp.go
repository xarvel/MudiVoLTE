// Package media carries the voice of one call: RTP (RFC 3550), the AMR-WB
// payload format (RFC 4867), G.711 (ITU-T G.711), DTMF events (RFC 4733) and
// WAV helpers. The AMR-WB speech codec itself is pluggable (see FrameCoder).
package media

import (
	"encoding/binary"
	"errors"
)

// Packet is an RTP packet without CSRC lists or extensions on send.
type Packet struct {
	Marker    bool
	PT        uint8
	Seq       uint16
	Timestamp uint32
	SSRC      uint32
	Payload   []byte
}

// Marshal renders the packet (RFC 3550 §5.1).
func (p Packet) Marshal() []byte {
	b := make([]byte, 12+len(p.Payload))
	b[0] = 2 << 6
	b[1] = p.PT & 0x7f
	if p.Marker {
		b[1] |= 0x80
	}
	binary.BigEndian.PutUint16(b[2:], p.Seq)
	binary.BigEndian.PutUint32(b[4:], p.Timestamp)
	binary.BigEndian.PutUint32(b[8:], p.SSRC)
	copy(b[12:], p.Payload)
	return b
}

// ParsePacket parses an RTP packet, skipping CSRCs, extension and padding.
func ParsePacket(b []byte) (Packet, error) {
	if len(b) < 12 || b[0]>>6 != 2 {
		return Packet{}, errors.New("not an RTP v2 packet")
	}
	p := Packet{
		Marker:    b[1]&0x80 != 0,
		PT:        b[1] & 0x7f,
		Seq:       binary.BigEndian.Uint16(b[2:]),
		Timestamp: binary.BigEndian.Uint32(b[4:]),
		SSRC:      binary.BigEndian.Uint32(b[8:]),
	}
	off := 12 + 4*int(b[0]&0x0f)
	if b[0]&0x10 != 0 { // extension
		if len(b) < off+4 {
			return Packet{}, errors.New("truncated RTP extension")
		}
		off += 4 + 4*int(binary.BigEndian.Uint16(b[off+2:]))
	}
	end := len(b)
	if b[0]&0x20 != 0 { // padding: the last octet counts the pad bytes, itself included (RFC 3550 §5.1)
		if pad := int(b[len(b)-1]); pad > 0 {
			end -= pad
		}
	}
	if off > end {
		return Packet{}, errors.New("truncated RTP packet")
	}
	p.Payload = b[off:end]
	return p, nil
}
