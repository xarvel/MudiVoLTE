// Package sms implements SMS over IP for the UE (3GPP TS 24.341): the
// relay layer RP (TS 24.011 §7.3), the transfer layer TPDUs SMS-DELIVER and
// SMS-SUBMIT (TS 23.040 §9.2), the GSM 7-bit and UCS-2 alphabets
// (TS 23.038 §6.2) and concatenation, plus the SIP MESSAGE exchange.
package sms

import (
	"errors"
	"strings"
	"unicode/utf16"
)

// GSM 7-bit default alphabet (TS 23.038 §6.2.1); 0x1B is the escape.
var gsm7 = []rune("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?" +
	"¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà")

// Extension table entries reached through the escape (§6.2.1.1).
var gsm7ext = map[byte]rune{0x0a: '\f', 0x14: '^', 0x28: '{', 0x29: '}', 0x2f: '\\',
	0x3c: '[', 0x3d: '~', 0x3e: ']', 0x40: '|', 0x65: '€'}

var (
	gsm7Rev    = map[rune]byte{}
	gsm7ExtRev = map[rune]byte{}
)

func init() {
	if len(gsm7) != 128 {
		panic("GSM 7-bit table must have 128 entries")
	}
	for i, r := range gsm7 {
		if i != 0x1b {
			gsm7Rev[r] = byte(i)
		}
	}
	for k, r := range gsm7ext {
		gsm7ExtRev[r] = k
	}
}

// toSeptets maps text to GSM 7-bit codes; ok is false if a rune is missing.
func toSeptets(s string) ([]byte, bool) {
	var out []byte
	for _, r := range s {
		if c, ok := gsm7Rev[r]; ok {
			out = append(out, c)
		} else if c, ok := gsm7ExtRev[r]; ok {
			out = append(out, 0x1b, c)
		} else {
			return nil, false
		}
	}
	return out, true
}

func fromSeptets(sep []byte) string {
	var b strings.Builder
	for i := 0; i < len(sep); i++ {
		c := sep[i] & 0x7f
		if c == 0x1b && i+1 < len(sep) {
			i++
			if r, ok := gsm7ext[sep[i]&0x7f]; ok {
				b.WriteRune(r)
			} else {
				b.WriteRune(gsm7[sep[i]&0x7f]) // unknown extension: show base char (§6.2.1.1)
			}
			continue
		}
		b.WriteRune(gsm7[c])
	}
	return b.String()
}

// packSeptets packs 7-bit codes LSB first, after fill padding bits (used
// when a UDH precedes the text so that the text starts on a septet boundary).
func packSeptets(sep []byte, fill int) []byte {
	totalBits := fill + 7*len(sep)
	out := make([]byte, (totalBits+7)/8)
	bit := fill
	for _, s := range sep {
		for i := 0; i < 7; i++ {
			if s>>uint(i)&1 != 0 {
				out[bit/8] |= 1 << uint(bit%8)
			}
			bit++
		}
	}
	return out
}

func unpackSeptets(b []byte, n, fill int) ([]byte, error) {
	if n < 0 || fill < 0 || fill > 7 {
		return nil, errors.New("7-bit user data: bad length")
	}
	if (fill+7*n+7)/8 > len(b) {
		return nil, errors.New("7-bit user data truncated")
	}
	out := make([]byte, n)
	bit := fill
	for i := range out {
		var v byte
		for j := 0; j < 7; j++ {
			if b[bit/8]>>uint(bit%8)&1 != 0 {
				v |= 1 << uint(j)
			}
			bit++
		}
		out[i] = v
	}
	return out, nil
}

func encodeUCS2(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 2*len(u))
	for i, c := range u {
		out[2*i], out[2*i+1] = byte(c>>8), byte(c)
	}
	return out
}

func decodeUCS2(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	return string(utf16.Decode(u))
}
