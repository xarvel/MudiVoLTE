package media

import (
	"errors"
	"fmt"
)

// AMR-WB frame types (3GPP TS 26.201 Table 1a). 0–8 are speech modes,
// 9 is SID, 14 speech lost, 15 no data.
const (
	FTSID     = 9
	FTLost    = 14
	FTNoData  = 15
	CMRNoPref = 15
)

// amrwbBits is the number of class A+B+C bits per frame type (TS 26.201 Table 2).
var amrwbBits = [16]int{132, 177, 253, 285, 317, 365, 397, 461, 477, 40}

// Frame is one AMR-WB frame: type, quality bit and speech bits, MSB first,
// in the order of TS 26.201 (the same order as the RFC 4867 storage format).
type Frame struct {
	FT   uint8
	Good bool   // Q bit
	Bits []byte // ceil(bits/8) bytes, zero padded
}

// FrameBytes is the byte length of a frame's speech bits.
func FrameBytes(ft uint8) int { return (amrwbBits[ft&15] + 7) / 8 }

func validFT(ft uint8) bool { return ft <= FTSID || ft == FTLost || ft == FTNoData }

// bitWriter / bitReader pack MSB first.
type bitWriter struct {
	b []byte
	n int // bits written
}

func (w *bitWriter) put(v uint32, bits int) {
	for i := bits - 1; i >= 0; i-- {
		if w.n%8 == 0 {
			w.b = append(w.b, 0)
		}
		if v>>uint(i)&1 != 0 {
			w.b[w.n/8] |= 0x80 >> uint(w.n%8)
		}
		w.n++
	}
}

func (w *bitWriter) putBits(src []byte, bits int) {
	for i := 0; i < bits; i++ {
		w.put(uint32(src[i/8]>>(7-uint(i%8))&1), 1)
	}
}

type bitReader struct {
	b []byte
	n int
}

func (r *bitReader) get(bits int) (uint32, error) {
	if r.n+bits > len(r.b)*8 {
		return 0, errors.New("AMR-WB payload truncated")
	}
	var v uint32
	for i := 0; i < bits; i++ {
		v = v<<1 | uint32(r.b[r.n/8]>>(7-uint(r.n%8))&1)
		r.n++
	}
	return v, nil
}

func (r *bitReader) getBits(bits int) ([]byte, error) {
	out := make([]byte, (bits+7)/8)
	for i := 0; i < bits; i++ {
		v, err := r.get(1)
		if err != nil {
			return nil, err
		}
		out[i/8] |= byte(v) << (7 - uint(i%8))
	}
	return out, nil
}

// PackAMRWB builds an RFC 4867 single-channel payload (§4.4.x BE, §4.4.x OA)
// carrying frames in order, with codec mode request cmr.
func PackAMRWB(frames []Frame, cmr uint8, octetAligned bool) ([]byte, error) {
	if len(frames) == 0 {
		return nil, errors.New("no frames")
	}
	w := &bitWriter{}
	w.put(uint32(cmr&15), 4)
	if octetAligned {
		w.put(0, 4)
	}
	for i, f := range frames {
		if !validFT(f.FT) {
			return nil, fmt.Errorf("invalid frame type %d", f.FT)
		}
		follow := uint32(0)
		if i < len(frames)-1 {
			follow = 1
		}
		q := uint32(0)
		if f.Good {
			q = 1
		}
		w.put(follow, 1)
		w.put(uint32(f.FT), 4)
		w.put(q, 1)
		if octetAligned {
			w.put(0, 2)
		}
	}
	for _, f := range frames {
		bits := amrwbBits[f.FT]
		if len(f.Bits)*8 < bits {
			return nil, fmt.Errorf("frame type %d needs %d bits, got %d bytes", f.FT, bits, len(f.Bits))
		}
		w.putBits(f.Bits, bits)
		if octetAligned && w.n%8 != 0 {
			w.put(0, 8-w.n%8)
		}
	}
	return w.b, nil
}

// UnpackAMRWB parses an RFC 4867 single-channel payload.
func UnpackAMRWB(p []byte, octetAligned bool) (frames []Frame, cmr uint8, err error) {
	r := &bitReader{b: p}
	v, err := r.get(4)
	if err != nil {
		return nil, 0, err
	}
	cmr = uint8(v)
	if octetAligned {
		r.n += 4
	}
	for {
		f, err := r.get(1)
		if err != nil {
			return nil, 0, err
		}
		ft, err := r.get(4)
		if err != nil {
			return nil, 0, err
		}
		q, err := r.get(1)
		if err != nil {
			return nil, 0, err
		}
		if octetAligned {
			r.n += 2
		}
		if !validFT(uint8(ft)) {
			return nil, 0, fmt.Errorf("invalid frame type %d", ft)
		}
		frames = append(frames, Frame{FT: uint8(ft), Good: q == 1})
		if f == 0 {
			break
		}
		if len(frames) > 32 {
			return nil, 0, errors.New("too many AMR-WB frames in one packet")
		}
	}
	for i := range frames {
		bits := amrwbBits[frames[i].FT]
		if frames[i].Bits, err = r.getBits(bits); err != nil {
			return nil, 0, err
		}
		if octetAligned && r.n%8 != 0 {
			r.n += 8 - r.n%8
		}
	}
	return frames, cmr, nil
}

// StorageFrame renders a frame in the RFC 4867 §5.3 storage format
// (header byte + speech bytes), the input of common AMR-WB decoders.
func (f Frame) StorageFrame() []byte {
	h := f.FT << 3
	if f.Good {
		h |= 0x04
	}
	out := make([]byte, 1+FrameBytes(f.FT))
	out[0] = h
	copy(out[1:], f.Bits)
	return out
}

// FrameFromStorage parses one storage-format frame.
func FrameFromStorage(b []byte) (Frame, error) {
	if len(b) == 0 {
		return Frame{}, errors.New("empty frame")
	}
	ft := b[0] >> 3 & 15
	if !validFT(ft) || len(b) < 1+FrameBytes(ft) {
		return Frame{}, fmt.Errorf("bad storage frame (type %d, %d bytes)", ft, len(b))
	}
	return Frame{FT: ft, Good: b[0]&0x04 != 0, Bits: append([]byte(nil), b[1:1+FrameBytes(ft)]...)}, nil
}
