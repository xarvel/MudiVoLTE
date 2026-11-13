package media

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// ReadWAV loads a mono 16-bit PCM WAV file.
func ReadWAV(path string) (pcm []int16, rate int, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	if len(b) < 12 || string(b[:4]) != "RIFF" || string(b[8:12]) != "WAVE" {
		return nil, 0, errors.New("not a WAV file")
	}
	var channels, bits int
	for off := 12; off+8 <= len(b); {
		id, size := string(b[off:off+4]), int(binary.LittleEndian.Uint32(b[off+4:]))
		body := b[off+8 : min(off+8+size, len(b))]
		switch id {
		case "fmt ":
			if len(body) < 16 || binary.LittleEndian.Uint16(body) != 1 {
				return nil, 0, errors.New("WAV is not PCM")
			}
			channels = int(binary.LittleEndian.Uint16(body[2:]))
			rate = int(binary.LittleEndian.Uint32(body[4:]))
			bits = int(binary.LittleEndian.Uint16(body[14:]))
		case "data":
			if channels != 1 || bits != 16 {
				return nil, 0, fmt.Errorf("need mono 16-bit WAV, got %d ch %d bit", channels, bits)
			}
			pcm = make([]int16, len(body)/2)
			for i := range pcm {
				pcm[i] = int16(binary.LittleEndian.Uint16(body[2*i:]))
			}
			return pcm, rate, nil
		}
		off += 8 + size + size%2
	}
	return nil, 0, errors.New("WAV has no data chunk")
}

// WAVWriter streams mono 16-bit PCM into a WAV file.
type WAVWriter struct {
	f    *os.File
	rate int
	n    int
}

func CreateWAV(path string, rate int) (*WAVWriter, error) {
	// Recordings are voice: owner-only, regardless of umask.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	w := &WAVWriter{f: f, rate: rate}
	if _, err := f.Write(w.header()); err != nil {
		f.Close()
		return nil, err
	}
	return w, nil
}

func (w *WAVWriter) header() []byte {
	h := make([]byte, 44)
	copy(h, "RIFF")
	binary.LittleEndian.PutUint32(h[4:], uint32(36+2*w.n))
	copy(h[8:], "WAVEfmt ")
	binary.LittleEndian.PutUint32(h[16:], 16)
	binary.LittleEndian.PutUint16(h[20:], 1)
	binary.LittleEndian.PutUint16(h[22:], 1)
	binary.LittleEndian.PutUint32(h[24:], uint32(w.rate))
	binary.LittleEndian.PutUint32(h[28:], uint32(2*w.rate))
	binary.LittleEndian.PutUint16(h[32:], 2)
	binary.LittleEndian.PutUint16(h[34:], 16)
	copy(h[36:], "data")
	binary.LittleEndian.PutUint32(h[40:], uint32(2*w.n))
	return h
}

func (w *WAVWriter) Write(pcm []int16) error {
	b := make([]byte, 2*len(pcm))
	for i, s := range pcm {
		binary.LittleEndian.PutUint16(b[2*i:], uint16(s))
	}
	_, err := w.f.Write(b)
	w.n += len(pcm)
	return err
}

// Close fixes up the sizes and closes the file.
func (w *WAVWriter) Close() error {
	if _, err := w.f.Seek(0, io.SeekStart); err != nil {
		w.f.Close()
		return err
	}
	if _, err := w.f.Write(w.header()); err != nil {
		w.f.Close()
		return err
	}
	return w.f.Close()
}

// Resample converts between 8 and 16 kHz (pair averaging down, linear
// interpolation up); other ratios are returned unchanged with an error.
func Resample(pcm []int16, from, to int) ([]int16, error) {
	switch {
	case from == to:
		return pcm, nil
	case from == 2*to:
		out := make([]int16, len(pcm)/2)
		for i := range out {
			out[i] = int16((int(pcm[2*i]) + int(pcm[2*i+1])) / 2)
		}
		return out, nil
	case to == 2*from:
		out := make([]int16, 2*len(pcm))
		for i, s := range pcm {
			next := s
			if i+1 < len(pcm) {
				next = pcm[i+1]
			}
			out[2*i], out[2*i+1] = s, int16((int(s)+int(next))/2)
		}
		return out, nil
	}
	return pcm, fmt.Errorf("resampling %d→%d Hz not supported", from, to)
}

// Play paces pcm into the stream in real time (one packet per ptime) until
// the samples run out or stop is closed. The tail is zero padded.
func Play(s *Stream, pcm []int16, stop <-chan struct{}) error {
	n := s.SamplesPerPacket()
	tick := time.NewTicker(time.Duration(s.cfg.Ptime) * time.Millisecond)
	defer tick.Stop()
	for off := 0; off < len(pcm); off += n {
		chunk := make([]int16, n)
		copy(chunk, pcm[off:min(off+n, len(pcm))])
		if err := s.Send(chunk); err != nil {
			return err
		}
		select {
		case <-stop:
			return nil
		case <-tick.C:
		}
	}
	return nil
}
