package main

// LAN-side codecs. Inside the bridge audio is always 16 kHz mono PCM in 20 ms
// frames (320 samples), the same as AMR-WB. G.722 is wideband (16 kHz, no
// resampling); PCMU/PCMA are 8 kHz through the ×2 resampler.

import (
	"fmt"
	"math"

	"github.com/xarvel/MudiVoLTE/volte/media"
	"github.com/xarvel/MudiVoLTE/volte/media/g722"
)

const (
	frameSamples16k = 320 // 20 ms @ 16 kHz
	frameSamples8k  = 160 // 20 ms @ 8 kHz
	rtpTSStep8k     = 160 // RTP timestamp step per 20 ms for formats with an 8000 Hz clock (G.722 too)
)

type lanCodec interface {
	Name() string
	PT() int
	// Encode: 320 samples at 16 kHz → a 20 ms payload.
	Encode(pcm []int16) []byte
	// Decode: payload → 16 kHz PCM (a multiple of 320 when ptime is a multiple of 20 ms).
	Decode(payload []byte) []int16
}

func newLANCodec(f lanFormat) (lanCodec, error) {
	switch f.Name {
	case "G722":
		return &g722Codec{pt: f.PT, enc: g722.NewEncoder(), dec: g722.NewDecoder()}, nil
	case "PCMU":
		return &g711Codec{pt: f.PT, name: "PCMU", down: newDownsampler(), up: newUpsampler()}, nil
	case "PCMA":
		return &g711Codec{pt: f.PT, name: "PCMA", alaw: true, down: newDownsampler(), up: newUpsampler()}, nil
	}
	return nil, fmt.Errorf("codec %q is not supported", f.Name)
}

// --- G.722 ---

type g722Codec struct {
	pt  int
	enc *g722.Encoder
	dec *g722.Decoder
}

func (c *g722Codec) Name() string { return "G722" }
func (c *g722Codec) PT() int      { return c.pt }

func (c *g722Codec) Encode(pcm []int16) []byte {
	out := make([]byte, len(pcm)/2+1)
	n := c.enc.Encode(out, pcm)
	return out[:n]
}

func (c *g722Codec) Decode(payload []byte) []int16 {
	out := make([]int16, len(payload)*2)
	n := c.dec.Decode(out, payload)
	return out[:n]
}

// --- G.711 (μ-law / A-law) ---

type g711Codec struct {
	pt   int
	name string
	alaw bool
	down *resampler
	up   *resampler
}

func (c *g711Codec) Name() string { return c.name }
func (c *g711Codec) PT() int      { return c.pt }

func (c *g711Codec) Encode(pcm []int16) []byte {
	nb := c.down.down(pcm)
	if !c.alaw {
		out := make([]byte, len(nb))
		for i, s := range nb {
			out[i] = media.LinearToULaw(s)
		}
		return out
	}
	out := make([]byte, len(nb))
	for i, s := range nb {
		out[i] = alawEncode(s)
	}
	return out
}

func (c *g711Codec) Decode(payload []byte) []int16 {
	var nb []int16
	if !c.alaw {
		nb = make([]int16, len(payload))
		for i, b := range payload {
			nb[i] = media.ULawToLinear(b)
		}
	} else {
		nb = make([]int16, len(payload))
		for i, b := range payload {
			nb[i] = alawDecode(b)
		}
	}
	return c.up.up(nb)
}

// alawEncode/alawDecode implement ITU-T G.711 A-law (as in the reference g711.c).
var alawSegEnd = [8]int{0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF}

func alawEncode(sample int16) byte {
	pcm := int(sample) >> 3
	mask := 0xD5
	if pcm < 0 {
		mask = 0x55
		pcm = -pcm - 1
	}
	seg := len(alawSegEnd)
	for i, end := range alawSegEnd {
		if pcm <= end {
			seg = i
			break
		}
	}
	if seg >= len(alawSegEnd) {
		return byte(0x7F ^ mask)
	}
	aval := seg << 4
	if seg < 2 {
		aval |= (pcm >> 1) & 0x0F
	} else {
		aval |= (pcm >> seg) & 0x0F
	}
	return byte(aval ^ mask)
}

func alawDecode(a byte) int16 {
	v := int(a) ^ 0x55
	t := (v & 0x0F) << 4
	seg := (v & 0x70) >> 4
	switch seg {
	case 0:
		t += 8
	case 1:
		t += 0x108
	default:
		t += 0x108
		t <<= seg - 1
	}
	if v&0x80 != 0 {
		return int16(t)
	}
	return int16(-t)
}

// --- ×2 resampler (16 kHz ↔ 8 kHz) ---
//
// Low-pass FIR (Hamming window, 33 taps, cutoff ~3.7 kHz) with history across
// frames: without it the joints of the 20 ms frames click.

const resampTaps = 33

var resampFIR = func() []float64 {
	h := make([]float64, resampTaps)
	const fc = 0.23 // fraction of 16 kHz
	m := float64(resampTaps-1) / 2
	sum := 0.0
	for n := range h {
		x := float64(n) - m
		var s float64
		if x == 0 {
			s = 2 * fc
		} else {
			s = math.Sin(2*math.Pi*fc*x) / (math.Pi * x)
		}
		w := 0.54 - 0.46*math.Cos(2*math.Pi*float64(n)/float64(resampTaps-1))
		h[n] = s * w
		sum += h[n]
	}
	for n := range h {
		h[n] /= sum
	}
	return h
}()

type resampler struct {
	hist []float64 // the last resampTaps-1 samples of the 16 kHz stream
}

func newDownsampler() *resampler { return &resampler{hist: make([]float64, resampTaps-1)} }
func newUpsampler() *resampler   { return &resampler{hist: make([]float64, resampTaps-1)} }

// filterAt is the convolution at point i of buf (history + current samples).
func filterAt(buf []float64, i int) float64 {
	acc := 0.0
	for k, h := range resampFIR {
		acc += buf[i-k] * h
	}
	return acc
}

// down: 16 kHz → 8 kHz (filter, then every second sample).
func (r *resampler) down(in []int16) []int16 {
	buf := make([]float64, len(r.hist)+len(in))
	copy(buf, r.hist)
	for i, s := range in {
		buf[len(r.hist)+i] = float64(s)
	}
	out := make([]int16, len(in)/2)
	for j := range out {
		out[j] = clamp16(filterAt(buf, len(r.hist)+2*j+1))
	}
	copy(r.hist, buf[len(buf)-len(r.hist):])
	return out
}

// up: 8 kHz → 16 kHz (zero insertion, filter, gain ×2).
func (r *resampler) up(in []int16) []int16 {
	buf := make([]float64, len(r.hist)+2*len(in))
	copy(buf, r.hist)
	for i, s := range in {
		buf[len(r.hist)+2*i] = float64(s)
	}
	out := make([]int16, 2*len(in))
	for j := range out {
		out[j] = clamp16(2 * filterAt(buf, len(r.hist)+j))
	}
	copy(r.hist, buf[len(buf)-len(r.hist):])
	return out
}

func clamp16(v float64) int16 {
	if v > 32767 {
		return 32767
	}
	if v < -32768 {
		return -32768
	}
	return int16(math.Round(v))
}
