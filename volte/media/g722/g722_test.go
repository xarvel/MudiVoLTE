package g722

import (
	"encoding/binary"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

// testdata, produced by ffmpeg 7.1 (regenerate: go test -run TestTestdata -update):
//
//	signals.raw      synthetic input, 16 kHz mono s16le: synth(1000) back to back
//	signals.g722     ffmpeg's encoding of signals.raw
//	signals.dec.raw  ffmpeg's decoding of signals.g722
//	random.g722      uniformly random octets, the suppressed codewords included
//	random.dec.raw   ffmpeg's decoding of random.g722
//	filtez.g722      filtezStream(): drives the zero predictor into overflow
//	filtez.dec.raw   ffmpeg's decoding of filtez.g722

func readFile(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func toPCM(b []byte) []int16 {
	out := make([]int16, len(b)/2)
	for i := range out {
		out[i] = int16(binary.LittleEndian.Uint16(b[2*i:]))
	}
	return out
}

func fromPCM(pcm []int16) []byte {
	out := make([]byte, 2*len(pcm))
	for i, s := range pcm {
		binary.LittleEndian.PutUint16(out[2*i:], uint16(s))
	}
	return out
}

func encode(pcm []int16) []byte {
	out := make([]byte, len(pcm)/2)
	NewEncoder().Encode(out, pcm)
	return out
}

func decode(g []byte) []int16 {
	out := make([]int16, 2*len(g))
	NewDecoder().Decode(out, g)
	return out
}

// firstDiff returns the first index where a and b differ, or -1.
func firstDiff[T comparable](a, b []T) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return min(len(a), len(b))
	}
	return -1
}

type signal struct {
	name string
	pcm  []int16
}

// synth returns the synthetic inputs, n samples each.
func synth(n int) []signal {
	rng := rand.New(rand.NewPCG(1, 2))
	gen := func(f func(i int) float64) []int16 {
		out := make([]int16, n)
		for i := range out {
			out[i] = int16(max(-32768, min(32767, math.Round(f(i)))))
		}
		return out
	}
	sin := func(hz float64, i int) float64 { return math.Sin(2 * math.Pi * hz * float64(i) / 16000) }
	dur := float64(n) / 16000
	return []signal{
		{"silence", make([]int16, n)},
		{"tone", gen(func(i int) float64 { return 8000 * sin(1000, i) })},
		{"sweep", gen(func(i int) float64 { // logarithmic, 50 Hz to 7900 Hz
			t, k := float64(i)/16000, math.Log(7900.0/50)/dur
			return 16000 * math.Sin(2*math.Pi*50*(math.Exp(k*t)-1)/k)
		})},
		{"noise", gen(func(int) float64 { return 6000 * rng.NormFloat64() })},
		{"quiet", gen(func(int) float64 { return 20 * rng.NormFloat64() })},
		{"clipped", gen(func(i int) float64 { return 50000 * sin(440, i) })},
		{"square", gen(func(i int) float64 { return 32767.5*float64(1-2*(i/20%2)) - 0.5 })},
		{"hf7k", gen(func(i int) float64 { return 32767 * sin(7000, i) })},
		{"steps", gen(func(i int) float64 { return []float64{32767, 0, -32768, 0}[i/250%4] })},
	}
}

// filtezStream is 60 octets of 0xC4, 60 of 0xE0, twice: the extreme lower
// sub-band codewords one way and then the other, the higher sub-band idle.
func filtezStream() []byte {
	var out []byte
	for range 2 {
		for _, c := range []byte{0xc4, 0xe0} {
			for range 60 {
				out = append(out, c)
			}
		}
	}
	return out
}

func randomStream(n int) []byte {
	rng := rand.New(rand.NewPCG(3, 4))
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(rng.Uint32())
	}
	return out
}

// The encoder reproduces ffmpeg's stream octet for octet: tone, sweep,
// noise, silence, low-level noise, clipping, full-scale square wave and
// 7 kHz tone, DC steps.
func TestEncoderMatchesFFmpegVectors(t *testing.T) {
	in := toPCM(readFile(t, "signals.raw"))
	want := readFile(t, "signals.g722")
	got := encode(in)
	if i := firstDiff(got, want); i >= 0 {
		t.Fatalf("octet %d (signal %s): %#02x, ffmpeg %#02x", i, synth(1)[2*i/1000].name, got[i], want[i])
	}
}

// The decoder reproduces ffmpeg's PCM sample for sample, on ffmpeg's own
// stream and on random octets (including 0000XX, read as 111111).
func TestDecoderMatchesFFmpegVectors(t *testing.T) {
	for _, name := range []string{"signals", "random"} {
		in := readFile(t, name+".g722")
		want := toPCM(readFile(t, name+".dec.raw"))
		got := decode(in)
		if i := firstDiff(got, want); i >= 0 {
			t.Errorf("%s: sample %d is %d, ffmpeg %d", name, i, got[i], want[i])
		}
	}
}

// predictWide is predict with the FILTEZ products summed in a 32-bit word
// and saturated once, which is how ffmpeg's decoder computes it.
func (b *band) predictWide() {
	var sz int32
	for i := range b.b {
		sz += b.b[i] * sat(b.d[i]+b.d[i]) >> 15
	}
	sz = sat(sz)
	sp := sat(b.a1*sat(b.r1+b.r1)>>15 + b.a2*sat(b.r2+b.r2)>>15)
	b.sz = sz
	b.s = sat(sp + sz)
}

// decodeWide is Decoder.Decode with predictWide. first is the first octet at
// which the wide FILTEZ sum differs from the one of §6.2.1.4, or -1.
func decodeWide(src []byte) (pcm []int16, first int) {
	d := NewDecoder()
	pcm, first = make([]int16, 2*len(src)), -1
	predict := func(k int, b *band) {
		ordered := *b
		ordered.predict()
		b.predictWide()
		if ordered.sz != b.sz && first < 0 {
			first = k
		}
	}
	for k, c := range src {
		ilr, ih := int32(c&0x3f), c>>6
		lo := &d.low
		predict(k, lo)
		rl := limit15(sat(lo.s + lo.det*invq6[ilr]>>15))
		ril := ilr >> 2
		lo.update(lo.det*invq4[ril]>>15, wl[il4[ril]], 18432, 8)
		hi := &d.hig
		predict(k, hi)
		dh := hi.det * invq2[ih] >> 15
		rh := limit15(sat(hi.s + dh))
		hi.update(dh, wh[ih2[ih]], 22528, 10)
		d.p = (d.p + 11) % 12
		d.hd[d.p], d.hd[d.p+12] = rl-rh, rl-rh
		d.hs[d.p], d.hs[d.p+12] = rl+rh, rl+rh
		var w1, w2 int32
		for i := range 12 {
			w1 += d.hd[d.p+i] * qmf[2*i]
			w2 += d.hs[d.p+i] * qmf[2*i+1]
		}
		pcm[2*k], pcm[2*k+1] = int16(sat(w1>>11)), int16(sat(w2>>11))
	}
	return pcm, first
}

// checkFILTEZDeviation pins down the one place where ffmpeg's decoder departs
// from the Recommendation: it agrees with us until the first octet whose
// FILTEZ partial sums saturate (§6.2.1.4 adds them with 16-bit saturation in
// a fixed order), and with a wide-accumulator FILTEZ on every sample.
func checkFILTEZDeviation(t *testing.T, name string, in []byte, ffmpeg []int16) {
	t.Helper()
	wide, k := decodeWide(in)
	if i := firstDiff(wide, ffmpeg); i >= 0 {
		t.Fatalf("%s: wide FILTEZ differs from ffmpeg at sample %d: %d vs %d", name, i, wide[i], ffmpeg[i])
	}
	got := decode(in)
	i := firstDiff(got, ffmpeg)
	switch {
	case k < 0 && i >= 0:
		t.Fatalf("%s: sample %d is %d, ffmpeg %d, without FILTEZ saturation", name, i, got[i], ffmpeg[i])
	case k >= 0 && i >= 0 && i < 2*k:
		t.Fatalf("%s: sample %d differs before the FILTEZ saturation at octet %d", name, i, k)
	case k >= 0 && i < 0:
		t.Logf("%s: FILTEZ saturates at octet %d without changing the output", name, k)
	case k >= 0:
		t.Logf("%s: FILTEZ saturates at octet %d, output departs from ffmpeg at sample %d", name, k, i)
	}
}

func TestFILTEZOrder(t *testing.T) {
	in := readFile(t, "filtez.g722")
	ffmpeg := toPCM(readFile(t, "filtez.dec.raw"))
	if firstDiff(decode(in), ffmpeg) < 0 {
		t.Fatal("filtez.g722 no longer separates the two FILTEZ sums")
	}
	checkFILTEZDeviation(t, "filtez", in, ffmpeg)
}

// Frame-by-frame coding (20 ms: 320 samples, 160 octets) and odd chunk
// sizes give the same result as one call.
func TestFrames(t *testing.T) {
	in := toPCM(readFile(t, "signals.raw"))
	whole := encode(in)
	wholePCM := decode(whole)
	rng := rand.New(rand.NewPCG(5, 6))
	for _, step := range []int{320, 2, -1} {
		e, d := NewEncoder(), NewDecoder()
		var g []byte
		var pcm []int16
		for off := 0; off < len(in); {
			n := step
			if n < 0 {
				n = 2 * rng.IntN(200)
			}
			n = min(n, len(in)-off)
			buf := make([]byte, n/2)
			if w := e.Encode(buf, in[off:off+n]); w != n/2 {
				t.Fatalf("Encode wrote %d of %d", w, n/2)
			}
			out := make([]int16, n)
			if w := d.Decode(out, buf); w != n {
				t.Fatalf("Decode wrote %d of %d", w, n)
			}
			g, pcm = append(g, buf...), append(pcm, out...)
			off += n
		}
		if i := firstDiff(g, whole); i >= 0 {
			t.Errorf("step %d: octet %d differs", step, i)
		}
		if i := firstDiff(pcm, wholePCM); i >= 0 {
			t.Errorf("step %d: sample %d differs", step, i)
		}
	}
}

func TestLengthsAndReset(t *testing.T) {
	e, d := NewEncoder(), NewDecoder()
	if n := e.Encode(make([]byte, 3), make([]int16, 10)); n != 3 {
		t.Errorf("short dst: Encode = %d, want 3", n)
	}
	if n := e.Encode(make([]byte, 10), make([]int16, 7)); n != 3 {
		t.Errorf("odd src: Encode = %d, want 3", n)
	}
	if n := d.Decode(make([]int16, 5), make([]byte, 4)); n != 4 {
		t.Errorf("short dst: Decode = %d, want 4", n)
	}
	in := toPCM(readFile(t, "signals.raw"))[:4000]
	first := make([]byte, 2000)
	e.Reset()
	e.Encode(first, in)
	again := make([]byte, 2000)
	e.Reset()
	e.Encode(again, in)
	if i := firstDiff(first, again); i >= 0 || firstDiff(first, encode(in)) >= 0 {
		t.Errorf("Reset does not restore the initial state (octet %d)", i)
	}
	a, b := make([]int16, 4000), make([]int16, 4000)
	d.Reset()
	d.Decode(a, first)
	d.Reset()
	d.Decode(b, first)
	if firstDiff(a, b) >= 0 || firstDiff(a, decode(first)) >= 0 {
		t.Error("decoder Reset does not restore the initial state")
	}
}

func benchPCM() []int16 { return synth(16000)[3].pcm[8000 : 8000+320] } // 20 ms of noise

func BenchmarkEncode20ms(b *testing.B) {
	pcm, out, e := benchPCM(), make([]byte, 160), NewEncoder()
	for b.Loop() {
		e.Encode(out, pcm)
	}
}

func BenchmarkDecode20ms(b *testing.B) {
	g, out, d := encode(benchPCM()), make([]int16, 320), NewDecoder()
	for b.Loop() {
		d.Decode(out, g)
	}
}
