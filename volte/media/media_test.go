package media

import (
	"bytes"
	"encoding/binary"
	"math"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRTPRoundTrip(t *testing.T) {
	p := Packet{Marker: true, PT: 101, Seq: 65535, Timestamp: 0xdeadbeef, SSRC: 42, Payload: []byte{1, 2, 3}}
	got, err := ParsePacket(p.Marshal())
	if err != nil || got.PT != 101 || !got.Marker || got.Seq != 65535 || got.Timestamp != 0xdeadbeef || !bytes.Equal(got.Payload, p.Payload) {
		t.Fatalf("%+v %v", got, err)
	}
	// CSRC count 1 + padding of 2 bytes.
	raw := append(p.Marshal(), 0, 2)
	raw[0] |= 0x21
	raw = append(raw[:12], append([]byte{9, 9, 9, 9}, raw[12:]...)...)
	if got, err := ParsePacket(raw); err != nil || !bytes.Equal(got.Payload, p.Payload) {
		t.Fatalf("csrc/padding: %+v %v", got, err)
	}
}

func randomFrame(ft uint8) Frame {
	b := make([]byte, FrameBytes(ft))
	for i := range b {
		b[i] = byte(rand.IntN(256))
	}
	if bits := amrwbBits[ft] % 8; bits != 0 && len(b) > 0 {
		b[len(b)-1] &= byte(0xff << (8 - bits))
	}
	return Frame{FT: ft, Good: true, Bits: b}
}

func TestAMRWBPayloadRoundTrip(t *testing.T) {
	for _, oa := range []bool{false, true} {
		for ft := uint8(0); ft <= FTSID; ft++ {
			frames := []Frame{randomFrame(ft), randomFrame(2), {FT: FTNoData, Good: true}}
			p, err := PackAMRWB(frames, 2, oa)
			if err != nil {
				t.Fatal(err)
			}
			got, cmr, err := UnpackAMRWB(p, oa)
			if err != nil || cmr != 2 || len(got) != 3 {
				t.Fatalf("oa=%v ft=%d: %v cmr=%d n=%d", oa, ft, err, cmr, len(got))
			}
			for i := range frames {
				if got[i].FT != frames[i].FT || !bytes.Equal(got[i].Bits, frames[i].Bits) {
					t.Fatalf("oa=%v ft=%d frame %d differs", oa, ft, i)
				}
			}
		}
	}
}

// RFC 4867 §4.3 sizes: one 12.65 kbit/s frame, bandwidth-efficient, is
// 4 + 6 + 253 bits = 33 bytes; octet-aligned is 1 + 1 + 32 = 34 bytes.
func TestAMRWBPayloadSizes(t *testing.T) {
	be, _ := PackAMRWB([]Frame{randomFrame(2)}, CMRNoPref, false)
	oa, _ := PackAMRWB([]Frame{randomFrame(2)}, CMRNoPref, true)
	if len(be) != 33 || len(oa) != 34 {
		t.Fatalf("BE %d bytes, OA %d bytes", len(be), len(oa))
	}
	if be[0]>>4 != CMRNoPref || oa[1] != 2<<3|0x04 {
		t.Fatalf("headers %08b %08b", be[0], oa[1])
	}
	if _, _, err := UnpackAMRWB(be[:20], false); err == nil {
		t.Fatal("truncated payload accepted")
	}
}

// Decoding must match ffmpeg's tables exactly. ffmpeg encodes to the nearest
// reconstruction level, which is not the G.711 decision rule at segment
// edges, so the encoder is checked against the rule itself: every input maps
// into the quantisation interval of its segment, and re-encoding a
// reconstruction level returns the same code.
func TestG711(t *testing.T) {
	load := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	adec, udec := load("alaw_dec.raw"), load("ulaw_dec.raw")
	for c := 0; c < 256; c++ {
		if got, want := ALawToLinear(byte(c)), int16(binary.LittleEndian.Uint16(adec[2*c:])); got != want {
			t.Fatalf("A-law decode %#x = %d, ffmpeg %d", c, got, want)
		}
		if got, want := ULawToLinear(byte(c)), int16(binary.LittleEndian.Uint16(udec[2*c:])); got != want {
			t.Fatalf("µ-law decode %#x = %d, ffmpeg %d", c, got, want)
		}
		if LinearToALaw(ALawToLinear(byte(c))) != byte(c) {
			t.Fatalf("A-law code %#x does not re-encode to itself", c)
		}
		if u := byte(c); u != 0x7f && LinearToULaw(ULawToLinear(u)) != u { // 0x7f and 0xff both decode to 0
			t.Fatalf("µ-law code %#x does not re-encode to itself", c)
		}
	}
	prevA, prevU := -1<<20, -1<<20
	for i := 0; i < 65536; i++ {
		s := int16(i - 32768)
		a, u := int(ALawToLinear(LinearToALaw(s))), int(ULawToLinear(LinearToULaw(s)))
		if a < prevA || u < prevU {
			t.Fatalf("not monotonic at %d", s)
		}
		prevA, prevU = a, u
		// Largest A-law step is 1024, µ-law 1024 (+ clipping above 32124).
		if d := a - int(s); d > 1024 || d < -1024 {
			t.Fatalf("A-law error %d at %d", d, s)
		}
		if d := u - int(s); (d > 1024 || d < -1024) && s < 32124 && s > -32124 {
			t.Fatalf("µ-law error %d at %d", d, s)
		}
	}
	for s, want := range map[int16]byte{0: 0xd5, 32767: 0xaa, -32768: 0x2a} {
		if got := LinearToALaw(s); got != want {
			t.Errorf("A-law(%d) = %#x, want %#x", s, got, want)
		}
	}
	for s, want := range map[int16]byte{0: 0xff, 32767: 0x80, -32768: 0x00} {
		if got := LinearToULaw(s); got != want {
			t.Errorf("µ-law(%d) = %#x, want %#x", s, got, want)
		}
	}
}

func TestDTMFDigits(t *testing.T) {
	for _, d := range "0123456789*#ABCD" {
		e, ok := DigitEvent(d)
		back, ok2 := EventDigit(e)
		if !ok || !ok2 || back != d {
			t.Fatalf("%q", d)
		}
	}
	e := DTMFEvent{Event: 11, End: true, Volume: 10, Duration: 1600}
	if got, _ := ParseDTMF(e.Marshal()); got != e {
		t.Fatalf("%+v", got)
	}
}

func tone(n, rate int, hz float64) []int16 {
	out := make([]int16, n)
	for i := range out {
		out[i] = int16(8000 * math.Sin(2*math.Pi*hz*float64(i)/float64(rate)))
	}
	return out
}

// Two streams on loopback exchange G.711 audio and a DTMF digit.
func TestStreamLoopback(t *testing.T) {
	lo := netip.MustParseAddrPort("127.0.0.1:0")
	ca, err := Listen(lo)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := Listen(lo)
	if err != nil {
		t.Fatal(err)
	}
	addr := func(c *net.UDPConn) netip.AddrPort { return c.LocalAddr().(*net.UDPAddr).AddrPort() }
	codec := func() Codec { c, _ := NewCodec(Params{Name: "PCMA"}); return c }
	audio := make(chan []int16, 64)
	digits := make(chan rune, 4)
	a, err := Start(ca, StreamConfig{Remote: addr(cb), PT: 8, Codec: codec(), DTMFPT: 101, DTMFHz: 8000})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Start(cb, StreamConfig{Remote: addr(ca), PT: 8, Codec: codec(), DTMFPT: 101, DTMFHz: 8000,
		OnAudio: func(p []int16) { audio <- p }, OnDTMF: func(d rune) { digits <- d }})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()

	pcm := tone(1600, 8000, 1000) // 200 ms
	if err := Play(a, pcm, nil); err != nil {
		t.Fatal(err)
	}
	var got []int16
	for len(got) < len(pcm) {
		select {
		case p := <-audio:
			got = append(got, p...)
		case <-time.After(2 * time.Second):
			t.Fatalf("received %d of %d samples", len(got), len(pcm))
		}
	}
	for i := range pcm {
		if d := int(pcm[i]) - int(got[i]); d > 300 || d < -300 {
			t.Fatalf("sample %d: sent %d, got %d", i, pcm[i], got[i])
		}
	}
	if err := a.SendDTMF('#', 100*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	select {
	case d := <-digits:
		if d != '#' {
			t.Fatalf("digit %q", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no DTMF")
	}
	select {
	case d := <-digits:
		t.Fatalf("digit %q reported twice", d)
	case <-time.After(100 * time.Millisecond):
	}
	if st := b.Stats(); st.Received != 10 || st.Lost != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestWAVRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.wav")
	w, err := CreateWAV(path, 16000)
	if err != nil {
		t.Fatal(err)
	}
	pcm := tone(1000, 16000, 440)
	_ = w.Write(pcm[:500])
	_ = w.Write(pcm[500:])
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	got, rate, err := ReadWAV(path)
	if err != nil || rate != 16000 || len(got) != 1000 || got[123] != pcm[123] {
		t.Fatalf("%d Hz, %d samples, %v", rate, len(got), err)
	}
	down, _ := Resample(pcm, 16000, 8000)
	up, _ := Resample(down, 8000, 16000)
	if len(down) != 500 || len(up) != 1000 {
		t.Fatal("resample lengths")
	}
}
