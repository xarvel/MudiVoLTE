package g722

import (
	"bytes"
	"flag"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// These tests use ffmpeg as a black-box reference and skip without it.

var update = flag.Bool("update", false, "rewrite testdata from ffmpeg")

func ffmpeg(t testing.TB, in []byte, args ...string) []byte {
	t.Helper()
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("ffmpeg not in PATH")
	}
	cmd := exec.Command("ffmpeg", append([]string{"-hide_banner", "-loglevel", "error"}, args...)...)
	cmd.Stdin = bytes.NewReader(in)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("ffmpeg %q: %v\n%s", args, err, stderr.Bytes())
	}
	return out.Bytes()
}

func ffEncode(t testing.TB, pcm []int16) []byte {
	return ffmpeg(t, fromPCM(pcm), "-f", "s16le", "-ar", "16000", "-ac", "1", "-i", "pipe:0",
		"-c:a", "g722", "-f", "g722", "pipe:1")
}

func ffDecode(t testing.TB, g []byte) []int16 {
	return toPCM(ffmpeg(t, g, "-f", "g722", "-i", "pipe:0", "-f", "s16le", "-ac", "1", "pipe:1"))
}

// snr returns the SNR of out against in in dB, at the codec delay (22
// samples) or whichever nearby delay maximizes it.
func snr(in, out []int16) (db float64, delay int) {
	db = math.Inf(-1)
	for d := range 32 {
		var s, e float64
		for i := range len(in) - d {
			x, y := float64(in[i]), float64(out[i+d])
			s += x * x
			e += (x - y) * (x - y)
		}
		v := 10 * math.Log10(s/e)
		if e == 0 {
			v = math.Inf(1)
		}
		if v > db {
			db, delay = v, d
		}
	}
	return db, delay
}

// speech returns the recordings in the project's research directory as
// 16 kHz mono PCM.
func speech(t *testing.T) []signal {
	var files []string
	for _, pat := range []string{"../../../research/s3-live/*.wav", "../../../research/*.wav"} {
		m, _ := filepath.Glob(pat)
		files = append(files, m...)
	}
	if f := os.Getenv("G722_SPEECH"); f != "" {
		files = append(files, f)
	}
	var out []signal
	for _, f := range files {
		raw := ffmpeg(t, nil, "-i", f, "-f", "s16le", "-ar", "16000", "-ac", "1", "pipe:1")
		out = append(out, signal{filepath.Base(f), toPCM(raw)})
	}
	return out
}

// Our stream equals ffmpeg's octet for octet, and ffmpeg's decoder agrees
// with ours on it sample for sample.
func TestFFmpegEncoder(t *testing.T) {
	sigs := append(synth(32000), speech(t)...)
	for _, s := range sigs {
		got := encode(s.pcm)
		want := ffEncode(t, s.pcm)
		if i := firstDiff(got, want); i >= 0 {
			t.Errorf("%s: octet %d of %d is %#02x, ffmpeg %#02x", s.name, i, len(want), got[i], want[i])
			continue
		}
		ff, ours := ffDecode(t, got), decode(got)
		if i := firstDiff(ours, ff); i >= 0 {
			t.Errorf("%s: decoded sample %d is %d, ffmpeg %d", s.name, i, ours[i], ff[i])
			continue
		}
		if db, delay := snr(s.pcm, ours); !math.IsInf(db, -1) {
			t.Logf("%-28s %6d octets identical, SNR %5.2f dB (delay %d)", s.name, len(got), db, delay)
		} else {
			peak := 0
			for _, v := range ours {
				peak = max(peak, int(v), -int(v))
			}
			t.Logf("%-28s %6d octets identical, output peak %d", s.name, len(got), peak)
		}
	}
}

// The decoder agrees with ffmpeg's on arbitrary streams: random octets,
// long runs of every octet value, extreme codewords only. The one exception
// is FILTEZ overflow, checked separately.
func TestFFmpegDecoder(t *testing.T) {
	var runs []byte
	for c := range 256 {
		runs = append(runs, bytes.Repeat([]byte{byte(c)}, 300)...)
	}
	var extreme []byte // largest magnitudes, both signs, both sub-bands
	for i, c := range randomStream(50000) {
		extreme = append(extreme, []byte{0x04, 0x05, 0x20, 0x21, 0x84, 0x85, 0xa0, 0xa1}[c%8]^byte(i&2))
	}
	for _, s := range []struct {
		name string
		g    []byte
	}{{"random", randomStream(200000)}, {"runs", runs}, {"extreme", extreme}} {
		got, want := decode(s.g), ffDecode(t, s.g)
		if i := firstDiff(got, want); i >= 0 {
			t.Errorf("%s: sample %d is %d, ffmpeg %d", s.name, i, got[i], want[i])
		}
	}
}

// Long runs of the extreme codewords push FILTEZ into saturation; ffmpeg
// then follows a wide-accumulator sum (see checkFILTEZDeviation).
func TestFFmpegFILTEZ(t *testing.T) {
	rng := randomStream(4000)
	var g []byte
	for i := 0; i+1 < len(rng) && len(g) < 40000; i += 2 {
		c := []byte{0x20, 0x04, 0xa0, 0x84, 0x00, 0x80, 0xc4, 0xe0}[rng[i]%8]
		g = append(g, bytes.Repeat([]byte{c}, 1+int(rng[i+1])%80)...)
	}
	checkFILTEZDeviation(t, "runs", g, ffDecode(t, g))
	checkFILTEZDeviation(t, "filtez", filtezStream(), ffDecode(t, filtezStream()))
}

// The stored outputs are what ffmpeg makes of the stored inputs. -update
// regenerates the inputs too (signals.raw comes from floating-point math and
// may differ in the last bit on another machine).
func TestTestdata(t *testing.T) {
	inputs := map[string][]byte{"random.g722": randomStream(2000), "filtez.g722": filtezStream()}
	var in []int16
	for _, s := range synth(1000) {
		in = append(in, s.pcm...)
	}
	inputs["signals.raw"] = fromPCM(in)
	for name, b := range inputs {
		if *update {
			writeTestdata(t, name, b)
		} else if name != "signals.raw" && !bytes.Equal(readFile(t, name), b) {
			t.Errorf("testdata/%s is not what the generator makes", name)
		}
	}
	encoded := ffEncode(t, toPCM(readFile(t, "signals.raw")))
	outputs := map[string][]byte{
		"signals.g722":    encoded,
		"signals.dec.raw": fromPCM(ffDecode(t, encoded)),
		"random.dec.raw":  fromPCM(ffDecode(t, readFile(t, "random.g722"))),
		"filtez.dec.raw":  fromPCM(ffDecode(t, readFile(t, "filtez.g722"))),
	}
	for name, b := range outputs {
		if *update {
			writeTestdata(t, name, b)
		} else if !bytes.Equal(readFile(t, name), b) {
			t.Errorf("testdata/%s is not what ffmpeg makes of its input", name)
		}
	}
}

func writeTestdata(t *testing.T, name string, b []byte) {
	if err := os.WriteFile(filepath.Join("testdata", name), b, 0o644); err != nil {
		t.Fatal(err)
	}
}
