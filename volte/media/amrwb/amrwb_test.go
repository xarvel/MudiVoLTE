//go:build cgo

package amrwb

import (
	"math"
	"testing"

	"github.com/xarvel/MudiVoLTE/volte/media"
)

// goertzel returns the power of freq in pcm.
func goertzel(pcm []int16, rate int, freq float64) float64 {
	k := 2 * math.Cos(2*math.Pi*freq/float64(rate))
	var s1, s2 float64
	for _, x := range pcm {
		s := float64(x) + k*s1 - s2
		s2, s1 = s1, s
	}
	return s1*s1 + s2*s2 - k*s1*s2
}

// A 1 kHz tone survives encode → RFC 4867 packing → decode at every mode the
// live offer allows, in both payload formats.
func TestCodecThroughPayload(t *testing.T) {
	for _, fmtp := range []string{"mode-set=0,1,2", "mode-set=2;octet-align=1", ""} {
		enc, err := media.NewCodec(media.Params{Name: "AMR-WB", Fmtp: fmtp})
		if err != nil {
			t.Fatal(err)
		}
		dec, _ := media.NewCodec(media.Params{Name: "AMR-WB", Fmtp: fmtp})
		var out []int16
		for f := 0; f < 50; f++ {
			pcm := make([]int16, 320)
			for i := range pcm {
				pcm[i] = int16(6000 * math.Sin(2*math.Pi*1000*float64(f*320+i)/16000))
			}
			payload, err := enc.Encode(pcm)
			if err != nil {
				t.Fatal(err)
			}
			got, err := dec.Decode(payload)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, got...)
		}
		tail := out[len(out)/2:]
		p1k, p3k := goertzel(tail, 16000, 1000), goertzel(tail, 16000, 3000)
		if p1k < 100*p3k {
			t.Errorf("fmtp %q: 1 kHz not dominant (%.3g vs %.3g)", fmtp, p1k, p3k)
		}
		media.Close(enc)
		media.Close(dec)
	}
}
