package media

import (
	"fmt"
	"strconv"
	"strings"
)

// Codec turns one packet's worth of PCM (mono s16 at SampleRate) into an RTP
// payload and back.
type Codec interface {
	Name() string
	SampleRate() int // also the RTP clock rate for our codecs
	Encode(pcm []int16) ([]byte, error)
	Decode(payload []byte) ([]int16, error)
}

// FrameCoder is an AMR-WB speech codec working on storage-format frames
// (RFC 4867 §5.3), e.g. opencore-amrwb + vo-amrwbenc via cgo.
type FrameCoder interface {
	EncodeFrame(pcm []int16, mode int) ([]byte, error) // 320 samples → storage frame
	DecodeFrame(storage []byte) ([]int16, error)       // storage frame → 320 samples
	Close()
}

// NewAMRWBCoder is set by a codec implementation package (see media/amrwb).
var NewAMRWBCoder func() (FrameCoder, error)

// Params selects the codec for a negotiated stream.
type Params struct {
	Name      string // AMR-WB, PCMA, PCMU
	ClockRate int
	Fmtp      string
	Ptime     int // ms; 0 → 20
}

func (p Params) fmtp(name string) (string, bool) {
	for _, kv := range strings.Split(p.Fmtp, ";") {
		k, v, _ := strings.Cut(strings.TrimSpace(kv), "=")
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return "", false
}

// NewCodec builds the codec for p.
func NewCodec(p Params) (Codec, error) {
	ptime := p.Ptime
	if ptime == 0 {
		ptime = 20
	}
	switch strings.ToUpper(p.Name) {
	case "PCMA":
		return &g711{alaw: true, samples: 8 * ptime}, nil
	case "PCMU":
		return &g711{samples: 8 * ptime}, nil
	case "AMR-WB":
		if NewAMRWBCoder == nil {
			return nil, fmt.Errorf("AMR-WB codec not linked in (import github.com/xarvel/MudiVoLTE/volte/media/amrwb)")
		}
		fc, err := NewAMRWBCoder()
		if err != nil {
			return nil, err
		}
		c := &amrwbCodec{fc: fc, frames: ptime / 20, mode: 8}
		if v, ok := p.fmtp("octet-align"); ok && v == "1" {
			c.octetAligned = true
		}
		// Send in the highest mode the peer allows (RFC 4867 §8.1 mode-set).
		if v, ok := p.fmtp("mode-set"); ok {
			best := -1
			for _, m := range strings.Split(v, ",") {
				if n, err := strconv.Atoi(strings.TrimSpace(m)); err == nil && n >= 0 && n <= 8 && n > best {
					best = n
				}
			}
			if best >= 0 {
				c.mode = best
			}
		}
		if c.frames < 1 {
			c.frames = 1
		}
		return c, nil
	}
	return nil, fmt.Errorf("unsupported codec %q", p.Name)
}

type g711 struct {
	alaw    bool
	samples int
}

func (g *g711) Name() string {
	if g.alaw {
		return "PCMA"
	}
	return "PCMU"
}

func (g *g711) SampleRate() int { return 8000 }

func (g *g711) Encode(pcm []int16) ([]byte, error) {
	out := make([]byte, len(pcm))
	for i, s := range pcm {
		if g.alaw {
			out[i] = LinearToALaw(s)
		} else {
			out[i] = LinearToULaw(s)
		}
	}
	return out, nil
}

func (g *g711) Decode(p []byte) ([]int16, error) {
	out := make([]int16, len(p))
	for i, b := range p {
		if g.alaw {
			out[i] = ALawToLinear(b)
		} else {
			out[i] = ULawToLinear(b)
		}
	}
	return out, nil
}

type amrwbCodec struct {
	fc           FrameCoder
	frames       int
	mode         int
	octetAligned bool
}

func (c *amrwbCodec) Name() string    { return "AMR-WB" }
func (c *amrwbCodec) SampleRate() int { return 16000 }

func (c *amrwbCodec) Encode(pcm []int16) ([]byte, error) {
	if len(pcm) != 320*c.frames {
		return nil, fmt.Errorf("AMR-WB needs %d samples, got %d", 320*c.frames, len(pcm))
	}
	frames := make([]Frame, c.frames)
	for i := range frames {
		st, err := c.fc.EncodeFrame(pcm[i*320:(i+1)*320], c.mode)
		if err != nil {
			return nil, err
		}
		if frames[i], err = FrameFromStorage(st); err != nil {
			return nil, err
		}
	}
	return PackAMRWB(frames, CMRNoPref, c.octetAligned)
}

func (c *amrwbCodec) Decode(p []byte) ([]int16, error) {
	frames, _, err := UnpackAMRWB(p, c.octetAligned)
	if err != nil {
		return nil, err
	}
	var out []int16
	for _, f := range frames {
		if f.FT == FTNoData {
			// Nothing transmitted: let the decoder conceal (DTX/comfort noise).
			f = Frame{FT: FTNoData}
		}
		pcm, err := c.fc.DecodeFrame(f.StorageFrame())
		if err != nil {
			return nil, err
		}
		out = append(out, pcm...)
	}
	return out, nil
}

// Close releases codec state.
func Close(c Codec) {
	if a, ok := c.(*amrwbCodec); ok {
		a.fc.Close()
	}
}
