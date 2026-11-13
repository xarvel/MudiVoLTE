package main

// IMS leg of the bridge: RTP of the network call ↔ 16 kHz PCM in 20 ms
// frames. Network codecs come from volte/media: AMR-WB (when linked in,
// cgo) and G.711 A/μ; 8 kHz formats go through the resampler.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/xarvel/MudiVoLTE/volte/media"
)

type imsLeg struct {
	call   imsMedia
	media  NetMedia
	codec  media.Codec
	wide   bool // 16 kHz without resampling
	logger *slog.Logger

	up *resampler

	wmu    sync.Mutex
	closed bool
	down   *resampler
	seq    uint16
	ts     uint32
	tsStep uint32

	frames, bad uint32
}

func newIMSLeg(call imsMedia, logger *slog.Logger) (*imsLeg, error) {
	l := &imsLeg{call: call, logger: logger}
	if err := l.syncMedia(); err != nil {
		return nil, err
	}
	return l, nil
}

// syncMedia follows accepted re-INVITEs/UPDATEs. Both directions hold wmu
// while using the codec, so replacing (and closing) it cannot race decoding.
func (l *imsLeg) syncMedia() error {
	if l.closed {
		return errors.New("network leg closed")
	}
	m := l.call.Media()
	if !m.Negotiated {
		return errors.New("network media not negotiated")
	}
	if m == l.media && l.codec != nil {
		return nil
	}
	fmtp := ""
	if m.ModeSet != "" {
		fmtp = "mode-set=" + m.ModeSet
	}
	if m.OctetAlign {
		fmtp += ";octet-align=1"
	}
	codec, err := media.NewCodec(media.Params{Name: m.Codec, ClockRate: m.ClockRate, Fmtp: fmtp})
	if err != nil {
		return fmt.Errorf("network codec %q: %w", m.Codec, err)
	}
	if l.media.ClockRate > 0 && m.ClockRate != l.media.ClockRate {
		l.ts = uint32(uint64(l.ts) * uint64(m.ClockRate) / uint64(l.media.ClockRate))
	}
	if l.codec != nil {
		media.Close(l.codec)
	}
	l.media, l.codec = m, codec
	l.wide, l.up, l.down = false, nil, nil
	if codec.SampleRate() == 16000 {
		l.wide, l.tsStep = true, frameSamples16k
	} else {
		l.tsStep = frameSamples8k
		l.up, l.down = newUpsampler(), newDownsampler()
	}
	return nil
}

func (l *imsLeg) describe() string {
	l.wmu.Lock()
	defer l.wmu.Unlock()
	return fmt.Sprintf("%s pt=%d mode_set=%q octet_align=%v", l.media.Codec, l.media.PayloadType, l.media.ModeSet, l.media.OctetAlign)
}

// Run receives from the network. Read errors do not end the leg: the bridge
// learns about the end of the call from a network event and cancels ctx.
func (l *imsLeg) Run(ctx context.Context, sink func([]int16)) error {
	defer func() {
		l.wmu.Lock()
		defer l.wmu.Unlock()
		l.closed = true
		media.Close(l.codec)
	}()
	for {
		pkt, _, err := l.call.ReadPacket(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(20 * time.Millisecond):
			}
			continue
		}
		p, err := media.ParsePacket(pkt)
		if err != nil {
			continue
		}
		l.wmu.Lock()
		if err := l.syncMedia(); err != nil || int(p.PT) != l.media.PayloadType {
			l.wmu.Unlock()
			continue // garbage or telephone-event
		}
		frames := l.decode(p.Payload)
		l.wmu.Unlock()
		for _, pcm := range frames {
			sink(pcm)
		}
	}
}

func (l *imsLeg) decode(payload []byte) [][]int16 {
	pcm, err := l.codec.Decode(payload)
	if err != nil {
		l.bad++
		return nil
	}
	if !l.wide {
		pcm = l.up.up(pcm)
	}
	var out [][]int16
	for off := 0; off+frameSamples16k <= len(pcm); off += frameSamples16k {
		out = append(out, pcm[off:off+frameSamples16k])
		l.frames++
	}
	return out
}

// WriteFrame sends a 20 ms frame (320 samples at 16 kHz) to the network.
func (l *imsLeg) WriteFrame(ctx context.Context, pcm []int16) error {
	l.wmu.Lock()
	if err := l.syncMedia(); err != nil {
		l.wmu.Unlock()
		return err
	}
	in := pcm
	if !l.wide {
		in = l.down.down(pcm)
	}
	payload, err := l.codec.Encode(in)
	if err != nil {
		l.wmu.Unlock()
		return err
	}
	rtp := make([]byte, 12, 12+len(payload))
	rtp[0] = 0x80
	rtp[1] = byte(l.media.PayloadType)
	binary.BigEndian.PutUint16(rtp[2:], l.seq)
	binary.BigEndian.PutUint32(rtp[4:], l.ts)
	l.seq++
	l.ts += l.tsStep
	l.wmu.Unlock()
	// The transport rewrites SSRC and seq; write errors (end of call) are not fatal.
	_ = l.call.WriteRTP(ctx, append(rtp, payload...))
	return nil
}
