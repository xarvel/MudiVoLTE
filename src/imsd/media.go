package main

// S4: call media without a bridge to the phones: recording what the other
// party says to WAV and playing a WAV file to them. Encoding and RTP go
// through imsLeg, as in the bridge.

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/xarvel/MudiVoLTE/volte/media"
)

// recordAndPlay starts both media goroutines of a call. An empty recordDir
// turns recording off; an empty playFile means silence. The goroutines live
// until the call ends (ReadPacket/WriteRTP start returning errors), not until
// the handler returns (pitfall §81).
func recordAndPlay(call imsCall, cfg *Config, logger *slog.Logger, fromMasked string) {
	m := call.Media()
	if !m.Negotiated {
		logger.Warn("media not negotiated, no audio")
		return
	}
	logger.Info("media negotiated", "codec", fmt.Sprintf("%s/%d", m.Codec, m.ClockRate),
		"pt", m.PayloadType, "octet_align", m.OctetAlign, "mode_set", m.ModeSet)
	if cfg.RecordDir != "" {
		leg, err := newIMSLeg(call, logger)
		if err != nil {
			logger.Error("recording: network leg", "err", err)
		} else {
			go recordDownlink(leg, cfg, logger)
		}
	}
	if cfg.PlayFile != "" {
		leg, err := newIMSLeg(call, logger)
		if err != nil {
			logger.Error("playback: network leg", "err", err)
		} else {
			go playUplink(call, leg, cfg, logger)
		}
	}
}

func recordDownlink(leg *imsLeg, cfg *Config, logger *slog.Logger) {
	path := filepath.Join(cfg.RecordDir, fmt.Sprintf("call-%s.wav", time.Now().Format("20060102-150405")))
	if err := os.MkdirAll(cfg.RecordDir, 0o755); err != nil {
		logger.Error("WAV: directory", "err", err)
		return
	}
	wav, err := media.CreateWAV(path, 16000)
	if err != nil {
		logger.Error("WAV not created", "err", err)
		return
	}
	var frames int
	// Run returns once the call is over (ReadPacket returns the termination
	// error, but ctx is a background one, so we leave via the call's done channel).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-callDone(leg.call)
		cancel()
	}()
	_ = leg.Run(ctx, func(pcm []int16) {
		if wav.Write(pcm) == nil {
			frames++
		}
	})
	if err := wav.Close(); err != nil {
		logger.Error("WAV close", "err", err)
	}
	logger.Info("recording finished", "path", path, "frames", frames, "bad", leg.bad,
		"dur", fmt.Sprintf("%.1fs", float64(frames)*0.02))
}

func playUplink(call imsCall, leg *imsLeg, cfg *Config, logger *slog.Logger) {
	pcm, rate, err := media.ReadWAV(cfg.PlayFile)
	if err != nil {
		logger.Error("play: file", "err", err)
		return
	}
	if pcm, err = media.Resample(pcm, rate, 16000); err != nil {
		logger.Error("play: an 8 or 16 kHz WAV is needed", "err", err)
		return
	}
	logger.Info("play: file loaded", "samples", len(pcm), "dur", fmt.Sprintf("%.1fs", float64(len(pcm))/16000))
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	ctx := context.Background()
	for off := 0; off+frameSamples16k <= len(pcm); off += frameSamples16k {
		<-t.C
		select {
		case <-callDone(call):
			return
		default:
		}
		if err := leg.WriteFrame(ctx, pcm[off:off+frameSamples16k]); err != nil {
			return
		}
	}
	logger.Info("play: file played to the end")
}

// callDone returns the end-of-call channel when the implementation provides
// one (netCall); otherwise nil, which waits forever, and the end is learned
// from transport errors.
func callDone(c any) <-chan struct{} {
	if d, ok := c.(interface{ Done() <-chan struct{} }); ok {
		return d.Done()
	}
	return nil
}
