package main

// Audio bridge between two legs (phone in the LAN ↔ network call). Inside,
// the audio is 16 kHz PCM in 20 ms frames. The output of each side is clocked
// by its own 20 ms ticker from a jitter queue: packets arrive unevenly, but an
// even stream of 50 packets/s goes out. When the queue is empty, the last
// frame is repeated with fading (loss concealment), then silence.

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/xarvel/MudiVoLTE/volte/media"
)

type audioLeg interface {
	Run(ctx context.Context, sink func([]int16)) error
	WriteFrame(ctx context.Context, pcm []int16) error
}

const (
	jitterMaxFrames = 8 // 160 ms: beyond that the oldest frames are dropped so as not to build up delay
	plcFrames       = 3 // this many frames of loss concealment, then silence
)

type frameQueue struct {
	mu       sync.Mutex
	frames   [][]int16
	prebuf   int
	max      int // queue limit: at least the prebuffer, or the prebuffer never fills
	primed   bool
	last     []int16
	misses   int
	received uint64
	dropped  uint64
}

func newFrameQueue(prebuf int) *frameQueue {
	if prebuf < 1 {
		prebuf = 1
	}
	return &frameQueue{prebuf: prebuf, max: max(jitterMaxFrames, prebuf+4)}
}

func (q *frameQueue) push(f []int16) {
	c := make([]int16, len(f))
	copy(c, f)
	q.mu.Lock()
	defer q.mu.Unlock()
	q.received++
	q.frames = append(q.frames, c)
	if len(q.frames) > q.max {
		q.frames = q.frames[len(q.frames)-q.max:]
		q.dropped++
	}
	if !q.primed && len(q.frames) >= q.prebuf {
		q.primed = true
	}
}

// pop returns the next frame to send (never nil).
func (q *frameQueue) pop() []int16 {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.primed && len(q.frames) > 0 {
		f := q.frames[0]
		q.frames = q.frames[1:]
		q.last, q.misses = f, 0
		return f
	}
	q.misses++
	if q.misses > plcFrames*4 {
		q.primed = false // long gap: fill the prebuffer again
	}
	out := make([]int16, frameSamples16k)
	if q.last != nil && q.misses <= plcFrames {
		gain := 1.0 / float64(int(1)<<q.misses) // 1/2, 1/4, 1/8
		for i, s := range q.last {
			out[i] = int16(float64(s) * gain)
		}
	}
	return out
}

// pump moves frames from the queue to leg dst every 20 ms until ctx is done.
func pump(ctx context.Context, q *frameQueue, dst audioLeg) {
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := dst.WriteFrame(ctx, q.pop()); err != nil && ctx.Err() == nil {
				return
			}
		}
	}
}

// runBridge runs a two-way bridge a↔b until ctx is cancelled.
func runBridge(ctx context.Context, a, b audioLeg, prebuf int, logger *slog.Logger) {
	qa, qb := newFrameQueue(prebuf), newFrameQueue(prebuf)
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); _ = a.Run(ctx, qa.push) }()
	go func() { defer wg.Done(); _ = b.Run(ctx, qb.push) }()
	go func() { defer wg.Done(); pump(ctx, qa, b) }()
	go func() { defer wg.Done(); pump(ctx, qb, a) }()
	wg.Wait()
	logger.Info("bridge: audio stopped",
		"a_frames", qa.received, "a_dropped", qa.dropped,
		"b_frames", qb.received, "b_dropped", qb.dropped)
}

// runEcho is an echo test for the phone: the voice comes back through
// AMR-WB 12.65 (as the other party in the network would hear it) when the
// codec is linked in, with a delay of ~200 ms; without AMR-WB it comes back
// as it is.
func runEcho(ctx context.Context, leg audioLeg, logger *slog.Logger) {
	q := newFrameQueue(10)
	codec, err := media.NewCodec(media.Params{Name: "AMR-WB", Fmtp: "mode-set=2"})
	if err != nil {
		logger.Info("echo: no AMR-WB, the voice comes back as it is", "err", err)
		codec = nil
	} else {
		defer media.Close(codec)
	}
	go func() { _ = leg.Run(ctx, q.push) }()
	t := time.NewTicker(20 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			logger.Info("echo: stopped", "frames", q.received)
			return
		case <-t.C:
			f := q.pop()
			if codec != nil {
				if p, err := codec.Encode(f); err == nil {
					if pcm, err := codec.Decode(p); err == nil && len(pcm) >= frameSamples16k {
						f = pcm[:frameSamples16k]
					}
				}
			}
			_ = leg.WriteFrame(ctx, f)
		}
	}
}
