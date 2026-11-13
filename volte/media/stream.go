package media

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// StreamConfig describes one negotiated audio stream.
type StreamConfig struct {
	Remote  netip.AddrPort
	PT      uint8
	Codec   Codec
	DTMFPT  uint8 // 0 = no telephone-event
	DTMFHz  int   // telephone-event clock rate
	Ptime   int   // ms; 0 → 20
	OnAudio func(pcm []int16)
	OnDTMF  func(digit rune)
	// Latch sends to the source of the first received packet when it differs
	// from Remote (symmetric RTP behind address translation).
	Latch bool
}

// Stats counts traffic.
type Stats struct {
	Sent, Received, Lost, Undecodable uint64
}

// Stream is one RTP session on a local UDP port.
type Stream struct {
	conn *net.UDPConn
	cfg  StreamConfig

	mu       sync.Mutex
	remote   netip.AddrPort
	ssrc     uint32
	seq      uint16
	ts       uint32
	started  bool
	lastSeq  uint16
	haveSeq  bool
	dtmfTS   uint32
	dtmfSeen bool

	sent, recv, lost, bad atomic.Uint64
	done                  chan struct{}
}

func rnd32() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// Listen binds the local RTP port (port 0 picks an even free port is not
// guaranteed; pass an explicit even port when RTCP pairing matters).
func Listen(local netip.AddrPort) (*net.UDPConn, error) {
	return net.ListenUDP("udp", net.UDPAddrFromAddrPort(local))
}

// Start runs the stream on an already bound socket.
func Start(conn *net.UDPConn, cfg StreamConfig) (*Stream, error) {
	if cfg.Codec == nil {
		return nil, errors.New("no codec")
	}
	if cfg.Ptime == 0 {
		cfg.Ptime = 20
	}
	s := &Stream{conn: conn, cfg: cfg, remote: cfg.Remote, ssrc: rnd32(), seq: uint16(rnd32()), ts: rnd32(), done: make(chan struct{})}
	go s.readLoop()
	return s, nil
}

// LocalAddr is the bound RTP address.
func (s *Stream) LocalAddr() netip.AddrPort { return s.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

// SamplesPerPacket is how many PCM samples Send expects.
func (s *Stream) SamplesPerPacket() int { return s.cfg.Codec.SampleRate() * s.cfg.Ptime / 1000 }

// Send encodes one packet of PCM and transmits it.
func (s *Stream) Send(pcm []int16) error {
	payload, err := s.cfg.Codec.Encode(pcm)
	if err != nil {
		return err
	}
	s.mu.Lock()
	p := Packet{PT: s.cfg.PT, Seq: s.seq, Timestamp: s.ts, SSRC: s.ssrc, Payload: payload, Marker: !s.started}
	s.started = true
	s.seq++
	s.ts += uint32(len(pcm))
	remote := s.remote
	s.mu.Unlock()
	if _, err := s.conn.WriteToUDPAddrPort(p.Marshal(), remote); err != nil {
		return err
	}
	s.sent.Add(1)
	return nil
}

// SendDTMF sends one digit as RFC 4733 events: updates every ptime, then
// three end packets, all with the event's start timestamp.
func (s *Stream) SendDTMF(digit rune, d time.Duration) error {
	if s.cfg.DTMFPT == 0 {
		return errors.New("telephone-event not negotiated")
	}
	ev, ok := DigitEvent(digit)
	if !ok {
		return fmt.Errorf("not a DTMF digit: %q", digit)
	}
	hz := s.cfg.DTMFHz
	if hz == 0 {
		hz = 8000
	}
	step := time.Duration(s.cfg.Ptime) * time.Millisecond
	s.mu.Lock()
	start := s.ts
	s.mu.Unlock()
	send := func(e DTMFEvent, marker bool) error {
		s.mu.Lock()
		p := Packet{PT: s.cfg.DTMFPT, Seq: s.seq, Timestamp: start, SSRC: s.ssrc, Payload: e.Marshal(), Marker: marker}
		s.seq++
		remote := s.remote
		s.mu.Unlock()
		_, err := s.conn.WriteToUDPAddrPort(p.Marshal(), remote)
		return err
	}
	units := func(t time.Duration) uint16 { return uint16(int64(t) * int64(hz) / int64(time.Second)) }
	for t := step; t < d; t += step {
		if err := send(DTMFEvent{Event: ev, Volume: 10, Duration: units(t)}, t == step); err != nil {
			return err
		}
		time.Sleep(step)
	}
	for i := 0; i < 3; i++ {
		if err := send(DTMFEvent{Event: ev, End: true, Volume: 10, Duration: units(d)}, false); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.ts += uint32(units(d))
	s.mu.Unlock()
	return nil
}

func (s *Stream) readLoop() {
	defer close(s.done)
	buf := make([]byte, 1500)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		p, err := ParsePacket(buf[:n])
		if err != nil {
			continue
		}
		s.mu.Lock()
		if s.cfg.Latch && from != s.remote {
			s.remote = from
		}
		s.mu.Unlock()
		switch {
		case p.PT == s.cfg.PT:
			s.onAudio(p)
		case s.cfg.DTMFPT != 0 && p.PT == s.cfg.DTMFPT:
			s.onDTMF(p)
		}
	}
}

func (s *Stream) onAudio(p Packet) {
	s.recv.Add(1)
	s.mu.Lock()
	if s.haveSeq {
		if gap := p.Seq - s.lastSeq; gap > 1 && gap < 1000 {
			s.lost.Add(uint64(gap - 1))
		}
	}
	s.lastSeq, s.haveSeq = p.Seq, true
	s.mu.Unlock()
	pcm, err := s.cfg.Codec.Decode(p.Payload)
	if err != nil {
		s.bad.Add(1)
		return
	}
	if s.cfg.OnAudio != nil {
		s.cfg.OnAudio(pcm)
	}
}

// onDTMF reports a digit once, on the first end packet of an event.
func (s *Stream) onDTMF(p Packet) {
	e, err := ParseDTMF(p.Payload)
	if err != nil || !e.End {
		return
	}
	s.mu.Lock()
	dup := s.dtmfSeen && s.dtmfTS == p.Timestamp
	s.dtmfTS, s.dtmfSeen = p.Timestamp, true
	s.mu.Unlock()
	if dup {
		return
	}
	if d, ok := EventDigit(e.Event); ok && s.cfg.OnDTMF != nil {
		s.cfg.OnDTMF(d)
	}
}

// Stats returns counters so far.
func (s *Stream) Stats() Stats {
	return Stats{Sent: s.sent.Load(), Received: s.recv.Load(), Lost: s.lost.Load(), Undecodable: s.bad.Load()}
}

// Close stops the stream and releases the socket and codec.
func (s *Stream) Close() error {
	err := s.conn.Close()
	<-s.done
	Close(s.cfg.Codec)
	return err
}
