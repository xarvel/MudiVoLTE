package main

// RTP leg of a phone in the LAN: a UDP socket from the rtp_port_min..max
// range, codec G.722/PCMU/PCMA, DTMF per RFC 4733, and SRTP when the call was
// set up over TLS (lan_srtp.go). Packets are accepted only from the phone's IP
// in the SDP; the port follows the first packet that passes (symmetric RTP).

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/xarvel/MudiVoLTE/volte/media"
	"github.com/xarvel/MudiVoLTE/volte/srtp"
)

// portAlloc hands out even RTP ports (the odd one after each is for RTCP).
type portAlloc struct {
	ip       net.IP
	min, max int
	mu       sync.Mutex
	next     int
}

func newPortAlloc(ip net.IP, min, max int) *portAlloc {
	if min%2 != 0 {
		min++
	}
	return &portAlloc{ip: ip, min: min, max: max, next: min}
}

func (p *portAlloc) open(logger *slog.Logger) (*rtpLeg, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	span := (p.max - p.min) / 2
	for range span + 1 {
		port := p.next
		p.next += 2
		if p.next+1 > p.max {
			p.next = p.min
		}
		rtp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: p.ip, Port: port})
		if err != nil {
			continue
		}
		rtcp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: p.ip, Port: port + 1})
		if err != nil {
			rtp.Close()
			continue
		}
		var ssrc [4]byte
		_, _ = rand.Read(ssrc[:])
		leg := &rtpLeg{conn: rtp, rtcp: rtcp, port: port, ssrc: binary.BigEndian.Uint32(ssrc[:]), logger: logger}
		go leg.drainRTCP()
		return leg, nil
	}
	return nil, fmt.Errorf("RTP: no free ports in %d..%d", p.min, p.max)
}

type rtpLeg struct {
	conn, rtcp *net.UDPConn
	port       int
	ssrc       uint32
	logger     *slog.Logger

	mu       sync.Mutex
	remote   *net.UDPAddr
	codec    lanCodec
	dtmfPT   int
	seq      uint16
	ts       uint32
	started  bool
	onDTMF   func(digit byte)
	dtmfTS   uint32
	dtmfSeen bool
	lastRX   time.Time // last well-formed RTP from this phone (after SRTP authentication)

	// SRTP: nil contexts mean plain RTP. local is our key (we send with it),
	// remote the phone's (it sends with it); profile is the m= profile of the
	// leg's SDP. fails counts packets that failed the SRTP check.
	tx, rx    *srtp.Context
	localKey  srtp.Crypto
	remoteKey srtp.Crypto
	profile   string
	fails     int

	closeOnce sync.Once
}

func (l *rtpLeg) Port() int { return l.port }

func (l *rtpLeg) setRemote(ip net.IP, port int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.remote = &net.UDPAddr{IP: ip, Port: port}
}

// resetStream starts a new stretch of the stream (after a re-INVITE,
// hold/resume): the next packet goes out with the marker bit, as RFC 3550
// §5.3 requires for a break in the stream.
func (l *rtpLeg) resetStream() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.started = false
}

func (l *rtpLeg) setCodec(c lanCodec, dtmfPT int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.codec, l.dtmfPT = c, dtmfPT
}

func (l *rtpLeg) setDTMFHandler(f func(digit byte)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onDTMF = f
}

func (l *rtpLeg) Close() {
	l.closeOnce.Do(func() {
		l.conn.Close()
		l.rtcp.Close()
	})
}

func (l *rtpLeg) drainRTCP() {
	buf := make([]byte, 1500)
	for {
		if _, _, err := l.rtcp.ReadFromUDP(buf); err != nil {
			return
		}
	}
}

// Run receives: every 20 ms frame of 16 kHz PCM goes to sink, until ctx is
// done or the leg is closed.
func (l *rtpLeg) Run(ctx context.Context, sink func([]int16)) error {
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	buf := make([]byte, 2048)
	plain := make([]byte, 0, 2048)
	for {
		n, addr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		l.mu.Lock()
		remote, codec, dtmfPT, rx := l.remote, l.codec, l.dtmfPT, l.rx
		l.mu.Unlock()
		if remote == nil || !addr.IP.Equal(remote.IP) {
			continue // foreign source: only the phone's IP from the SDP
		}
		data := buf[:n]
		if rx != nil {
			if data, err = rx.Unprotect(plain[:0], data); err != nil {
				// Not RTP at all is no failed check: a phone sends the odd
				// non-media packet when a stream starts.
				if !errors.Is(err, srtp.ErrNotRTP) {
					l.srtpFailed(err)
				}
				continue
			}
		}
		pkt, err := media.ParsePacket(data)
		if err != nil {
			continue
		}
		l.mu.Lock()
		l.lastRX = time.Now()
		l.mu.Unlock()
		if addr.Port != remote.Port {
			l.mu.Lock()
			l.remote = &net.UDPAddr{IP: addr.IP, Port: addr.Port} // symmetric RTP
			l.mu.Unlock()
		}
		switch {
		case dtmfPT > 0 && int(pkt.PT) == dtmfPT:
			l.handleDTMF(pkt)
		case codec != nil && int(pkt.PT) == codec.PT():
			pcm := codec.Decode(pkt.Payload)
			for off := 0; off+frameSamples16k <= len(pcm); off += frameSamples16k {
				sink(pcm[off : off+frameSamples16k])
			}
		}
	}
}

func (l *rtpLeg) lastReceived() time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lastRX
}

// handleDTMF handles RFC 4733 events: an event is reported once per timestamp.
func (l *rtpLeg) handleDTMF(pkt media.Packet) {
	if len(pkt.Payload) < 4 {
		return
	}
	ev := pkt.Payload[0]
	l.mu.Lock()
	if l.dtmfSeen && l.dtmfTS == pkt.Timestamp {
		l.mu.Unlock()
		return
	}
	l.dtmfSeen, l.dtmfTS = true, pkt.Timestamp
	cb := l.onDTMF
	l.mu.Unlock()
	digit, ok := dtmfDigit(ev)
	if ok && cb != nil {
		cb(digit)
	}
}

func dtmfDigit(ev byte) (byte, bool) {
	switch {
	case ev <= 9:
		return '0' + ev, true
	case ev == 10:
		return '*', true
	case ev == 11:
		return '#', true
	case ev >= 12 && ev <= 15:
		return 'A' + (ev - 12), true
	}
	return 0, false
}

// WriteFrame sends one 20 ms frame (320 samples at 16 kHz) to the phone.
func (l *rtpLeg) WriteFrame(_ context.Context, pcm []int16) error {
	l.mu.Lock()
	remote, codec, tx := l.remote, l.codec, l.tx
	if remote == nil || codec == nil {
		l.mu.Unlock()
		return nil
	}
	payload := codec.Encode(pcm)
	hdr := make([]byte, 12, 12+len(payload))
	hdr[0] = 0x80
	hdr[1] = byte(codec.PT())
	if !l.started {
		hdr[1] |= 0x80 // marker on the first packet of the stream
		l.started = true
	}
	binary.BigEndian.PutUint16(hdr[2:], l.seq)
	binary.BigEndian.PutUint32(hdr[4:], l.ts)
	binary.BigEndian.PutUint32(hdr[8:], l.ssrc)
	l.seq++
	l.ts += rtpTSStep8k
	l.mu.Unlock()
	pkt := append(hdr, payload...)
	if tx != nil {
		var err error
		if pkt, err = tx.Protect(make([]byte, 0, len(pkt)+srtpTagMax), pkt); err != nil {
			return nil
		}
	}
	_ = l.conn.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := l.conn.WriteToUDP(pkt, remote)
	if err != nil && errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}
