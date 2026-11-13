package main

// The network on top of the volte library: registration (reg), calls (call), SMS
// (sms). netStack ties them together and hands calls to the daemon as
// imsCall. The RTP of a network call uses its own UDP socket on the IMS
// address; imsLeg does the encoding, here there is only the transport and
// RFC 4733 for tones.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/call"
	"github.com/xarvel/MudiVoLTE/volte/media"
	"github.com/xarvel/MudiVoLTE/volte/reg"
	volsim "github.com/xarvel/MudiVoLTE/volte/sim"
	"github.com/xarvel/MudiVoLTE/volte/sipnet"
	"github.com/xarvel/MudiVoLTE/volte/sms"
)

type netStack struct {
	log *slog.Logger
	ue  netip.Addr
	// iface is the IMS interface: RTP to the SBC is bound to it, otherwise the
	// media addresses (not the P-CSCF ones, they have no /32) go by the default
	// route through the internet PDN and get lost.
	iface string
	reg   *reg.Client
	calls *call.Manager
	sms   *sms.Service

	mu   sync.Mutex
	byID map[string]*netCall

	// onIncoming receives a new incoming call (in its own goroutine).
	onIncoming func(c *netCall, from string)
	// onEvent reports a call state change; it must not block.
	onEvent func(c *netCall, s CallState)
}

// availableCodecs returns what we can do on the network: AMR-WB only when the
// codec is linked in (cgo build with media/amrwb), otherwise G.711.
func availableCodecs() []string {
	if media.NewAMRWBCoder != nil {
		return []string{"AMR-WB", "PCMA", "PCMU"}
	}
	return []string{"PCMA", "PCMU"}
}

func newNetStack(iface string, rc reg.Config, auth volsim.Authenticator, cc call.Config, sc sms.Config, log *slog.Logger) (*netStack, error) {
	st := &netStack{log: log, ue: rc.UEAddr, iface: iface, byID: map[string]*netCall{}}
	r, err := reg.New(rc, auth, func(conn *sipnet.Conn, req *sip.Request) { st.calls.Handle(conn, req) })
	if err != nil {
		return nil, err
	}
	st.reg = r
	if cc.Codecs == nil {
		cc.Codecs = availableCodecs()
	}
	st.calls = call.NewManager(r, cc)
	st.sms = sms.New(r, sc)
	st.calls.Other = st.sms.Handle
	st.calls.OnIncoming = st.handleIncoming
	st.calls.OnState = st.handleState
	return st, nil
}

func (st *netStack) remember(nc *netCall) {
	st.mu.Lock()
	st.byID[nc.c.ID()] = nc
	st.mu.Unlock()
}

func (st *netStack) lookup(id string) *netCall {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.byID[id]
}

func (st *netStack) forget(id string) {
	st.mu.Lock()
	delete(st.byID, id)
	st.mu.Unlock()
}

func (st *netStack) handleIncoming(c *call.Call) {
	nc := newNetCall(st, c, CallIncoming)
	st.remember(nc)
	if st.onIncoming == nil {
		_ = c.Reject(603, "Decline")
		return
	}
	st.onIncoming(nc, c.RemoteNumber())
}

func (st *netStack) handleState(c *call.Call, s call.State) {
	nc := st.lookup(c.ID())
	if nc == nil {
		return
	}
	var ev CallState
	switch s {
	case call.StateCalling:
		ev = CallStateDialing
	case call.StateRinging:
		ev = CallStateRinging
	case call.StateEarly:
		ev = CallStateEarlyMedia
	case call.StateActive:
		ev = CallStateActive
		nc.activeOnce.Do(func() { close(nc.active) })
	case call.StateEnded:
		ev = CallStateEnded
		st.forget(c.ID())
		nc.closeRTP()
	default:
		return
	}
	if st.onEvent != nil {
		st.onEvent(nc, ev)
	}
}

// bindRTP binds an even port on the IMS address (the odd one after it is left
// for RTCP), with the socket bound to the IMS interface (SO_BINDTODEVICE).
func (st *netStack) bindRTP() (*net.UDPConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, rc syscall.RawConn) error {
		if st.iface == "" {
			return nil
		}
		var serr error
		err := rc.Control(func(fd uintptr) { serr = bindToDevice(fd, st.iface) })
		return errors.Join(err, serr)
	}}
	var last error
	for i := 0; i < 20; i++ {
		port := 40000 + 2*mrand.IntN(5000)
		c, err := lc.ListenPacket(context.Background(), "udp4", netip.AddrPortFrom(st.ue, uint16(port)).String())
		if err == nil {
			return c.(*net.UDPConn), nil
		}
		last = err
	}
	return nil, fmt.Errorf("cannot bind an RTP port: %w", last)
}

// Dial places an outgoing call to the network; it returns on answer, failure
// or cancellation of ctx.
func (st *netStack) Dial(ctx context.Context, to string) (imsCall, error) {
	rtp, err := st.bindRTP()
	if err != nil {
		return nil, err
	}
	local := rtp.LocalAddr().(*net.UDPAddr).AddrPort()
	var nc *netCall
	c, err := st.calls.DialWith(to, local, func(c *call.Call) {
		nc = newNetCall(st, c, CallOutgoing)
		nc.rtp = rtp
		st.remember(nc)
	})
	if err != nil {
		rtp.Close()
		return nil, err
	}
	select {
	case <-nc.active:
		return nc, nil
	case <-c.Done():
		_, cause := c.State()
		return nil, causeError(cause)
	case <-ctx.Done():
		// CANCEL waits up to 10 s for the network's answer; neither the phone nor
		// the line needs to wait for it. A callee's answer that crosses the CANCEL is
		// ended by the library itself.
		go func() { _ = c.Hangup() }()
		return nil, ctx.Err()
	}
}

// causeError — "486 Busy Here" → dialError{486, "Busy Here"}.
func causeError(cause string) error {
	code, reason, _ := strings.Cut(cause, " ")
	if n, err := strconv.Atoi(code); err == nil && n >= 300 && n < 700 {
		return &dialError{Code: n, Reason: reason}
	}
	return errors.New("the call failed: " + cause)
}

// --- Call ---

type netCall struct {
	st  *netStack
	c   *call.Call
	dir CallDirection

	mu  sync.Mutex
	rtp *net.UDPConn

	wmu    sync.Mutex
	ssrc   uint32
	seq    uint16
	lastTS uint32

	active     chan struct{}
	activeOnce sync.Once
}

func newNetCall(st *netStack, c *call.Call, dir CallDirection) *netCall {
	var b [6]byte
	_, _ = rand.Read(b[:])
	return &netCall{st: st, c: c, dir: dir, ssrc: binary.BigEndian.Uint32(b[:4]),
		seq: binary.BigEndian.Uint16(b[4:]), active: make(chan struct{})}
}

func (n *netCall) ID() string               { return n.c.ID() }
func (n *netCall) Done() <-chan struct{}    { return n.c.Done() }
func (n *netCall) Direction() CallDirection { return n.dir }
func (n *netCall) Ring() error              { return n.c.Ring() }

func (n *netCall) Media() NetMedia {
	neg, _, ok := n.c.Media()
	if !ok {
		return NetMedia{}
	}
	m := NetMedia{Negotiated: true, Codec: strings.ToUpper(neg.Codec.Name), PayloadType: neg.Codec.PT,
		ClockRate: neg.Codec.ClockRate, OctetAlign: neg.Codec.OctetAligned()}
	m.ModeSet, _ = neg.Codec.Param("mode-set")
	if neg.DTMF != nil {
		m.DTMFPT, m.DTMFHz = neg.DTMF.PT, neg.DTMF.ClockRate
	}
	return m
}

func (n *netCall) socket() *net.UDPConn {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.rtp
}

func (n *netCall) closeRTP() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.rtp != nil {
		n.rtp.Close()
	}
}

func (n *netCall) remote() (netip.AddrPort, bool) {
	neg, _, ok := n.c.Media()
	return neg.Remote, ok && neg.Remote.Port() != 0
}

// ReadPacket returns the next RTP packet from the network. An error means the
// call has ended.
func (n *netCall) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-n.c.Done():
			return nil, nil, errors.New("the call has ended")
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}
		s := n.socket()
		if s == nil { // incoming call not answered yet
			select {
			case <-n.c.Done():
			case <-ctx.Done():
			case <-time.After(20 * time.Millisecond):
			}
			continue
		}
		_ = s.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		k, addr, err := s.ReadFromUDP(buf)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return nil, nil, err
		}
		return buf[:k], addr, nil
	}
}

// WriteRTP sends a packet to the network with our own SSRC and sequence
// number, so that RFC 4733 tones go in the same stream without gaps.
func (n *netCall) WriteRTP(_ context.Context, data []byte) error {
	s := n.socket()
	dst, ok := n.remote()
	if s == nil || !ok || len(data) < 12 {
		return errors.New("media not ready")
	}
	pkt := append([]byte(nil), data...)
	n.wmu.Lock()
	binary.BigEndian.PutUint16(pkt[2:], n.seq)
	binary.BigEndian.PutUint32(pkt[8:], n.ssrc)
	n.seq++
	n.lastTS = binary.BigEndian.Uint32(pkt[4:])
	n.wmu.Unlock()
	_, err := s.WriteToUDPAddrPort(pkt, dst)
	return err
}

func (n *netCall) Answer(context.Context) error {
	rtp, err := n.st.bindRTP()
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.rtp = rtp
	n.mu.Unlock()
	return n.c.Answer(rtp.LocalAddr().(*net.UDPAddr).AddrPort())
}

func (n *netCall) Reject(_ context.Context, code int, reason string) error {
	return n.c.Reject(code, reason)
}

func (n *netCall) Hangup(ctx context.Context) error {
	done := make(chan error, 1)
	go func() { done <- n.c.Hangup() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// SendDTMF sends RFC 4733 tones: 100 ms per digit, three end packets.
func (n *netCall) SendDTMF(ctx context.Context, digits string) error {
	m := n.Media()
	s := n.socket()
	dst, ok := n.remote()
	if m.DTMFPT == 0 || s == nil || !ok {
		return errors.New("telephone-event not negotiated")
	}
	hz := m.DTMFHz
	if hz == 0 {
		hz = 8000
	}
	units := func(d time.Duration) uint16 { return uint16(int64(d) * int64(hz) / int64(time.Second)) }
	for _, d := range digits {
		ev, ok := media.DigitEvent(d)
		if !ok {
			return fmt.Errorf("not a DTMF digit: %q", d)
		}
		n.wmu.Lock()
		start := n.lastTS
		n.wmu.Unlock()
		send := func(e media.DTMFEvent, marker bool) error {
			n.wmu.Lock()
			p := media.Packet{PT: uint8(m.DTMFPT), Seq: n.seq, Timestamp: start, SSRC: n.ssrc, Payload: e.Marshal(), Marker: marker}
			n.seq++
			n.wmu.Unlock()
			_, err := s.WriteToUDPAddrPort(p.Marshal(), dst)
			return err
		}
		for t := 20 * time.Millisecond; t < 100*time.Millisecond; t += 20 * time.Millisecond {
			if err := send(media.DTMFEvent{Event: ev, Volume: 10, Duration: units(t)}, t == 20*time.Millisecond); err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(20 * time.Millisecond):
			}
		}
		for i := 0; i < 3; i++ {
			if err := send(media.DTMFEvent{Event: ev, End: true, Volume: 10, Duration: units(100 * time.Millisecond)}, false); err != nil {
				return err
			}
		}
		time.Sleep(60 * time.Millisecond)
	}
	return nil
}
