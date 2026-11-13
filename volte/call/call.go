// Package call implements MMTel voice call signalling for the UE
// (3GPP TS 24.229 §5.1.3/§5.1.4, TS 24.173, GSMA IR.92 §2.2): INVITE as UAS
// and UAC, reliable provisionals (RFC 3262), CANCEL, re-INVITE/UPDATE
// (RFC 3311) and SDP offer/answer (RFC 3264) for one audio stream.
package call

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// RFC 3261 timers.
const (
	T1 = 500 * time.Millisecond
	T2 = 4 * time.Second
)

// State of a call as seen by the application.
type State int

const (
	StateIncoming State = iota // INVITE received, not yet answered
	StateCalling               // our INVITE sent
	StateRinging               // remote is alerting (180)
	StateEarly                 // early media (183 with SDP)
	StateAnswered              // 200 sent, waiting for ACK
	StateActive                // confirmed dialog
	StateEnded
)

func (s State) String() string {
	return [...]string{"incoming", "calling", "ringing", "early", "answered", "active", "ended"}[s]
}

// Direction of the call.
type Direction int

const (
	Inbound Direction = iota
	Outbound
)

// Call is one voice session.
type Call struct {
	m   *Manager
	Dir Direction

	mu        sync.Mutex
	state     State
	cause     string
	callID    string
	localTag  string
	remoteTag string
	localURI  string // name-addr without tag
	remoteURI string
	remoteID  string // P-Asserted-Identity or From
	target    string // remote target URI (Contact)
	routes    []string
	localSeq  uint32

	// inbound
	invite          *sip.Request
	inviteConn      *sipnet.Conn
	reliable        bool // peer requires 100rel
	rseq            uint32
	remoteInviteSeq uint32
	offerDir        string
	pracked         chan uint32
	acked           chan struct{}
	ackOnce         sync.Once
	offerless       bool

	// outbound
	out       *sipnet.Request
	inviteSeq uint32   // CSeq of our INVITE; a retry after 422 takes the next one
	routes0   []string // route set of the initial INVITE
	cancelled bool     // CANCEL sent
	answered  bool     // the 2xx to our INVITE is taken: hanging up is a BYE from here on

	se sessionTimer

	// media
	local    netip.AddrPort
	neg      Negotiated
	hasMedia bool
	sdpID    uint64
	sdpVer   uint64

	done chan struct{}
}

func newCall(m *Manager, dir Direction) *Call {
	return &Call{m: m, Dir: dir, sdpID: randU32(), sdpVer: 1, localSeq: 1, rseq: uint32(randU32() & 0xffff),
		acked: make(chan struct{}), pracked: make(chan uint32, 4), done: make(chan struct{})}
}

func randU32() uint64 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return uint64(binary.BigEndian.Uint32(b[:]))
}

// ID is the Call-ID.
func (c *Call) ID() string { return c.callID }

// State returns the current state and, once ended, the reason.
func (c *Call) State() (State, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state, c.cause
}

// Done is closed when the call has ended.
func (c *Call) Done() <-chan struct{} { return c.done }

// RemoteIdentity is the asserted identity of the other party.
func (c *Call) RemoteIdentity() string { return c.remoteID }

// RemoteNumber extracts the number from the remote identity (tel: or sip:user).
func (c *Call) RemoteNumber() string { return Number(c.remoteID) }

// Number returns the user part of a tel:/sip: URI or name-addr.
func Number(addr string) string {
	s := addr
	if i := strings.Index(s, "<"); i >= 0 {
		s = s[i+1:]
		if j := strings.Index(s, ">"); j >= 0 {
			s = s[:j]
		}
	}
	s = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(s, "tel:"), "sip:"), "sips:")
	s, _, _ = strings.Cut(s, "@")
	s, _, _ = strings.Cut(s, ";")
	return strings.TrimSpace(s)
}

// Media returns the negotiated stream and our RTP address, once known.
func (c *Call) Media() (Negotiated, netip.AddrPort, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.neg, c.local, c.hasMedia
}

func (c *Call) setState(s State, cause string) {
	c.mu.Lock()
	if c.state == StateEnded || c.state == s {
		c.mu.Unlock()
		return
	}
	c.state, c.cause = s, cause
	if s == StateEnded {
		c.armSessionLocked(0, false)
	}
	c.mu.Unlock()
	if s == StateEnded {
		close(c.done)
		c.m.forget(c)
	}
	c.m.notify(c, s)
}

// inDialog builds a request inside the dialog (RFC 3261 §12.2.1.1).
func (c *Call) inDialog(method string) *sipnet.Request {
	c.mu.Lock()
	c.localSeq++
	seq := c.localSeq
	c.mu.Unlock()
	return c.inDialogSeq(method, seq, sipnet.NewBranch())
}

func (c *Call) inDialogSeq(method string, seq uint32, branch string) *sipnet.Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.inDialogSeqLocked(method, seq, branch)
}

func (c *Call) inDialogSeqLocked(method string, seq uint32, branch string) *sipnet.Request {
	r := sipnet.NewRequest(method, strings.Trim(c.target, "<>")).
		Add("Via", "SIP/2.0/TCP "+c.m.reg.SentBy()+";branch="+branch).
		Add("Max-Forwards", "70")
	for _, rt := range c.routes {
		r.Add("Route", rt)
	}
	to := c.remoteURI
	if c.remoteTag != "" {
		to += ";tag=" + c.remoteTag
	}
	r.Add("From", c.localURI+";tag="+c.localTag).
		Add("To", to).
		Add("Call-ID", c.callID).
		Add("CSeq", itoa(seq)+" "+method)
	c.m.commonHeaders(r)
	return r
}

func itoa(n uint32) string { return strconv.FormatUint(uint64(n), 10) }
