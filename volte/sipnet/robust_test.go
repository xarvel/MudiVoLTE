package sipnet

import (
	"bufio"
	"bytes"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// A Content-Length near the int limit overflowed len(head)+clen: the negative
// total passed both bound checks and buf[:total] panicked on the read loop.
func TestSplitFrameHugeContentLength(t *testing.T) {
	for _, clen := range []string{
		"Content-Length: 9223372036854775807",
		"l: 9223372036854775807",
		"Content-Length: 99999999999999999999", // beyond int64
		"Content-Length: 262145",               // just over maxMessage
	} {
		msg := []byte("NOTIFY sip:x SIP/2.0\r\n" + clen + "\r\n\r\n")
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: splitFrame panicked: %v", clen, r)
				}
			}()
			if _, _, _, err := splitFrame(msg); err == nil || errors.Is(err, errNeedMore) {
				t.Errorf("%s: accepted (%v)", clen, err)
			}
		}()
	}
	// The limit itself still frames.
	body := strings.Repeat("x", 1000)
	msg := "NOTIFY sip:x SIP/2.0\r\nContent-Length: 1000\r\n\r\n" + body
	if frame, _, _, err := splitFrame([]byte(msg)); err != nil || string(frame) != msg {
		t.Fatalf("ordinary message: %v", err)
	}
}

// The same bytes from the peer of a Conn: the read loop used to die of the
// panic and take the process (mudi-imsd) with it. Now the connection fails
// and the process lives. The child process holds the Conn; the parent checks
// how it ended.
func TestConnSurvivesHugeContentLength(t *testing.T) {
	if os.Getenv("SIPNET_CHILD") == "1" {
		a, b := net.Pipe()
		c := newConn(a, nil, nil)
		go func() { _, _ = b.Write([]byte("SIP/2.0 200 OK\r\nl: 9223372036854775807\r\n\r\n")) }()
		select {
		case <-c.Done():
			os.Exit(0)
		case <-time.After(3 * time.Second):
			os.Exit(3) // neither failed nor crashed
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestConnSurvivesHugeContentLength$")
	cmd.Env = append(os.Environ(), "SIPNET_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		s := string(out)
		if i := strings.Index(s, "panic:"); i >= 0 {
			s = s[i:]
			if j := strings.IndexByte(s, '\n'); j > 0 {
				s = s[:j]
			}
		}
		t.Fatalf("the read loop crashed the process or kept the connection: %v: %s", err, s)
	}
}

// syncBuffer collects the log of a Conn, written from its read loop.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// peer is the network side of a Conn under test: it writes raw messages and
// reads what the Conn answers.
type peer struct {
	t   *testing.T
	nc  net.Conn
	in  *bufio.Reader
	got chan *sip.Request // what reached the handler
	log *syncBuffer
	c   *Conn
}

// newPeer connects a Conn whose handler runs before (when not nil) on every
// request and then reports it.
func newPeer(t *testing.T, before func(*sip.Request)) *peer {
	a, b := netPipe(t)
	got, log := make(chan *sip.Request, 8), &syncBuffer{}
	c := newConn(b, func(_ *Conn, r *sip.Request) {
		if before != nil {
			before(r)
		}
		got <- r
	}, slog.New(slog.NewTextHandler(log, nil)))
	t.Cleanup(func() { c.Close() })
	return &peer{t: t, nc: a, in: bufio.NewReader(a), got: got, log: log, c: c}
}

func request(method, callID string, drop ...string) string {
	lines := []string{
		"Via: SIP/2.0/TCP 192.0.2.1:5060;branch=z9hG4bK" + callID,
		"From: <sip:net@ims.test>;tag=n1",
		"To: <sip:ue@ims.test>",
		"Call-ID: " + callID,
		"CSeq: 1 " + method,
	}
	out := method + " sip:ue@192.0.2.2 SIP/2.0\r\n"
	for _, l := range lines {
		name, _, _ := strings.Cut(l, ":")
		if len(drop) == 0 || name != drop[0] {
			out += l + "\r\n"
		}
	}
	return out + "Content-Length: 0\r\n\r\n"
}

func (p *peer) send(raw string) {
	p.t.Helper()
	if _, err := p.nc.Write([]byte(raw)); err != nil {
		p.t.Fatal(err)
	}
}

// status reads the status line of the next response, "" when none comes.
func (p *peer) status(within time.Duration) string {
	p.t.Helper()
	_ = p.nc.SetReadDeadline(time.Now().Add(within))
	defer p.nc.SetReadDeadline(time.Time{})
	var first string
	for {
		line, err := p.in.ReadString('\n')
		if err != nil {
			return first
		}
		if first == "" {
			first = strings.TrimSpace(line)
		}
		if line == "\r\n" {
			return first
		}
	}
}

// next is the Call-ID of the next request that reached the handler, "" when
// none does.
func (p *peer) next() string {
	select {
	case r := <-p.got:
		if r.CallID() == nil {
			return "(no Call-ID)"
		}
		return r.CallID().Value()
	case <-time.After(2 * time.Second):
		return ""
	}
}

// Every request carries Via, From, To, Call-ID and CSeq (RFC 3261 §8.1.1),
// and the handlers take them for granted: an INVITE without Call-ID used to
// crash the process in the call manager. sipnet refuses such a request with
// a 400 that names the header, drops it when no response could be routed
// (no Via) or none is allowed (ACK), and keeps the connection.
func TestRequestWithoutMandatoryHeader(t *testing.T) {
	for _, h := range []string{"From", "To", "Call-ID", "CSeq"} {
		p := newPeer(t, nil)
		p.send(request("INVITE", "x"+strings.ToLower(h[:1]), h))
		if got, want := p.status(2*time.Second), "SIP/2.0 400 Missing "+h+" header field"; got != want {
			t.Errorf("INVITE without %s: got %q, want %q", h, got, want)
		}
		p.send(request("OPTIONS", "after"))
		if got := p.next(); got != "after" {
			t.Errorf("without %s: the handler got %q, want only the request after it", h, got)
		}
	}
	for _, c := range []struct{ method, drop string }{{"INVITE", "Via"}, {"ACK", "Call-ID"}} {
		p := newPeer(t, nil)
		p.send(request(c.method, "dropped", c.drop))
		if got := p.status(300 * time.Millisecond); got != "" {
			t.Errorf("%s without %s answered with %q", c.method, c.drop, got)
		}
		p.send(request("OPTIONS", "after"))
		if got := p.next(); got != "after" {
			t.Errorf("%s without %s: the handler got %q, want only the request after it", c.method, c.drop, got)
		}
		if p.c.Err() != nil {
			t.Errorf("%s without %s: connection failed: %v", c.method, c.drop, p.c.Err())
		}
	}
}

// A panic while one message is handled costs that message, not the
// connection and not the process: it is logged as an error with its stack,
// and the next message on the connection is handled as usual.
func TestPanicInHandlerCostsOneMessage(t *testing.T) {
	p := newPeer(t, func(r *sip.Request) {
		if r.CallID().Value() == "boom" {
			var missing *sip.CallIDHeader
			_ = missing.Value() // the kind of bug this guards against
		}
	})
	p.send(request("MESSAGE", "boom"))
	p.send(request("MESSAGE", "next"))
	if got := p.next(); got != "next" {
		t.Fatalf("after the panic the handler got %q, want the next message", got)
	}
	if p.c.Err() != nil {
		t.Fatalf("connection failed: %v", p.c.Err())
	}
	log := p.log.String()
	if !strings.Contains(log, "level=ERROR") || !strings.Contains(log, "message dropped") ||
		!strings.Contains(log, "nil pointer dereference") || !strings.Contains(log, "TestPanicInHandlerCostsOneMessage") {
		t.Fatalf("no error with the panic and its stack in the log:\n%s", log)
	}
}

// panicConn fails its first Read with a panic, standing for a bug on the
// read loop outside the handling of one message (in the framing, say).
type panicConn struct{ net.Conn }

func (panicConn) Read([]byte) (int, error) { panic("read loop bug") }

// Such a panic leaves the stream at an unknown position: the connection
// fails, with the panic and its stack in the log, and the process lives.
func TestPanicOnReadLoopClosesTheConnection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	log := &syncBuffer{}
	c := newConn(panicConn{b}, nil, slog.New(slog.NewTextHandler(log, nil)))
	select {
	case <-c.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the connection outlived a panic of its read loop")
	}
	if err := c.Err(); err == nil || !strings.Contains(err.Error(), "read loop bug") {
		t.Errorf("Err() = %v", err)
	}
	if s := log.String(); !strings.Contains(s, "level=ERROR") || !strings.Contains(s, "read loop bug") || !strings.Contains(s, "readLoop") {
		t.Errorf("no error with the panic and its stack in the log:\n%s", s)
	}
}
