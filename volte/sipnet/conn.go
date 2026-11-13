package sipnet

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emiago/sipgo/sip"
)

// TimerF bounds a non-INVITE client transaction (RFC 3261 §17.1.2.2, 64·T1).
const TimerF = 32 * time.Second

// Handler receives requests arriving on a connection. It runs on the read
// loop, in arrival order, so it must not block for long.
type Handler func(c *Conn, req *sip.Request)

// ErrClosed is returned for transactions on a closed connection.
var ErrClosed = errors.New("sip connection closed")

// Conn is one TCP connection carrying SIP in both directions.
type Conn struct {
	nc      net.Conn
	handler Handler
	log     *slog.Logger

	wmu sync.Mutex

	mu      sync.Mutex
	pending map[string]chan *sip.Response
	err     error
	done    chan struct{}
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func reuseAddr(_, _ string, rc syscall.RawConn) error {
	var serr error
	err := rc.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
	})
	return errors.Join(err, serr)
}

// Dial opens a TCP connection from local (port 0 = ephemeral) to remote.
func Dial(ctx context.Context, local, remote netip.AddrPort, h Handler, log *slog.Logger) (*Conn, error) {
	d := net.Dialer{Control: reuseAddr, Timeout: 10 * time.Second}
	if local.IsValid() {
		d.LocalAddr = net.TCPAddrFromAddrPort(local)
	}
	nc, err := d.DialContext(ctx, "tcp", remote.String())
	if err != nil {
		return nil, err
	}
	return newConn(nc, h, log), nil
}

func newConn(nc net.Conn, h Handler, log *slog.Logger) *Conn {
	if log == nil {
		log = discard()
	}
	c := &Conn{nc: nc, handler: h, log: log, pending: map[string]chan *sip.Response{}, done: make(chan struct{})}
	go c.readLoop()
	return c
}

func (c *Conn) LocalAddr() netip.AddrPort  { return addrPort(c.nc.LocalAddr()) }
func (c *Conn) RemoteAddr() netip.AddrPort { return addrPort(c.nc.RemoteAddr()) }

// addrPort is the address of a TCP endpoint; other transports (net.Pipe in
// tests) have none, and the logs of the read loop must not panic on them.
func addrPort(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort()
	}
	return netip.AddrPort{}
}

// Done is closed when the connection dies; Err then tells why.
func (c *Conn) Done() <-chan struct{} { return c.done }

func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

func (c *Conn) Close() error {
	c.fail(ErrClosed)
	return nil
}

func (c *Conn) fail(err error) {
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return
	}
	c.err = err
	c.pending = map[string]chan *sip.Response{}
	close(c.done)
	c.mu.Unlock()
	c.nc.Close()
}

// Send writes one parsed message (responses to inbound requests).
func (c *Conn) Send(m sip.Message) error {
	return c.write([]byte(m.String()))
}

// SendRequest writes a request outside a client transaction (ACK).
func (c *Conn) SendRequest(r *Request) error {
	return c.write(r.Bytes())
}

func (c *Conn) write(b []byte) error {
	select {
	case <-c.done:
		return ErrClosed
	default:
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.nc.Write(b); err != nil {
		c.fail(err)
		return err
	}
	return nil
}

func txKey(branch string, method string) string {
	return strings.ToLower(branch) + "|" + strings.ToUpper(method)
}

// Do runs a client transaction: sends req and waits for the final response.
// Provisional responses go to onProvisional when it is not nil. Non-INVITE
// transactions are bounded by Timer F; INVITE ones only by ctx.
func (c *Conn) Do(ctx context.Context, req *Request, onProvisional func(*sip.Response)) (*sip.Response, error) {
	branch := req.Branch()
	if branch == "" {
		return nil, errors.New("request has no Via branch")
	}
	key := txKey(branch, req.Method)
	ch := make(chan *sip.Response, 8)
	c.mu.Lock()
	if c.err != nil {
		c.mu.Unlock()
		return nil, ErrClosed
	}
	c.pending[key] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, key)
		c.mu.Unlock()
	}()

	if err := c.write(req.Bytes()); err != nil {
		return nil, err
	}
	if req.Method != "INVITE" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, TimerF)
		defer cancel()
	}
	for {
		select {
		case res := <-ch:
			if res.StatusCode < 200 {
				if onProvisional != nil {
					onProvisional(res)
				}
				continue
			}
			return res, nil
		case <-c.done:
			return nil, fmt.Errorf("%s %s: %w", req.Method, branch, c.Err())
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: no final response: %w", req.Method, ctx.Err())
		}
	}
}

func (c *Conn) readLoop() {
	// The last line of defence for what handle does not cover: a panic while
	// framing leaves the stream at an unknown position, so it costs the
	// connection, not the process.
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("panic on the SIP read loop, closing the connection",
				"remote", c.RemoteAddr(), "panic", r, "stack", string(debug.Stack()))
			c.fail(fmt.Errorf("read loop: panic: %v", r))
		}
	}()
	buf := make([]byte, 0, 16<<10)
	tmp := make([]byte, 16<<10)
	for {
		n, err := c.nc.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if perr := c.drain(&buf); perr != nil {
				c.log.Warn("sip stream error, closing", "remote", c.RemoteAddr(), "err", perr)
				c.fail(perr)
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = fmt.Errorf("closed by %s: %w", c.RemoteAddr(), io.EOF)
			}
			c.fail(err)
			return
		}
	}
}

func (c *Conn) drain(buf *[]byte) error {
	for {
		frame, n, crlfs, err := splitFrame(*buf)
		if crlfs >= 2 {
			// "\r\n\r\n" ping → "\r\n" pong (RFC 5626 §4.4.1).
			_ = c.write([]byte("\r\n"))
		}
		if errors.Is(err, errNeedMore) {
			*buf = append((*buf)[:0], (*buf)[n:]...)
			return nil
		}
		if err != nil {
			return err
		}
		// frame aliases buf: copy it before compacting the buffer.
		frame = append([]byte(nil), frame...)
		*buf = append((*buf)[:0], (*buf)[n:]...)
		c.handle(frame)
	}
}

// handle parses one framed message and hands it on. A panic on the way, in
// the parser or in a handler, costs that message only: it is logged with
// the stack and dropped, and the connection goes on with the next message,
// whose framing is not in question.
func (c *Conn) handle(frame []byte) {
	defer func() {
		if r := recover(); r != nil {
			c.log.Error("panic while handling a SIP message, message dropped",
				"remote", c.RemoteAddr(), "bytes", len(frame), "panic", r, "stack", string(debug.Stack()))
		}
	}()
	msg, err := sip.ParseMessage(frame)
	if err != nil {
		c.log.Warn("unparsable SIP message dropped", "err", err)
		return
	}
	c.dispatch(msg)
}

// missingHeader names the first header field that req lacks of those every
// request carries (RFC 3261 §8.1.1; Max-Forwards aside, which only proxies
// act on), or returns "". Handlers take them for granted.
func missingHeader(req *sip.Request) string {
	switch {
	case req.Via() == nil:
		return "Via"
	case req.From() == nil:
		return "From"
	case req.To() == nil:
		return "To"
	case req.CallID() == nil:
		return "Call-ID"
	case req.CSeq() == nil:
		return "CSeq"
	}
	return ""
}

func (c *Conn) dispatch(msg sip.Message) {
	switch m := msg.(type) {
	case *sip.Response:
		via, cseq := m.Via(), m.CSeq()
		if via == nil || cseq == nil {
			return
		}
		branch, _ := via.Params.Get("branch")
		c.mu.Lock()
		ch := c.pending[txKey(branch, string(cseq.MethodName))]
		c.mu.Unlock()
		if ch == nil {
			c.log.Debug("stray response", "status", m.StatusCode, "method", cseq.MethodName)
			return
		}
		select {
		case ch <- m:
		default:
		}
	case *sip.Request:
		if h := missingHeader(m); h != "" {
			// A response without Via has nowhere to go (RFC 3261 §18.2.2) and an
			// ACK takes none (§17); anything else hears what is missing
			// (§21.4.1).
			if h == "Via" || m.IsAck() {
				c.log.Warn("SIP request without "+h+" dropped", "method", m.Method)
				return
			}
			c.log.Warn("SIP request without "+h+" refused", "method", m.Method)
			_ = c.Respond(m, 400, "Missing "+h+" header field")
			return
		}
		if c.handler != nil {
			c.handler(c, m)
		}
	}
}

// Respond sends a response built from req (RFC 3261 §8.2.6).
func (c *Conn) Respond(req *sip.Request, code int, reason string, extra ...sip.Header) error {
	res := sip.NewResponseFromRequest(req, code, reason, nil)
	for _, h := range extra {
		res.AppendHeader(h)
	}
	return c.Send(res)
}

// Listener accepts inbound TCP connections on a protected server port.
type Listener struct {
	ln      net.Listener
	handler Handler
	log     *slog.Logger

	mu    sync.Mutex
	conns map[*Conn]struct{}
}

// Listen binds local and serves accepted connections with h.
func Listen(local netip.AddrPort, h Handler, log *slog.Logger) (*Listener, error) {
	lc := net.ListenConfig{Control: reuseAddr}
	ln, err := lc.Listen(context.Background(), "tcp", local.String())
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = discard()
	}
	l := &Listener{ln: ln, handler: h, log: log, conns: map[*Conn]struct{}{}}
	go l.acceptLoop()
	return l, nil
}

func (l *Listener) Addr() netip.AddrPort { return l.ln.Addr().(*net.TCPAddr).AddrPort() }

func (l *Listener) acceptLoop() {
	for {
		nc, err := l.ln.Accept()
		if err != nil {
			return
		}
		c := newConn(nc, l.handler, l.log)
		l.mu.Lock()
		l.conns[c] = struct{}{}
		l.mu.Unlock()
		go func() {
			<-c.Done()
			l.mu.Lock()
			delete(l.conns, c)
			l.mu.Unlock()
		}()
	}
}

// Close stops accepting and closes every accepted connection.
func (l *Listener) Close() error {
	err := l.ln.Close()
	l.mu.Lock()
	conns := l.conns
	l.conns = map[*Conn]struct{}{}
	l.mu.Unlock()
	for c := range conns {
		c.Close()
	}
	return err
}
