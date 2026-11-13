package main

// The phones' SIP connections over TCP (sip.listen) and TLS (sip.tls_port).
// sipgo's accept loop (sip.TransportTCP.Serve) returns on the first error of
// Accept, and it keeps every connection it accepted until the other side
// goes, so both listeners are wrapped here before sipgo gets them:
//
//   - a temporary error of Accept (EMFILE, ENFILE, ECONNABORTED, a timeout)
//     is waited out, with a pause that doubles from 5 ms to 1 s as in
//     net/http, instead of ending the loop for good;
//   - at most sipConnMax connections are open and at most sipConnPerIP from
//     one address, and the last sipConnReserve of sipConnMax are kept for
//     addresses a phone has signed in from. A connection over a limit is
//     closed as soon as it is accepted, so none waits in the kernel's
//     backlog;
//   - a connection is closed if no request with a valid password (digest)
//     comes in on it within sipSignInWithin of the accept. One a phone has
//     signed in on has no idle timeout: an iPhone in the background keeps it
//     silent for hours and is woken by a push. TCP keep-alive, which Go turns
//     on for accepted connections, ends it once the phone is gone;
//   - if sipgo's loop ends anyway while the server runs, the error goes to
//     the log at Error level and the same address is listened on again.

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	// The daemon has about 4096 descriptors on the router (RLIMIT_NOFILE);
	// the RTP ports (200 by default), the IMS side, the log and the
	// provisioning page need theirs. A home has a few phones with one
	// connection each.
	sipConnMax = 128
	// Of sipConnMax, for addresses a phone has signed in from: a crowd of
	// strangers cannot keep a phone from connecting again.
	sipConnReserve = 32
	// Linphone keeps one connection per account; the rest is room for a
	// device that comes back before TCP keep-alive has ended its old one.
	sipConnPerIP = 8
	// A phone signs in within a second of connecting (REGISTER, 401, REGISTER
	// with the password); the rest is room for a slow Wi-Fi.
	sipSignInWithin = 30 * time.Second
	// How many addresses phones signed in from are remembered for the reserve.
	sipKnownMax = 64

	sipAcceptPauseMin = 5 * time.Millisecond
	sipAcceptPauseMax = time.Second
	// After the loop has ended: the first pause before listening again; it
	// doubles up to sipRelistenMax while listening fails.
	sipRelisten    = time.Second
	sipRelistenMax = time.Minute
	// A refused or timed-out connection costs the sender nothing, so such
	// lines go to the log at most once a minute each, with a count.
	sipConnLogEvery = time.Minute
)

// sipConnKey names an accepted connection the way sipgo names the source of
// its requests: the transport and the phone's address and port.
type sipConnKey struct{ transport, remote string }

// sipConns counts the phones' TCP and TLS connections and keeps them within
// the limits.
type sipConns struct {
	logger *slog.Logger

	mu sync.Mutex
	// The limits: the constants above, smaller in tests.
	max, perIP, reserve int
	signIn              time.Duration

	total int
	byIP  map[string]int
	open  map[sipConnKey]*sipConn
	known map[string]time.Time // addresses a phone signed in from, by the time of the last sign-in

	refusedIP, refusedAll, refusedStranger, expired logLimiter
}

func newSIPConns(logger *slog.Logger) *sipConns {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &sipConns{logger: logger,
		max: sipConnMax, perIP: sipConnPerIP, reserve: sipConnReserve, signIn: sipSignInWithin,
		byIP: map[string]int{}, open: map[sipConnKey]*sipConn{}, known: map[string]time.Time{}}
}

// admit takes a connection Accept returned on transport (tcp or tls). It
// returns the connection to hand to sipgo, or nil when a limit is reached;
// then the connection is closed already.
func (s *sipConns) admit(transport string, c net.Conn) net.Conn {
	remote := c.RemoteAddr().String()
	ip := hostOnly(remote)
	s.mu.Lock()
	var why string
	var limit, count int
	var lim *logLimiter
	switch {
	case s.byIP[ip] >= s.perIP:
		why, limit, count, lim = "from one address", s.perIP, s.byIP[ip], &s.refusedIP
	case s.total >= s.max:
		why, limit, count, lim = "in all", s.max, s.total, &s.refusedAll
	case s.total >= s.max-s.reserve && !s.knownLocked(ip):
		why, limit, count, lim = "from addresses no phone signed in from", s.max-s.reserve, s.total, &s.refusedStranger
	}
	if lim != nil {
		n, show := lim.tick(time.Now(), sipConnLogEvery)
		s.mu.Unlock()
		if show {
			s.logger.Warn("SIP: connection refused, too many "+why, "transport", transport, "from", remote,
				"open", count, "limit", limit, "refused", n)
		}
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0) // a reset: nothing of it is left in the kernel
		}
		_ = c.Close()
		return nil
	}
	sc := &sipConn{Conn: c, conns: s, key: sipConnKey{transport, remote}, ip: ip}
	s.total++
	s.byIP[ip]++
	s.open[sc.key] = sc // a later connection from the same address and port takes the name
	sc.timer = time.AfterFunc(s.signIn, sc.expire)
	s.mu.Unlock()
	return sc
}

func (s *sipConns) knownLocked(ip string) bool {
	_, ok := s.known[ip]
	return ok
}

// signedIn notes a request with a valid password that came from source over
// transport (as sipgo names them): its connection has no time limit from
// now on, and its address may use the reserve.
func (s *sipConns) signedIn(transport, source string) {
	ip := hostOnly(source)
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.known[ip]; !ok && len(s.known) >= sipKnownMax {
		oldest := ""
		for k, at := range s.known {
			if oldest == "" || at.Before(s.known[oldest]) {
				oldest = k
			}
		}
		delete(s.known, oldest)
	}
	s.known[ip] = now
	if c := s.open[sipConnKey{strings.ToLower(transport), source}]; c != nil && !c.signedIn {
		c.signedIn = true
		c.timer.Stop()
	}
}

func (s *sipConns) release(c *sipConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.released = true
	c.timer.Stop()
	s.total--
	if s.byIP[c.ip]--; s.byIP[c.ip] <= 0 {
		delete(s.byIP, c.ip)
	}
	if s.open[c.key] == c {
		delete(s.open, c.key)
	}
}

// sipConn is an accepted connection within the limits of sipConns.
type sipConn struct {
	net.Conn
	conns *sipConns
	key   sipConnKey
	ip    string
	timer *time.Timer // sipSignInWithin after the accept: expire
	once  sync.Once
	// dropped: we closed it because nobody signed in. sipgo's own close comes
	// after that and says goodbye over TLS; that write goes nowhere, so that
	// the closing costs no line in the log.
	dropped atomic.Bool
	// Under conns.mu.
	signedIn, released bool
}

// expire closes the connection unless a phone has signed in on it.
func (c *sipConn) expire() {
	s := c.conns
	s.mu.Lock()
	if c.signedIn || c.released {
		s.mu.Unlock()
		return
	}
	n, show := s.expired.tick(time.Now(), sipConnLogEvery)
	within := s.signIn
	s.mu.Unlock()
	if show {
		s.logger.Warn("SIP: connection closed, nobody signed in on it", "transport", c.key.transport,
			"from", c.key.remote, "within", within.String(), "closed", n)
	}
	c.dropped.Store(true)
	_ = c.Close()
}

func (c *sipConn) Write(b []byte) (int, error) {
	if c.dropped.Load() {
		return len(b), nil
	}
	return c.Conn.Write(b)
}

// Close closes the connection once and frees its place; closing it again is
// not an error (the TLS layer and sipgo both close it).
func (c *sipConn) Close() error {
	var err error
	c.once.Do(func() {
		c.conns.release(c)
		err = c.Conn.Close()
	})
	return err
}

// logLimiter lets one log line of a kind through per interval and counts
// the events in between.
type logLimiter struct {
	last time.Time
	n    int
}

// tick counts an event. show says whether to log it; n is the number of
// events since the last line, this one included.
func (l *logLimiter) tick(now time.Time, every time.Duration) (n int, show bool) {
	l.n++
	if !l.last.IsZero() && now.Sub(l.last) < every {
		return 0, false
	}
	n, l.n, l.last = l.n, 0, now
	return n, true
}

// sipListener is the listening socket of one transport (tcp or tls), with
// the limits of sipConns on what it accepts. Accept returns an error only
// when the socket is closed or broken.
type sipListener struct {
	net.Listener
	transport string
	conns     *sipConns
	logger    *slog.Logger
	done      chan struct{}
	closeOnce sync.Once
	failures  logLimiter // only Accept, in sipgo's one loop, uses it
}

func (ln *sipListener) Accept() (net.Conn, error) {
	var pause time.Duration
	for {
		c, err := ln.Listener.Accept()
		if err != nil {
			select {
			case <-ln.done:
				return nil, net.ErrClosed
			default:
			}
			if !temporaryAcceptError(err) {
				return nil, err
			}
			pause = acceptPause(pause)
			if n, show := ln.failures.tick(time.Now(), sipConnLogEvery); show {
				ln.logger.Error("SIP: accept failed, trying again", "transport", ln.transport, "err", err,
					"pause", pause.String(), "failures", n)
			}
			t := time.NewTimer(pause)
			select {
			case <-t.C:
			case <-ln.done:
				t.Stop()
				return nil, net.ErrClosed
			}
			continue
		}
		pause = 0
		if sc := ln.conns.admit(ln.transport, c); sc != nil {
			return sc, nil
		}
	}
}

func (ln *sipListener) Close() error {
	ln.closeOnce.Do(func() { close(ln.done) })
	return ln.Listener.Close()
}

// acceptPause is the pause after a failed Accept, as in net/http: 5 ms after
// the first failure in a row, then twice the last pause, at most 1 s.
func acceptPause(last time.Duration) time.Duration {
	if last <= 0 {
		return sipAcceptPauseMin
	}
	return min(2*last, sipAcceptPauseMax)
}

// temporaryAcceptError reports an error of Accept that passes by itself: no
// free descriptors or memory for now, a connection that went away before it
// was taken, a timeout.
func temporaryAcceptError(err error) bool {
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ENOBUFS, syscall.ENOMEM,
		syscall.ECONNABORTED, syscall.ECONNRESET, syscall.EPROTO, syscall.EPERM, syscall.EINTR, syscall.EAGAIN} {
		if errors.Is(err, e) {
			return true
		}
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// sipStream serves one stream transport (tcp or tls) through sipgo for the
// life of the server. If sipgo's loop ends while the server is open (Accept
// failed in a way that does not pass), the error goes to the log and the same
// address is listened on again.
type sipStream struct {
	transport string
	addr      string                   // as the first listener got it: a port 0 of the tests made real
	serve     func(net.Listener) error // srv.ServeTCP or srv.ServeTLS
	tlsConf   *tls.Config              // tls: what sipgo gets is a TLS listener
	conns     *sipConns
	logger    *slog.Logger

	mu     sync.Mutex
	ln     *sipListener
	retry  time.Duration // sipRelisten, shorter in tests
	closed bool
	done   chan struct{}
}

func newSIPStream(transport string, ln net.Listener, serve func(net.Listener) error, tlsConf *tls.Config, conns *sipConns) *sipStream {
	st := &sipStream{transport: transport, addr: ln.Addr().String(), serve: serve, tlsConf: tlsConf,
		conns: conns, logger: conns.logger, retry: sipRelisten, done: make(chan struct{})}
	st.ln = st.wrap(ln)
	return st
}

func (st *sipStream) wrap(ln net.Listener) *sipListener {
	return &sipListener{Listener: ln, transport: st.transport, conns: st.conns, logger: st.logger, done: make(chan struct{})}
}

// run serves until Close.
func (st *sipStream) run() {
	st.mu.Lock()
	ln := st.ln
	st.mu.Unlock()
	var pause time.Duration
	for {
		started := time.Now()
		var l net.Listener = ln
		if st.tlsConf != nil {
			l = tls.NewListener(ln, st.tlsConf)
		}
		err := st.serve(l)
		st.mu.Lock()
		closed := st.closed
		if pause == 0 || time.Since(started) > sipRelistenMax {
			pause = st.retry // the first stop, or it served for a good while: the shortest pause
		}
		st.mu.Unlock()
		if closed {
			return
		}
		_ = ln.Close()
		st.logger.Error("SIP: the listener stopped, listening again", "transport", st.transport, "listen", st.addr,
			"err", err, "in", pause.String())
		for {
			if !st.sleep(pause) {
				return
			}
			pause = min(2*pause, sipRelistenMax)
			nl, err := net.Listen("tcp4", st.addr)
			if err != nil {
				st.logger.Error("SIP: cannot listen again", "transport", st.transport, "listen", st.addr,
					"err", err, "next_in", pause.String())
				continue
			}
			st.mu.Lock()
			if st.closed {
				st.mu.Unlock()
				_ = nl.Close()
				return
			}
			ln = st.wrap(nl)
			st.ln = ln
			st.mu.Unlock()
			st.logger.Info("SIP: listening again", "transport", st.transport, "listen", st.addr)
			break
		}
	}
}

// sleep waits d or until Close; false means closed.
func (st *sipStream) sleep(d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-st.done:
		return false
	}
}

func (st *sipStream) Close() error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	st.closed = true
	close(st.done)
	ln := st.ln
	st.mu.Unlock()
	return ln.Close()
}
