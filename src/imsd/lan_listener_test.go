package main

// The phones' TCP and TLS connections (lan_listener.go): the listeners live
// through a full descriptor table and a broken socket, one address or a crowd
// of strangers cannot take all the connections, and a connection nobody
// signs in on is closed while a phone's silent one stays.

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// streamRig is a SIP server on TCP and TLS with its log to read back. No
// UDP: the TCP port would then have to be the free UDP port the kernel chose,
// and under load a client's TCP socket sometimes holds that number.
type streamRig struct {
	lan              *lanSIP
	tcpAddr, tlsAddr string
	log              *logBook
}

func newStreamRig(t *testing.T) *streamRig {
	t.Helper()
	book := &logBook{}
	logger := slog.New(slog.NewTextHandler(book, nil))
	dir := t.TempDir()
	sc := SIPConfig{
		Listen: "127.0.0.1:0", Transports: []string{"tcp", "tls"},
		TLSCertFile: dir + "/tls.crt", TLSKeyFile: dir + "/tls.key",
		Accounts:   []SIPAccount{{User: "pixel", Password: testPass}},
		RTPPortMin: 41400, RTPPortMax: 41500,
	}.withDefaults()
	mgr := newCallManager(&Config{}, sc, nil, logger)
	lan, err := startLANSIP(sc, mgr, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lan.Close)
	return &streamRig{lan: lan, log: book,
		tcpAddr: fmt.Sprintf("127.0.0.1:%d", lan.port), tlsAddr: fmt.Sprintf("127.0.0.1:%d", lan.tlsPort)}
}

// rawSIP is one TCP or TLS connection of a phone, driven by hand, so that a
// test knows which connection each request goes over.
type rawSIP struct {
	c  net.Conn
	r  *bufio.Reader
	tr string // TCP or TLS
}

// dialRaw connects from src, an address on 127/8 (tests are many hosts that
// way), to addr; tlsOn adds the TLS handshake.
func dialRaw(src, addr string, tlsOn bool) (*rawSIP, error) {
	d := &net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}}
	if !tlsOn {
		c, err := d.Dial("tcp4", addr)
		if err != nil {
			return nil, err
		}
		return &rawSIP{c: c, r: bufio.NewReader(c), tr: "TCP"}, nil
	}
	c, err := tls.DialWithDialer(d, "tcp4", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	return &rawSIP{c: c, r: bufio.NewReader(c), tr: "TLS"}, nil
}

func dialRawT(t *testing.T, src, addr string, tlsOn bool) *rawSIP {
	t.Helper()
	p, err := dialRaw(src, addr, tlsOn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.c.Close() })
	return p
}

// dialFrom opens a plain TCP connection from src that sends nothing (on the
// TLS port it does not even start the handshake).
func dialFrom(t *testing.T, src, addr string) net.Conn {
	t.Helper()
	p := dialRawT(t, src, addr, false)
	return p.c
}

// do sends a request of pixel without a body (auth: an Authorization value
// or nothing) and returns the head of the final answer.
func (p *rawSIP) do(method, auth string) (string, error) {
	local := p.c.LocalAddr().(*net.TCPAddr)
	m := method + " sip:127.0.0.1 SIP/2.0\r\n" +
		fmt.Sprintf("Via: SIP/2.0/%s %s:%d;branch=%s\r\n", p.tr, local.IP, local.Port, sip.GenerateBranch()) +
		"Max-Forwards: 70\r\n" +
		"From: <sip:pixel@127.0.0.1>;tag=" + sip.GenerateTagN(8) + "\r\n" +
		"To: <sip:pixel@127.0.0.1>\r\n" +
		"Call-ID: " + sip.GenerateTagN(16) + "\r\n" +
		"CSeq: 1 " + method + "\r\n" +
		fmt.Sprintf("Contact: <sip:pixel@%s:%d;transport=%s>\r\n", local.IP, local.Port, strings.ToLower(p.tr))
	if auth != "" {
		m += "Authorization: " + auth + "\r\n"
	}
	if _, err := p.c.Write([]byte(m + "Content-Length: 0\r\n\r\n")); err != nil {
		return "", err
	}
	_ = p.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer p.c.SetReadDeadline(time.Time{})
	for {
		var head strings.Builder
		length := 0
		for {
			line, err := p.r.ReadString('\n')
			if err != nil {
				return head.String(), err
			}
			if line == "\r\n" {
				break
			}
			head.WriteString(line)
			if v, ok := strings.CutPrefix(strings.ToLower(line), "content-length:"); ok {
				length, _ = strconv.Atoi(strings.TrimSpace(v))
			}
		}
		if _, err := io.CopyN(io.Discard, p.r, int64(length)); err != nil {
			return head.String(), err
		}
		if !strings.HasPrefix(head.String(), "SIP/2.0 1") {
			return head.String(), nil
		}
	}
}

// signIn signs pixel in over the connection: REGISTER, 401, REGISTER with
// the password, 200.
func (p *rawSIP) signIn() error {
	head, err := p.do("REGISTER", "")
	if err != nil || !strings.HasPrefix(head, "SIP/2.0 401") {
		return fmt.Errorf("REGISTER without the password: %.40q %v", head, err)
	}
	_, rest, _ := strings.Cut(head, "Digest ")
	line, _, _ := strings.Cut(rest, "\r\n")
	ch := parseDigestParams(line)
	ha1 := md5hex("pixel:" + ch["realm"] + ":" + testPass)
	ha2 := md5hex("REGISTER:sip:127.0.0.1")
	resp := md5hex(ha1 + ":" + ch["nonce"] + ":00000001:abc:auth:" + ha2)
	auth := fmt.Sprintf(`Digest username="pixel", realm="%s", nonce="%s", uri="sip:127.0.0.1", response="%s", algorithm=MD5, cnonce="abc", qop=auth, nc=00000001`,
		ch["realm"], ch["nonce"], resp)
	if head, err = p.do("REGISTER", auth); err != nil || !strings.HasPrefix(head, "SIP/2.0 200") {
		return fmt.Errorf("REGISTER with the password: %.40q %v", head, err)
	}
	return nil
}

// register401 sends a REGISTER without the password over a new connection
// from src: a server that serves the port answers 401.
func register401(src, addr string, tlsOn bool) error {
	p, err := dialRaw(src, addr, tlsOn)
	if err != nil {
		return err
	}
	defer p.c.Close()
	head, err := p.do("REGISTER", "")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(head, "SIP/2.0 401") {
		return fmt.Errorf("answer %.40q", head)
	}
	return nil
}

// closedOnConnect reports whether the server closes a new connection from
// src to addr at once. Its reset may come before connect has returned.
func closedOnConnect(t *testing.T, src, addr string) bool {
	t.Helper()
	p, err := dialRaw(src, addr, false)
	if errors.Is(err, syscall.ECONNRESET) {
		return true
	}
	if err != nil {
		t.Fatal(err)
	}
	defer p.c.Close()
	return waitClosed(p.c, 10*time.Second)
}

// waitClosed reports whether the server closes c within d: a read ends with
// EOF or a reset rather than the deadline.
func waitClosed(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 512)
	for {
		if _, err := c.Read(buf); err != nil {
			var ne net.Error
			return !errors.As(err, &ne) || !ne.Timeout()
		}
	}
}

func openFDs(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	return len(ents)
}

// failOneAccept makes one accept of the server on addr fail with EMFILE, the
// way a flood of idle connections does: the test process gets a low limit
// of descriptors, the table is filled but for one slot, a plain TCP connect
// takes that slot (also on the TLS port: no handshake needed), and then
// everything is freed and the limit is back.
func failOneAccept(t *testing.T, addr string) {
	t.Helper()
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &old); err != nil {
		t.Fatal(err)
	}
	lim := old
	lim.Cur = uint64(openFDs(t) + 16)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatal(err)
	}
	var fill []*os.File
	for {
		f, err := os.Open(os.DevNull)
		if err != nil {
			break
		}
		fill = append(fill, f)
	}
	if len(fill) > 0 {
		fill[len(fill)-1].Close()
		fill = fill[:len(fill)-1]
		if c, err := net.DialTimeout("tcp4", addr, time.Second); err == nil {
			time.Sleep(300 * time.Millisecond)
			c.Close()
		}
	}
	for _, f := range fill {
		f.Close()
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &old); err != nil {
		t.Fatal(err)
	}
	if len(fill) == 0 {
		t.Fatal("no descriptors to fill")
	}
}

// A flood of idle connections from a host on the LAN brings the daemon to
// its limit of descriptors, and one accept4 fails with EMFILE. sipgo's loop
// (TransportTCP.Serve) returned on that error, and nobody accepted on the
// port again until the daemon restarted: the phones on TLS could not sign in
// again long after the flood had gone.
func TestLANTCPListenerSurvivesFDExhaustion(t *testing.T) {
	rig := newStreamRig(t)
	if err := register401("127.0.0.1", rig.tcpAddr, false); err != nil {
		t.Fatalf("before: %v", err)
	}
	failOneAccept(t, rig.tcpAddr)
	if err := register401("127.0.0.1", rig.tcpAddr, false); err != nil {
		t.Fatalf("after one EMFILE in accept the TCP listener is dead: %v", err)
	}
	if !strings.Contains(rig.log.String(), `level=ERROR msg="SIP: accept failed, trying again" transport=tcp`) {
		t.Fatalf("the failed accept is not in the log:\n%s", rig.log.String())
	}
}

// The same for the TLS port, where the phones set up by QR code are.
func TestLANTLSListenerSurvivesFDExhaustion(t *testing.T) {
	rig := newStreamRig(t)
	if err := register401("127.0.0.1", rig.tlsAddr, true); err != nil {
		t.Fatalf("before: %v", err)
	}
	failOneAccept(t, rig.tlsAddr)
	if err := register401("127.0.0.1", rig.tlsAddr, true); err != nil {
		t.Fatalf("after one EMFILE in accept the TLS listener is dead: %v", err)
	}
	if !strings.Contains(rig.log.String(), `level=ERROR msg="SIP: accept failed, trying again" transport=tls`) {
		t.Fatalf("the failed accept is not in the log:\n%s", rig.log.String())
	}
}

// One address may hold so many connections, TCP and TLS together; one more
// is closed at once, and the refusals take one line in the log.
func TestLANConnLimitPerAddress(t *testing.T) {
	rig := newStreamRig(t)
	setConnLimits(rig.lan, 100, 3, 0, time.Hour)
	var held []net.Conn
	for i, addr := range []string{rig.tcpAddr, rig.tlsAddr, rig.tcpAddr} {
		held = append(held, dialFrom(t, "127.0.0.1", addr))
		waitConnsFrom(t, rig.lan, "127.0.0.1", i+1)
	}
	for i := 0; i < 4; i++ {
		addr := rig.tcpAddr
		if i%2 == 1 {
			addr = rig.tlsAddr
		}
		if !closedOnConnect(t, "127.0.0.1", addr) {
			t.Fatalf("connection %d from one address stayed open, the limit is 3", 4+i)
		}
	}
	if err := register401("127.0.0.2", rig.tcpAddr, false); err != nil {
		t.Fatalf("another address while the first one is at its limit: %v", err)
	}
	held[0].Close()
	waitConnsFrom(t, rig.lan, "127.0.0.1", 2)
	if err := register401("127.0.0.1", rig.tlsAddr, true); err != nil {
		t.Fatalf("the address after one of its connections closed: %v", err)
	}
	if n := strings.Count(rig.log.String(), `msg="SIP: connection refused, too many from one address"`); n != 1 {
		t.Fatalf("%d log lines for 4 refusals in a row, want 1:\n%s", n, rig.log.String())
	}
}

// The connections in all have a limit, and its last places are kept for the
// addresses a phone has signed in from: strangers cannot fill them.
func TestLANConnLimitInAll(t *testing.T) {
	rig := newStreamRig(t)
	setConnLimits(rig.lan, 4, 8, 1, time.Hour) // 4 in all, the last one kept
	phone := dialRawT(t, "127.0.0.9", rig.tlsAddr, true)
	if err := phone.signIn(); err != nil {
		t.Fatal(err)
	}
	a := dialFrom(t, "127.0.0.2", rig.tcpAddr)
	b := dialFrom(t, "127.0.0.3", rig.tlsAddr)
	waitConnsOpen(t, rig.lan, 3)
	if !closedOnConnect(t, "127.0.0.4", rig.tcpAddr) {
		t.Fatal("a stranger took the place kept for the phones")
	}
	again := dialRawT(t, "127.0.0.9", rig.tcpAddr, false)
	if head, err := again.do("REGISTER", ""); err != nil || !strings.HasPrefix(head, "SIP/2.0 401") {
		t.Fatalf("the phone's address did not get the kept place: %.40q %v", head, err)
	}
	waitConnsOpen(t, rig.lan, 4)
	if !closedOnConnect(t, "127.0.0.9", rig.tlsAddr) {
		t.Fatal("a fifth connection stayed open, the limit is 4")
	}
	a.Close()
	b.Close()
	waitConnsOpen(t, rig.lan, 2)
	if err := register401("127.0.0.4", rig.tcpAddr, false); err != nil {
		t.Fatalf("a stranger once places are free again: %v", err)
	}
	if head, err := phone.do("OPTIONS", ""); err != nil || !strings.HasPrefix(head, "SIP/2.0 200") {
		t.Fatalf("the phone's first connection: %.40q %v", head, err)
	}
}

// A connection nobody signs in on is closed after the sign-in limit, on the
// TCP port and on the TLS port before any handshake.
func TestLANUnsignedConnectionClosed(t *testing.T) {
	rig := newStreamRig(t)
	setConnLimits(rig.lan, 128, 8, 32, 200*time.Millisecond)
	conns := map[string]net.Conn{
		"TCP":                    dialFrom(t, "127.0.0.1", rig.tcpAddr),
		"TLS port, no handshake": dialFrom(t, "127.0.0.2", rig.tlsAddr),
	}
	for name, c := range conns {
		if !waitClosed(c, 10*time.Second) {
			t.Errorf("%s: a silent connection stayed open 10 s, the sign-in limit is 200 ms", name)
		}
	}
	waitConnsOpen(t, rig.lan, 0)
	if n := strings.Count(rig.log.String(), `msg="SIP: connection closed, nobody signed in on it"`); n != 1 {
		t.Fatalf("%d log lines for 2 closed connections, want 1:\n%s", n, rig.log.String())
	}
}

// A phone signed in on a TLS connection keeps it however long it is silent
// (an iPhone in the background); a request without the password does not
// count as signing in.
func TestLANSignedInTLSConnectionStays(t *testing.T) {
	rig := newStreamRig(t)
	setConnLimits(rig.lan, 128, 8, 32, time.Hour) // the test runs the deadlines itself
	phone := dialRawT(t, "127.0.0.1", rig.tlsAddr, true)
	if err := phone.signIn(); err != nil {
		t.Fatal(err)
	}
	asked := dialRawT(t, "127.0.0.2", rig.tlsAddr, true)
	if head, err := asked.do("REGISTER", ""); err != nil || !strings.HasPrefix(head, "SIP/2.0 401") {
		t.Fatalf("REGISTER without the password: %.40q %v", head, err)
	}
	silent := dialFrom(t, "127.0.0.3", rig.tlsAddr)
	waitConnsOpen(t, rig.lan, 3)
	runSignInDeadlines(rig.lan)
	if !waitClosed(asked.c, 10*time.Second) {
		t.Fatal("a TLS connection with only a 401 on it stayed open after its sign-in limit")
	}
	if !waitClosed(silent, 10*time.Second) {
		t.Fatal("a silent connection stayed open after its sign-in limit")
	}
	if head, err := phone.do("OPTIONS", ""); err != nil || !strings.HasPrefix(head, "SIP/2.0 200") {
		t.Fatalf("the phone's signed-in TLS connection did not outlive the sign-in limit: %.40q %v", head, err)
	}
	waitConnsOpen(t, rig.lan, 1)
}

// If sipgo's accept loop ends anyway (the listening socket broke under it),
// the error is in the log and the port is served again.
func TestLANSIPListenerComesBack(t *testing.T) {
	rig := newStreamRig(t)
	for _, tc := range []struct {
		transport, addr string
		tls             bool
	}{{"tcp", rig.tcpAddr, false}, {"tls", rig.tlsAddr, true}} {
		breakListener(t, rig.lan, tc.transport)
		var err error
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
			if err = register401("127.0.0.1", tc.addr, tc.tls); err == nil {
				break
			}
		}
		if err != nil {
			t.Fatalf("%s: the port is not served 10 s after its socket broke: %v", tc.transport, err)
		}
		if want := `level=ERROR msg="SIP: the listener stopped, listening again" transport=` + tc.transport; !strings.Contains(rig.log.String(), want) {
			t.Fatalf("%s: no error in the log:\n%s", tc.transport, rig.log.String())
		}
	}
}

func TestAcceptPause(t *testing.T) {
	var got []time.Duration
	for d := time.Duration(0); len(got) < 10; {
		d = acceptPause(d)
		got = append(got, d)
	}
	want := []time.Duration{5, 10, 20, 40, 80, 160, 320, 640, 1000, 1000}
	for i := range want {
		if got[i] != want[i]*time.Millisecond {
			t.Fatalf("pauses %v, want 5 ms doubling up to 1 s", got)
		}
	}
}

func TestTemporaryAcceptError(t *testing.T) {
	accept := func(err error) error {
		return &net.OpError{Op: "accept", Net: "tcp4", Err: os.NewSyscallError("accept4", err)}
	}
	for _, tc := range []struct {
		err  error
		temp bool
	}{
		{accept(syscall.EMFILE), true},
		{accept(syscall.ENFILE), true},
		{accept(syscall.ECONNABORTED), true},
		{accept(syscall.ENOBUFS), true},
		{accept(syscall.ETIMEDOUT), true},
		{&net.OpError{Op: "accept", Net: "tcp4", Err: net.ErrClosed}, false},
		{accept(syscall.EBADF), false},
		{accept(syscall.EINVAL), false},
	} {
		if got := temporaryAcceptError(tc.err); got != tc.temp {
			t.Errorf("%v: temporary %v, want %v", tc.err, got, tc.temp)
		}
	}
}

// Access to lan_listener.go for the tests above.

// setConnLimits sets the limits of the server's TCP and TLS connections;
// the connections accepted from now on get them.
func setConnLimits(lan *lanSIP, max, perIP, reserve int, signIn time.Duration) {
	s := lan.conns
	s.mu.Lock()
	s.max, s.perIP, s.reserve, s.signIn = max, perIP, reserve, signIn
	s.mu.Unlock()
}

// runSignInDeadlines runs the sign-in deadline of every open connection now,
// as if the sign-in limit had passed for all of them.
func runSignInDeadlines(lan *lanSIP) {
	s := lan.conns
	s.mu.Lock()
	var all []*sipConn
	for _, c := range s.open {
		all = append(all, c)
	}
	s.mu.Unlock()
	for _, c := range all {
		c.expire()
	}
}

func waitConnsFrom(t *testing.T, lan *lanSIP, ip string, n int) {
	t.Helper()
	s := lan.conns
	var got int
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		s.mu.Lock()
		got = s.byIP[ip]
		s.mu.Unlock()
		if got == n {
			return
		}
	}
	t.Fatalf("connections from %s: %d, want %d", ip, got, n)
}

func waitConnsOpen(t *testing.T, lan *lanSIP, n int) {
	t.Helper()
	s := lan.conns
	var got int
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		s.mu.Lock()
		got = s.total
		s.mu.Unlock()
		if got == n {
			return
		}
	}
	t.Fatalf("open connections: %d, want %d", got, n)
}

// breakListener closes the listening socket of a transport under sipgo's
// loop, as a socket that fails for good would end it.
func breakListener(t *testing.T, lan *lanSIP, transport string) {
	t.Helper()
	for _, c := range lan.closers {
		if st, ok := c.(*sipStream); ok && st.transport == transport {
			st.mu.Lock()
			st.retry = 20 * time.Millisecond
			ln := st.ln
			st.mu.Unlock()
			_ = ln.Listener.Close()
			return
		}
	}
	t.Fatalf("no %s listener", transport)
}
