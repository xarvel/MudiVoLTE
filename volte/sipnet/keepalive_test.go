//go:build linux

// TCP_KEEPIDLE is a Linux name; the daemon runs on the router, so the check
// is Linux only.

package sipnet

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

func keepAlive(t *testing.T, c *Conn) (on, idle int) {
	t.Helper()
	rc, err := c.nc.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.Control(func(fd uintptr) {
		on, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
		idle, _ = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE)
	}); err != nil {
		t.Fatal(err)
	}
	return on, idle
}

// A connection whose peer vanished without a FIN or RST must not look alive
// for hours: both sides of a protected connection keep TCP keep-alive on
// (Go enables it by default for dialed and accepted connections).
func TestKeepAliveIsOn(t *testing.T) {
	l, err := Listen(netip.MustParseAddrPort("127.0.0.1:0"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := Dial(context.Background(), netip.AddrPort{}, l.Addr(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var accepted *Conn
	for deadline := time.Now().Add(2 * time.Second); accepted == nil && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		l.mu.Lock()
		for a := range l.conns {
			accepted = a
		}
		l.mu.Unlock()
	}
	if accepted == nil {
		t.Fatal("connection not accepted")
	}
	for name, conn := range map[string]*Conn{"dialed": c, "accepted": accepted} {
		if on, idle := keepAlive(t, conn); on != 1 || idle <= 0 || idle > 60 {
			t.Errorf("%s connection: SO_KEEPALIVE=%d, TCP_KEEPIDLE=%d s", name, on, idle)
		}
	}
}
