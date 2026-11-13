package sipnet

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

func TestSplitFrame(t *testing.T) {
	msg := "SIP/2.0 200 OK\r\nCall-ID: a\r\nl: 4\r\n\r\nbody"
	in := []byte("\r\n\r\n" + msg + "INVITE")
	frame, n, crlfs, err := splitFrame(in)
	if err != nil || string(frame) != msg || n != 4+len(msg) || crlfs != 2 {
		t.Fatalf("frame=%q n=%d crlfs=%d err=%v", frame, n, crlfs, err)
	}
	if _, _, _, err := splitFrame(in[n:]); !errors.Is(err, errNeedMore) {
		t.Fatalf("partial: %v", err)
	}
	if _, _, _, err := splitFrame([]byte(msg[:len(msg)-2])); !errors.Is(err, errNeedMore) {
		t.Fatalf("short body: %v", err)
	}
	if _, _, _, err := splitFrame([]byte("SIP/2.0 200 OK\r\nCall-ID: a\r\n\r\n")); err == nil || errors.Is(err, errNeedMore) {
		t.Fatalf("missing Content-Length accepted: %v", err)
	}
}

func TestRequestBytesAndBranch(t *testing.T) {
	r := NewRequest("OPTIONS", "sip:x").Add("Via", "SIP/2.0/TCP 1.2.3.4:5;branch=z9hG4bKabc;rport").Add("Content-Length", "99")
	r.Set("Max-Forwards", "70")
	if r.Branch() != "z9hG4bKabc" {
		t.Fatal(r.Branch())
	}
	want := "OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/TCP 1.2.3.4:5;branch=z9hG4bKabc;rport\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n"
	if string(r.Bytes()) != want {
		t.Fatalf("%q", r.Bytes())
	}
}

// Two messages in one read must both arrive intact.
func TestConnTwoMessagesInOneRead(t *testing.T) {
	a, b := netPipe(t)
	got := make(chan string, 2)
	c := newConn(b, func(_ *Conn, r *sip.Request) { got <- r.CallID().Value() }, nil)
	defer c.Close()
	m1 := "OPTIONS sip:x SIP/2.0\r\nVia: SIP/2.0/TCP h;branch=z9hG4bK1\r\nFrom: <sip:a@h>;tag=1\r\nTo: <sip:x@h>\r\nCall-ID: first-call-with-a-long-id\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
	m2 := "OPTIONS sip:y SIP/2.0\r\nVia: SIP/2.0/TCP h;branch=z9hG4bK2\r\nFrom: <sip:a@h>;tag=1\r\nTo: <sip:y@h>\r\nCall-ID: second\r\nCSeq: 2 OPTIONS\r\nContent-Length: 0\r\n\r\n"
	if _, err := a.Write([]byte(m1 + m2)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"first-call-with-a-long-id", "second"} {
		select {
		case id := <-got:
			if id != want {
				t.Fatalf("got %q, want %q", id, want)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("missing %s", want)
		}
	}
}

func netPipe(t *testing.T) (net.Conn, net.Conn) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}
