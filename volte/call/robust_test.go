package call

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	stdnet "net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/reg"
	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// bareReg is as much of a registration as Manager.Handle needs.
type bareReg struct{}

func (bareReg) Conn() *sipnet.Conn           { return nil }
func (bareReg) ContactURI() string           { return "sip:ue@127.0.0.1:5060;transport=tcp" }
func (bareReg) SentBy() string               { return "127.0.0.1:5060" }
func (bareReg) IMPU() string                 { return impu }
func (bareReg) Binding() (reg.Binding, bool) { return reg.Binding{}, true }

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const inviteWithoutCallID = "INVITE sip:ue@127.0.0.1:5060 SIP/2.0\r\n" +
	"Via: SIP/2.0/TCP 127.0.0.2:5060;branch=z9hG4bKnocallid\r\n" +
	"From: <sip:+447700900002@ims.test>;tag=a\r\n" +
	"To: <sip:ue@ims.test>\r\n" +
	"CSeq: 1 INVITE\r\n" +
	"Content-Length: 0\r\n\r\n"

const optionsRequest = "OPTIONS sip:ue@127.0.0.1:5060 SIP/2.0\r\n" +
	"Via: SIP/2.0/TCP 127.0.0.2:5060;branch=z9hG4bKoptions\r\n" +
	"From: <sip:+447700900002@ims.test>;tag=b\r\n" +
	"To: <sip:ue@ims.test>\r\n" +
	"Call-ID: options-after\r\n" +
	"CSeq: 1 OPTIONS\r\n" +
	"Content-Length: 0\r\n\r\n"

// statusLine reads one response and returns its status line.
func statusLine(in *bufio.Reader) (string, error) {
	first := ""
	for {
		line, err := in.ReadString('\n')
		if err != nil {
			return first, err
		}
		if first == "" {
			first = strings.TrimSpace(line)
		}
		if line == "\r\n" {
			return first, nil
		}
	}
}

// An INVITE without Call-ID reached incoming(), which called
// req.CallID().Value() on the missing header, on the read loop: the whole
// mudi-imsd process died. The child process plays the UE with the real
// Manager behind a real sipnet listener; the parent checks how it ended and
// what the network side heard: a 400 for the INVITE, then a 200 for an
// OPTIONS on the same connection.
func TestInviteWithoutCallIDIsRefused(t *testing.T) {
	if os.Getenv("CALL_CHILD") == "1" {
		m := NewManager(bareReg{}, Config{Log: quietLog()})
		ln, err := sipnet.Listen(netip.MustParseAddrPort("127.0.0.1:0"), m.Handle, quietLog())
		if err != nil {
			os.Exit(2)
		}
		c, err := stdnet.Dial("tcp", ln.Addr().String())
		if err != nil {
			os.Exit(2)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		in := bufio.NewReader(c)
		for _, msg := range []string{inviteWithoutCallID, optionsRequest} {
			if _, err := c.Write([]byte(msg)); err != nil {
				os.Exit(2)
			}
			line, err := statusLine(in)
			fmt.Printf("status: %s\n", line)
			if err != nil {
				os.Exit(2)
			}
		}
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInviteWithoutCallIDIsRefused$")
	cmd.Env = append(os.Environ(), "CALL_CHILD=1")
	out, err := cmd.CombinedOutput()
	s := string(out)
	if i := strings.Index(s, "panic:"); i >= 0 {
		line := s[i:]
		if j := strings.IndexByte(line, '\n'); j > 0 {
			line = line[:j]
		}
		t.Fatalf("an INVITE without Call-ID crashed the process: %s", line)
	}
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	for _, want := range []string{"status: SIP/2.0 400 Missing Call-ID header field", "status: SIP/2.0 200 OK"} {
		if !strings.Contains(s, want) {
			t.Errorf("no %q in\n%s", want, s)
		}
	}
}

// Handle does not rely on sipnet for that: given such a request directly, it
// answers 400 as well instead of dereferencing the missing header.
func TestHandleInviteWithoutCallID(t *testing.T) {
	ln, err := stdnet.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := sipnet.Dial(ctx, netip.AddrPort{}, netip.MustParseAddrPort(ln.Addr().String()), nil, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	raw, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	msg, err := sip.ParseMessage([]byte(inviteWithoutCallID))
	if err != nil {
		t.Fatal(err)
	}
	NewManager(bareReg{}, Config{Log: quietLog()}).Handle(conn, msg.(*sip.Request))
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	if line, err := statusLine(bufio.NewReader(raw)); line != "SIP/2.0 400 Missing Call-ID header field" {
		t.Fatalf("got %q (%v)", line, err)
	}
}
