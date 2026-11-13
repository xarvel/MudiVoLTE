package reg_test

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/call"
	"github.com/xarvel/MudiVoLTE/volte/reg"
	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// A call runs through a re-registration. Whatever the network answers the
// re-REGISTER with, the Contact of the call stays, the network reaches it
// over the connection it has and over a new one, and our own requests leave
// over the SAs in use.
func TestCallThroughReregistration(t *testing.T) {
	for _, tc := range []struct {
		name      string
		network   func(*reg.FakeNetwork)
		registers int  // REGISTER requests the re-registration takes
		newConn   bool // whether our requests leave from another client port after it
	}{
		{"refreshed", func(*reg.FakeNetwork) {}, 1, false},
		{"re-authenticated", func(n *reg.FakeNetwork) { n.Challenge(true) }, 2, true},
		{"registered anew", func(n *reg.FakeNetwork) { n.Refuse(500) }, 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := reg.NewFakeNetwork(t)
			var m *call.Manager
			c := n.Client(t, func(conn *sipnet.Conn, req *sip.Request) { m.Handle(conn, req) })
			m = call.NewManager(c, call.Config{Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
			incoming, states := make(chan *call.Call, 1), make(chan call.State, 16)
			m.OnIncoming = func(cl *call.Call) { incoming <- cl }
			m.OnState = func(_ *call.Call, s call.State) { states <- s }
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := c.Register(ctx); err != nil {
				t.Fatal(err)
			}

			// The network calls on a connection of its own to our Contact.
			contact := c.ContactURI()
			nc := dialContact(t, contact)
			final := make(chan *sip.Response, 1)
			go func() {
				res, err := nc.Do(ctx, invite(t, contact), nil)
				if err != nil {
					t.Error(err)
				}
				final <- res
			}()
			var cl *call.Call
			select {
			case cl = <-incoming:
			case <-time.After(3 * time.Second):
				t.Fatal("no incoming call")
			}
			if err := cl.Answer(netip.MustParseAddrPort("127.0.0.1:40000")); err != nil {
				t.Fatal(err)
			}
			res := <-final
			if res == nil || res.StatusCode != 200 {
				t.Fatalf("answer %v", res)
			}
			tag, _ := res.To().Params.Get("tag")
			if err := nc.SendRequest(inDialog("ACK", tag, 1)); err != nil {
				t.Fatal(err)
			}
			waitState(t, states, call.StateActive)

			conn := c.Conn()
			before, _ := n.Registers()
			tc.network(n)
			if _, err := c.Refresh(ctx); err != nil {
				t.Fatal(err)
			}
			if after, _ := n.Registers(); after-before != tc.registers {
				t.Errorf("%d REGISTER requests, want %d", after-before, tc.registers)
			}
			if c.ContactURI() != contact || (c.Conn() != conn) != tc.newConn {
				t.Errorf("contact %s (was %s), connection replaced: %v", c.ContactURI(), contact, c.Conn() != conn)
			}

			// The network refreshes the session over the connection it has
			// (RFC 4028, UPDATE without SDP)…
			upd := inDialog("UPDATE", tag, 2).Add("Supported", "timer").Add("Session-Expires", "1800;refresher=uac")
			if r, err := nc.Do(ctx, upd, nil); err != nil || r.StatusCode != 200 {
				t.Fatalf("UPDATE of the network: %v %v", r, err)
			}
			// …and reaches the Contact over a new one.
			opt := sipnet.NewRequest("OPTIONS", contact).
				Add("Via", "SIP/2.0/TCP 127.0.0.1:9900;branch="+sipnet.NewBranch()).
				Add("From", "<tel:+447700900002>;tag=net2").Add("To", "<tel:447700900001>").
				Add("Call-ID", "probe").Add("CSeq", "1 OPTIONS")
			if r, err := dialContact(t, contact).Do(ctx, opt, nil); err != nil || r.StatusCode != 200 {
				t.Fatalf("OPTIONS of the network: %v %v", r, err)
			}

			// We hang up: the BYE leaves over the SAs in use.
			byes := make(chan *sip.Request, 1)
			n.OnRequest(func(conn *sipnet.Conn, req *sip.Request) {
				if req.Method == sip.BYE && conn.RemoteAddr() != c.Conn().LocalAddr() {
					t.Errorf("BYE from %s, the client port in use is %s", conn.RemoteAddr(), c.Conn().LocalAddr())
				}
				_ = conn.Respond(req, 200, "OK")
				byes <- req
			})
			if err := cl.Hangup(); err != nil {
				t.Fatal(err)
			}
			if req := <-byes; req.Method != sip.BYE {
				t.Errorf("%s instead of BYE", req.Method)
			}
			waitState(t, states, call.StateEnded)
		})
	}
}

func dialContact(t *testing.T, contact string) *sipnet.Conn {
	t.Helper()
	hp := strings.TrimPrefix(strings.Split(contact, ";")[0], "sip:")
	hp = hp[strings.Index(hp, "@")+1:]
	nc, err := sipnet.Dial(context.Background(), netip.AddrPort{}, netip.MustParseAddrPort(hp), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	return nc
}

// invite is a terminating INVITE the way the tested network sends it.
func invite(t *testing.T, contact string) *sipnet.Request {
	sdp, err := os.ReadFile("../call/testdata/live_offer.sdp")
	if err != nil {
		t.Fatal(err)
	}
	r := sipnet.NewRequest("INVITE", contact).
		Add("Via", "SIP/2.0/TCP 127.0.0.1:9900;branch="+sipnet.NewBranch()).
		Add("Record-Route", "<sip:127.0.0.1:9900;transport=tcp;lr>").
		Add("Call-ID", "through-rereg").
		Add("From", "<tel:+447700900002;noa=international>;tag=net").
		Add("To", "<tel:447700900001>").
		Add("CSeq", "1 INVITE").
		Add("Contact", "<sip:127.0.0.1:9900;Dsp=x>").
		Add("Supported", "timer,100rel").
		Add("P-Asserted-Identity", "<tel:+447700900002>").
		Add("Content-Type", "application/sdp")
	r.Body = []byte(strings.ReplaceAll(string(sdp), "\n", "\r\n"))
	return r
}

func inDialog(method, toTag string, seq int) *sipnet.Request {
	return sipnet.NewRequest(method, "sip:UE@x").
		Add("Via", "SIP/2.0/TCP 127.0.0.1:9900;branch="+sipnet.NewBranch()).
		Add("Call-ID", "through-rereg").
		Add("From", "<tel:+447700900002>;tag=net").
		Add("To", "<tel:447700900001>;tag="+toTag).
		Add("CSeq", strconv.Itoa(seq)+" "+method)
}

func waitState(t *testing.T, states <-chan call.State, want call.State) {
	t.Helper()
	for {
		select {
		case s := <-states:
			if s == want {
				return
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("no state %v", want)
		}
	}
}
