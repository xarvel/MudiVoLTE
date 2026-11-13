package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/call"
	"github.com/xarvel/MudiVoLTE/volte/media"
	"github.com/xarvel/MudiVoLTE/volte/reg"
	"github.com/xarvel/MudiVoLTE/volte/sipnet"
	"github.com/xarvel/MudiVoLTE/volte/sms"
)

// regressionReg is a registration that holds: what calls need from reg.Client.
type regressionReg struct{}

func (regressionReg) Conn() *sipnet.Conn { return nil }
func (regressionReg) ContactURI() string { return "sip:u@127.0.0.1:5000;transport=tcp" }
func (regressionReg) SentBy() string     { return "127.0.0.1:5000" }
func (regressionReg) IMPU() string       { return "sip:u@d" }
func (regressionReg) Binding() (reg.Binding, bool) {
	return reg.Binding{Preferred: "sip:u@d"}, true
}

// newRegressionStack is newNetStack with the wiring of the daemon over a fake
// registration, and the connection the network uses towards the UE.
func newRegressionStack(t *testing.T) (*netStack, *sipnet.Conn) {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	cc := call.Config{Codecs: []string{"PCMA", "PCMU"}, Log: log}
	sc := sms.Config{Domain: "d", Log: log}
	st, err := newNetStack("", reg.Config{IMPI: "i@d", IMPU: "sip:u@d", Domain: "d",
		UEAddr: netip.MustParseAddr("127.0.0.1"), PCSCF: netip.MustParseAddrPort("127.0.0.1:5060"), Log: log},
		nil, cc, sc, log)
	if err != nil {
		t.Fatal(err)
	}
	st.calls = call.NewManager(regressionReg{}, cc)
	st.sms = sms.New(regressionReg{}, sc)
	st.calls.Other = st.sms.Handle
	st.calls.OnIncoming = st.handleIncoming
	st.calls.OnState = st.handleState
	ue, err := sipnet.Listen(netip.MustParseAddrPort("127.0.0.1:0"), st.calls.Handle, log)
	if err != nil {
		t.Fatal(err)
	}
	toUE, err := sipnet.Dial(context.Background(), netip.AddrPort{}, ue.Addr(), nil, log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { toUE.Close(); ue.Close() })
	return st, toUE
}

func regressionSDP(port, pt int, name string) []byte {
	return []byte(fmt.Sprintf("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"+
		"m=audio %d RTP/AVP %d\r\na=rtpmap:%d %s/8000\r\na=ptime:20\r\na=sendrecv\r\n", port, pt, pt, name))
}

func regressionInvite(callID, toTag string, seq int, sdp []byte) *sipnet.Request {
	to := "<sip:ue@net.test>"
	if toTag != "" {
		to += ";tag=" + toTag
	}
	r := sipnet.NewRequest("INVITE", "sip:u@127.0.0.1:5000;transport=tcp").
		Add("Via", "SIP/2.0/TCP 127.0.0.1:9900;branch="+sipnet.NewBranch()).
		Add("Call-ID", callID).
		Add("From", "<sip:peer@net.test>;tag=net").
		Add("To", to).
		Add("CSeq", fmt.Sprintf("%d INVITE", seq)).
		Add("Contact", "<sip:127.0.0.1:9900>").
		Add("Supported", "timer,100rel").
		Add("Content-Type", "application/sdp")
	r.Body = sdp
	return r
}

// An incoming call must alert the caller: 180 between the INVITE and the 200
// while the phones ring (the flow in docs/PROTOCOLS.md §4.2).
func TestRegressionIncomingSends180ToNetwork(t *testing.T) {
	st, toUE := newRegressionStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// What runIncoming can do with an imsCall: the phones ring, then one picks up.
	st.onIncoming = func(c *netCall, _ string) {
		if err := c.Ring(); err != nil {
			t.Error(err)
		}
		time.Sleep(50 * time.Millisecond)
		_ = c.Answer(ctx)
	}
	var mu sync.Mutex
	var codes []int
	res, err := toUE.Do(ctx, regressionInvite("rev-180", "", 1, regressionSDP(30000, 8, "PCMA")),
		func(p *sip.Response) { mu.Lock(); codes = append(codes, p.StatusCode); mu.Unlock() })
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	t.Logf("provisional responses before the %d: %v", res.StatusCode, codes)
	if !slices.Contains(codes, 180) {
		t.Errorf("the network got no 180 Ringing: %v", codes)
	}
}

// A re-INVITE that moves the call to another codec is answered with the new
// payload type, so the media must follow it.
func TestRegressionReinviteCodecReachesMedia(t *testing.T) {
	st, toUE := newRegressionStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	far, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer far.Close()
	farPort := far.LocalAddr().(*net.UDPAddr).Port

	calls := make(chan *netCall, 1)
	st.onIncoming = func(c *netCall, _ string) {
		_ = c.Answer(ctx)
		calls <- c
	}
	res, err := toUE.Do(ctx, regressionInvite("rev-pt", "", 1, regressionSDP(farPort, 8, "PCMA")), nil)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("INVITE: %v %v", err, res)
	}
	tag, _ := res.To().Params.Get("tag")
	ack := sipnet.NewRequest("ACK", "sip:u@127.0.0.1:5000").
		Add("Via", "SIP/2.0/TCP 127.0.0.1:9900;branch="+sipnet.NewBranch()).
		Add("Call-ID", "rev-pt").
		Add("From", "<sip:peer@net.test>;tag=net").
		Add("To", "<sip:ue@net.test>;tag="+tag).
		Add("CSeq", "1 ACK")
	if err := toUE.SendRequest(ack); err != nil {
		t.Fatal(err)
	}
	nc := <-calls
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	leg, err := newIMSLeg(nc, log) // bridgeAndWait builds it once, at the start of the call
	if err != nil {
		t.Fatal(err)
	}
	frames := make(chan []int16, 8)
	go leg.Run(ctx, func(pcm []int16) {
		select {
		case frames <- pcm:
		default:
		}
	})

	re, err := toUE.Do(ctx, regressionInvite("rev-pt", tag, 2, regressionSDP(farPort, 0, "PCMU")), nil)
	if err != nil || re.StatusCode != 200 {
		t.Fatalf("re-INVITE: %v %v", err, re)
	}
	if !strings.Contains(string(re.Body()), "RTP/AVP 0") {
		t.Fatalf("answer to the re-INVITE does not take PCMU:\n%s", re.Body())
	}
	t.Log("the re-INVITE negotiated PT", nc.Media().PayloadType)

	// The network sends what was agreed; the UE must decode it.
	ueRTP := nc.socket().LocalAddr().(*net.UDPAddr)
	pkt := media.Packet{PT: 0, Seq: 1, Timestamp: 160, SSRC: 1, Payload: make([]byte, 160)}.Marshal()
	for i := 0; i < 5; i++ {
		if _, err := far.WriteToUDP(pkt, ueRTP); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-frames:
	case <-time.After(700 * time.Millisecond):
		t.Errorf("no audio decoded from the agreed PT 0")
	}

	// And it must send what was agreed.
	if err := leg.WriteFrame(ctx, make([]int16, frameSamples16k)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	_ = far.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := far.ReadFromUDP(buf)
	if err != nil || n < 12 {
		t.Fatalf("no RTP from the UE: %v", err)
	}
	if pt := buf[1] & 0x7f; pt != 0 {
		t.Errorf("the UE sends PT %d after agreeing to PT 0", pt)
	}
}

// A request inside a dialog we do not know gets 481 (RFC 3261 §12.2.2): the
// answer that tells the network the dialog is gone. 405 keeps it alive
// (RFC 5057: a transaction-only failure).
func TestRegressionUnknownDialogGets481(t *testing.T) {
	_, toUE := newRegressionStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, m := range []string{"BYE", "UPDATE"} {
		r := sipnet.NewRequest(m, "sip:u@127.0.0.1:5000").
			Add("Via", "SIP/2.0/TCP 127.0.0.1:9900;branch="+sipnet.NewBranch()).
			Add("Call-ID", "gone-"+m).
			Add("From", "<sip:peer@net.test>;tag=net").
			Add("To", "<sip:ue@net.test>;tag=ours").
			Add("CSeq", "7 "+m)
		res, err := toUE.Do(ctx, r, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s for an unknown dialog: %d %s", m, res.StatusCode, res.Reason)
		if res.StatusCode != 481 {
			t.Errorf("%s for an unknown dialog: %d, want 481", m, res.StatusCode)
		}
	}
}

// A phone-to-phone call uses neither the network nor the SIM: the end of an
// IMS session (service.session) must not end it.
func TestRegressionIMSRestartKeepsInternalCall(t *testing.T) {
	for _, dir := range []string{"internal", "echo", "in", "out"} {
		t.Run(dir, func(t *testing.T) {
			m := newCallManager(&Config{}, SIPConfig{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
			lc, _ := m.acquire(dir)
			defer m.release(lc)
			m.networkDown()
			local := dir == "internal" || dir == "echo"
			if (lc.ctx.Err() == nil) != local {
				t.Fatalf("%s after IMS restart: %v", dir, lc.ctx.Err())
			}
			m.shutdown()
			if lc.ctx.Err() == nil {
				t.Fatal("daemon shutdown left a call running")
			}
		})
	}
}
