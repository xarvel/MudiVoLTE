package call

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/reg"
	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

const impu = "sip:001010000000001@ims.mnc001.mcc001.3gppnetwork.org"

// net is a fake P-CSCF: it accepts the UE client connection on "port-s" and
// opens its own connection to the UE server port, like the tested network does.
type net struct {
	t       *testing.T
	ps      *sipnet.Listener // network protected server port
	ue      *sipnet.Listener // UE protected server port (served by Manager)
	toUE    *sipnet.Conn     // network → UE
	fromUE  chan inReq
	ueConn  *sipnet.Conn // UE → network
	m       *Manager
	states  chan State
	incomin chan *Call
}

type inReq struct {
	conn *sipnet.Conn
	req  *sip.Request
}

type fakeReg struct{ n *net }

func (f fakeReg) Conn() *sipnet.Conn { return f.n.ueConn }
func (f fakeReg) ContactURI() string {
	return "sip:001010000000001@" + f.n.ue.Addr().String() + ";transport=tcp"
}
func (f fakeReg) SentBy() string { return f.n.ue.Addr().String() }
func (f fakeReg) IMPU() string   { return impu }
func (f fakeReg) Binding() (reg.Binding, bool) {
	return reg.Binding{Routes: []string{"<sip:orig@scscf.test;lr>"}}, true
}

func newNet(t *testing.T) *net {
	n := &net{t: t, fromUE: make(chan inReq, 16), states: make(chan State, 32), incomin: make(chan *Call, 4)}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	n.m = NewManager(fakeReg{n}, Config{PANI: "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=0010100010000001", Log: log})
	n.m.OnState = func(_ *Call, s State) { n.states <- s }
	n.m.OnIncoming = func(c *Call) { n.incomin <- c }
	var err error
	lo := netip.MustParseAddrPort("127.0.0.1:0")
	if n.ps, err = sipnet.Listen(lo, func(c *sipnet.Conn, r *sip.Request) { n.fromUE <- inReq{c, r} }, nil); err != nil {
		t.Fatal(err)
	}
	if n.ue, err = sipnet.Listen(lo, n.m.Handle, nil); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if n.ueConn, err = sipnet.Dial(ctx, netip.AddrPort{}, n.ps.Addr(), n.m.Handle, nil); err != nil {
		t.Fatal(err)
	}
	if n.toUE, err = sipnet.Dial(ctx, netip.AddrPort{}, n.ue.Addr(), nil, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.toUE.Close(); n.ueConn.Close(); n.ps.Close(); n.ue.Close() })
	return n
}

func (n *net) waitState(want State) {
	n.t.Helper()
	for {
		select {
		case s := <-n.states:
			if s == want {
				return
			}
		case <-time.After(3 * time.Second):
			n.t.Fatalf("timeout waiting for state %v", want)
		}
	}
}

func (n *net) recv(method sip.RequestMethod) inReq {
	n.t.Helper()
	select {
	case r := <-n.fromUE:
		if r.req.Method != method {
			n.t.Fatalf("got %s, want %s:\n%s", r.req.Method, method, r.req)
		}
		return r
	case <-time.After(3 * time.Second):
		n.t.Fatalf("timeout waiting for %s from UE", method)
	}
	return inReq{}
}

// invite builds a terminating INVITE shaped like a live one.
func (n *net) invite(callID, extra string, sdp []byte) *sipnet.Request {
	r := sipnet.NewRequest("INVITE", "sip:UE@"+n.ue.Addr().String()+";transport=tcp").
		Add("Via", "SIP/2.0/TCP 127.0.0.1:9900;branch="+sipnet.NewBranch()).
		Add("Record-Route", "<sip:127.0.0.1:9900;transport=tcp;lr>").
		Add("Call-ID", callID).
		Add("From", "<tel:+447700900002;noa=international>;tag=net").
		Add("To", "<tel:447700900001>").
		Add("CSeq", "1 INVITE").
		Add("Contact", "<sip:127.0.0.1:9900;Dsp=x>").
		Add("Supported", "timer,100rel").
		Add("P-Asserted-Identity", "<tel:+447700900002>").
		Add("Content-Type", "application/sdp")
	if extra != "" {
		k, v, _ := strings.Cut(extra, ": ")
		r.Add(k, v)
	}
	r.Body = sdp
	return r
}

func liveOffer(t *testing.T) []byte {
	b, err := os.ReadFile("testdata/live_offer.sdp")
	if err != nil {
		t.Fatal(err)
	}
	return []byte(strings.ReplaceAll(string(b), "\n", "\r\n"))
}

type collected struct {
	mu  sync.Mutex
	got []*sip.Response
}

func (c *collected) add(r *sip.Response) { c.mu.Lock(); c.got = append(c.got, r); c.mu.Unlock() }
func (c *collected) codes() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []int
	for _, r := range c.got {
		out = append(out, r.StatusCode)
	}
	return out
}

func inDialogReq(method, callID, toTag string, seq string) *sipnet.Request {
	return sipnet.NewRequest(method, "sip:UE@x").
		Add("Via", "SIP/2.0/TCP 127.0.0.1:9900;branch="+sipnet.NewBranch()).
		Add("Call-ID", callID).
		Add("From", "<tel:+447700900002>;tag=net").
		Add("To", "<tel:447700900001>;tag="+toTag).
		Add("CSeq", seq+" "+method)
}

func TestInboundAnswerRefreshBye(t *testing.T) {
	n := newNet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	prov := &collected{}
	finalCh := make(chan *sip.Response, 1)
	go func() {
		res, err := n.toUE.Do(ctx, n.invite("in1", "", liveOffer(t)), prov.add)
		if err != nil {
			t.Error(err)
		}
		finalCh <- res
	}()
	c := <-n.incomin
	if c.RemoteNumber() != "+447700900002" {
		t.Errorf("remote number %q", c.RemoteNumber())
	}
	if err := c.Ring(); err != nil {
		t.Fatal(err)
	}
	local := netip.MustParseAddrPort("127.0.0.1:40000")
	if err := c.Answer(local); err != nil {
		t.Fatal(err)
	}
	res := <-finalCh
	if res == nil || res.StatusCode != 200 {
		t.Fatalf("final %v", res)
	}
	if got := prov.codes(); len(got) != 2 || got[0] != 100 || got[1] != 180 {
		t.Errorf("provisionals %v", got)
	}
	tag := toTag(res)
	ans, err := ParseSDP(res.Body())
	if err != nil || ans.Formats[0].PT != 101 || ans.Addr != local || len(res.GetHeaders("Record-Route")) == 0 {
		t.Fatalf("answer %+v %v\n%s", ans, err, res)
	}
	if err := n.toUE.SendRequest(inDialogReq("ACK", "in1", tag, "1")); err != nil {
		t.Fatal(err)
	}
	n.waitState(StateActive)
	if neg, _, ok := c.Media(); !ok || neg.Remote != netip.MustParseAddrPort("192.0.2.82:26390") || neg.DTMF == nil {
		t.Fatalf("media %+v", neg)
	}

	// Session refresh re-INVITE with an unchanged offer keeps the SDP version.
	re := inDialogReq("INVITE", "in1", tag, "2").Add("Content-Type", "application/sdp")
	re.Body = liveOffer(t)
	r2, err := n.toUE.Do(ctx, re, nil)
	if err != nil || r2.StatusCode != 200 || !strings.Contains(string(r2.Body()), " 1 IN IP4 127.0.0.1") {
		t.Fatalf("re-INVITE: %v %v\n%s", r2, err, r2.Body())
	}
	_ = n.toUE.SendRequest(inDialogReq("ACK", "in1", tag, "2"))

	bye := inDialogReq("BYE", "in1", tag, "3").Add("Reason", `Q.850;cause=16;text="Normal call clearing"`)
	if r3, err := n.toUE.Do(ctx, bye, nil); err != nil || r3.StatusCode != 200 {
		t.Fatalf("BYE: %v %v", r3, err)
	}
	n.waitState(StateEnded)
	if _, cause := c.State(); !strings.Contains(cause, "cause=16") {
		t.Errorf("cause %q", cause)
	}
	if len(n.m.Calls()) != 0 {
		t.Error("call not forgotten")
	}
}

func TestInboundLocalHangup(t *testing.T) {
	n := newNet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	finalCh := make(chan *sip.Response, 1)
	go func() { res, _ := n.toUE.Do(ctx, n.invite("in2", "", liveOffer(t)), nil); finalCh <- res }()
	c := <-n.incomin
	_ = c.Answer(netip.MustParseAddrPort("127.0.0.1:40002"))
	res := <-finalCh
	_ = n.toUE.SendRequest(inDialogReq("ACK", "in2", toTag(res), "1"))
	n.waitState(StateActive)

	done := make(chan error, 1)
	go func() { done <- c.Hangup() }()
	bye := n.recv(sip.BYE)
	if got := bye.req.Recipient.Host; got != "127.0.0.1" || headerValue(bye.req, "Route") != "<sip:127.0.0.1:9900;transport=tcp;lr>" {
		t.Errorf("BYE target %s route %q", bye.req.Recipient.String(), headerValue(bye.req, "Route"))
	}
	if toTag(bye.req) != "net" || fromTag(bye.req) != toTag(res) {
		t.Errorf("BYE tags from=%s to=%s", fromTag(bye.req), toTag(bye.req))
	}
	_ = bye.conn.Respond(bye.req, 200, "OK")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	n.waitState(StateEnded)
}

func TestInboundReliableRinging(t *testing.T) {
	n := newNet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ringing := make(chan *sip.Response, 8)
	go func() {
		_, _ = n.toUE.Do(ctx, n.invite("in3", "Require: 100rel", liveOffer(t)), func(r *sip.Response) {
			if r.StatusCode == 180 {
				ringing <- r
			}
		})
	}()
	c := <-n.incomin
	_ = c.Ring()
	r180 := <-ringing
	rseq := headerValue(r180, "RSeq")
	if rseq == "" || !hasTag(optionTags(r180, "Require"), "100rel") {
		t.Fatalf("180 not reliable:\n%s", r180)
	}
	// Without PRACK the 180 is retransmitted after T1.
	select {
	case <-ringing:
	case <-time.After(3 * T1):
		t.Fatal("no 180 retransmission")
	}
	prack := inDialogReq("PRACK", "in3", toTag(r180), "2").Add("RAck", rseq+" 1 INVITE")
	if res, err := n.toUE.Do(ctx, prack, nil); err != nil || res.StatusCode != 200 {
		t.Fatalf("PRACK: %v %v", res, err)
	}
	for len(ringing) > 0 {
		<-ringing
	}
	select {
	case <-ringing:
		t.Fatal("180 retransmitted after PRACK")
	case <-time.After(3 * T1):
	}
	_ = c.Reject(486, "Busy Here")
}

func TestInboundCancelAndRefusals(t *testing.T) {
	n := newNet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	inv := n.invite("in4", "", liveOffer(t))
	finalCh := make(chan *sip.Response, 1)
	go func() { res, _ := n.toUE.Do(ctx, inv, nil); finalCh <- res }()
	<-n.incomin
	cn := sipnet.NewRequest("CANCEL", inv.URI).Add("Via", inv.Get("Via")).Add("Call-ID", "in4").
		Add("From", inv.Get("From")).Add("To", inv.Get("To")).Add("CSeq", "1 CANCEL")
	if res, err := n.toUE.Do(ctx, cn, nil); err != nil || res.StatusCode != 200 {
		t.Fatalf("CANCEL: %v %v", res, err)
	}
	if res := <-finalCh; res == nil || res.StatusCode != 487 {
		t.Fatalf("INVITE final %v", res)
	}
	n.waitState(StateEnded)

	g729 := []byte("v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 5004 RTP/AVP 18\r\na=rtpmap:18 G729/8000\r\n")
	if res, _ := n.toUE.Do(ctx, n.invite("in5", "", g729), nil); res == nil || res.StatusCode != 488 {
		t.Fatalf("no common codec: %v", res)
	}
	if res, _ := n.toUE.Do(ctx, n.invite("in6", "Require: precondition", liveOffer(t)), nil); res == nil || res.StatusCode != 420 ||
		headerValue(res, "Unsupported") != "precondition" {
		t.Fatalf("precondition: %v", res)
	}
}

// answerSDP is what the network answers to our offer.
const answerSDP = "v=0\r\no=- 1 1 IN IP4 192.0.2.82\r\ns=-\r\nc=IN IP4 192.0.2.82\r\nt=0 0\r\n" +
	"m=audio 30000 RTP/AVP 104 105\r\na=rtpmap:104 AMR-WB/16000\r\na=fmtp:104 mode-set=0,1,2\r\n" +
	"a=rtpmap:105 telephone-event/16000\r\na=ptime:20\r\na=sendrecv\r\n"

func respond(r inReq, code int, reason string, tag string, hdrs map[string]string, body string) {
	res := sip.NewResponseFromRequest(r.req, code, reason, nil)
	if tag != "" {
		res.To().Params.Add("tag", tag)
	}
	for k, v := range hdrs {
		res.AppendHeader(sip.NewHeader(k, v))
	}
	if body != "" {
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.SetBody([]byte(body))
	} else {
		res.SetBody(nil)
	}
	_ = r.conn.Send(res)
}

func TestOutboundCall(t *testing.T) {
	n := newNet(t)
	local := netip.MustParseAddrPort("127.0.0.1:41000")
	c, err := n.m.Dial("+447700900002", local)
	if err != nil {
		t.Fatal(err)
	}
	inv := n.recv(sip.INVITE)
	for h, want := range map[string]string{
		"Route":                "<sip:orig@scscf.test;lr>",
		"P-Preferred-Service":  "urn:urn-7:3gpp-service.ims.icsi.mmtel",
		"P-Preferred-Identity": "<" + impu + ">",
	} {
		if got := headerValue(inv.req, h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
	if inv.req.Recipient.String() != "tel:+447700900002" {
		t.Errorf("Request-URI %s", inv.req.Recipient.String())
	}
	offer, err := ParseSDP(inv.req.Body())
	if err != nil || offer.Formats[0].Name != "AMR-WB" || offer.Addr != local {
		t.Fatalf("offer %+v %v", offer, err)
	}
	dlg := map[string]string{"Contact": "<sip:127.0.0.1:9900;Dsp=y>", "Record-Route": "<sip:127.0.0.1:9900;lr>"}
	respond(inv, 100, "Trying", "", nil, "")
	rel := map[string]string{"Contact": dlg["Contact"], "Record-Route": dlg["Record-Route"], "Require": "100rel", "RSeq": "7"}
	respond(inv, 180, "Ringing", "callee", rel, "")
	n.waitState(StateRinging)
	prack := n.recv(sip.PRACK)
	if headerValue(prack.req, "RAck") != "7 1 INVITE" || toTag(prack.req) != "callee" ||
		headerValue(prack.req, "Route") != "<sip:127.0.0.1:9900;lr>" || prack.req.Recipient.String() != "sip:127.0.0.1:9900;Dsp=y" {
		t.Errorf("PRACK:\n%s", prack.req)
	}
	_ = prack.conn.Respond(prack.req, 200, "OK")
	respond(inv, 200, "OK", "callee", dlg, answerSDP)
	ack := n.recv(sip.ACK)
	if ack.req.CSeq().SeqNo != 1 || toTag(ack.req) != "callee" {
		t.Errorf("ACK:\n%s", ack.req)
	}
	n.waitState(StateActive)
	neg, _, ok := c.Media()
	if !ok || neg.Codec.PT != 104 || neg.Remote != netip.MustParseAddrPort("192.0.2.82:30000") || neg.DTMF == nil {
		t.Fatalf("media %+v", neg)
	}

	bye := inDialogReq("BYE", c.ID(), c.localTag, "5")
	if res, err := n.toUE.Do(context.Background(), bye, nil); err != nil || res.StatusCode != 200 {
		t.Fatalf("BYE: %v %v", res, err)
	}
	n.waitState(StateEnded)
}

func TestOutboundBusyAndCancel(t *testing.T) {
	n := newNet(t)
	c, err := n.m.Dial("tel:+447700900003", netip.MustParseAddrPort("127.0.0.1:41002"))
	if err != nil {
		t.Fatal(err)
	}
	inv := n.recv(sip.INVITE)
	respond(inv, 486, "Busy Here", "busy", nil, "")
	ack := n.recv(sip.ACK)
	if ack.req.Via().Params.GetOr("branch", "") != inv.req.Via().Params.GetOr("branch", "x") {
		t.Error("ACK for non-2xx must reuse the INVITE branch")
	}
	n.waitState(StateEnded)
	if _, cause := c.State(); cause != "486 Busy Here" {
		t.Errorf("cause %q", cause)
	}

	c2, _ := n.m.Dial("tel:+447700900004", netip.MustParseAddrPort("127.0.0.1:41004"))
	inv2 := n.recv(sip.INVITE)
	respond(inv2, 180, "Ringing", "r2", map[string]string{"Contact": "<sip:127.0.0.1:9900>"}, "")
	n.waitState(StateRinging)
	go func() { _ = c2.Hangup() }()
	cn := n.recv(sip.CANCEL)
	if cn.req.Via().Params.GetOr("branch", "") != inv2.req.Via().Params.GetOr("branch", "x") {
		t.Error("CANCEL must reuse the INVITE branch")
	}
	_ = cn.conn.Respond(cn.req, 200, "OK")
	respond(inv2, 487, "Request Terminated", "r2", nil, "")
	n.recv(sip.ACK)
	n.waitState(StateEnded)
	if _, cause := c2.State(); cause != "cancelled" {
		t.Errorf("cause %q", cause)
	}
}

// The callee answers just as we give up: the 200 that crosses our CANCEL is
// acknowledged and the call it made is ended with BYE.
func TestOutboundAnswerCrossesCancel(t *testing.T) {
	n := newNet(t)
	c, err := n.m.Dial("tel:+447700900005", netip.MustParseAddrPort("127.0.0.1:41006"))
	if err != nil {
		t.Fatal(err)
	}
	inv := n.recv(sip.INVITE)
	dlg := map[string]string{"Contact": "<sip:127.0.0.1:9900;Dsp=z>", "Record-Route": "<sip:127.0.0.1:9900;lr>"}
	respond(inv, 180, "Ringing", "late", dlg, "")
	n.waitState(StateRinging)
	go func() { _ = c.Hangup() }()
	cn := n.recv(sip.CANCEL)
	_ = cn.conn.Respond(cn.req, 200, "OK")
	respond(inv, 200, "OK", "late", dlg, answerSDP)
	if ack := n.recv(sip.ACK); toTag(ack.req) != "late" {
		t.Errorf("ACK:\n%s", ack.req)
	}
	bye := n.recv(sip.BYE)
	if toTag(bye.req) != "late" || bye.req.Recipient.String() != "sip:127.0.0.1:9900;Dsp=z" {
		t.Errorf("BYE:\n%s", bye.req)
	}
	_ = bye.conn.Respond(bye.req, 200, "OK")
	n.waitState(StateEnded)
	if _, cause := c.State(); cause != "cancelled" {
		t.Errorf("cause %q", cause)
	}
	if len(n.m.Calls()) != 0 {
		t.Error("call not forgotten")
	}
}

func TestNumber(t *testing.T) {
	for in, want := range map[string]string{
		"<tel:+447700;noa=international>":      "+447700",
		"<sip:+447700@ims.example;user=phone>": "+447700",
		"tel:07700":                            "07700",
	} {
		if got := Number(in); got != want {
			t.Errorf("Number(%q) = %q", in, got)
		}
	}
}
