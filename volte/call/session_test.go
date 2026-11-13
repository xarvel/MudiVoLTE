package call

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// fastSession shrinks the session-timer clock for a test: an interval of 90
// takes 90·second.
func fastSession(t *testing.T, second time.Duration) {
	t.Helper()
	s, r, g := sessionSecond, refreshTimeout, glareDelay
	sessionSecond, refreshTimeout = second, 20*second
	glareDelay = func(bool) time.Duration { return 2 * second }
	t.Cleanup(func() { sessionSecond, refreshTimeout, glareDelay = s, r, g })
}

// answered sets up an inbound call in StateActive; hdr are name, value pairs
// added to the INVITE (Supported is replaced, the rest appended).
func (n *net) answered(callID string, hdr ...string) (*Call, *sip.Response) {
	n.t.Helper()
	inv := n.invite(callID, "", liveOffer(n.t))
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i] == "Supported" {
			inv.Set(hdr[i], hdr[i+1])
		} else {
			inv.Add(hdr[i], hdr[i+1])
		}
	}
	final := make(chan *sip.Response, 1)
	go func() { res, _ := n.toUE.Do(context.Background(), inv, nil); final <- res }()
	var c *Call
	select {
	case c = <-n.incomin:
	case <-time.After(3 * time.Second):
		n.t.Fatal("INVITE did not reach the application")
	}
	if err := c.Answer(netip.MustParseAddrPort("127.0.0.1:40100")); err != nil {
		n.t.Fatal(err)
	}
	res := <-final
	if res == nil || res.StatusCode != 200 {
		n.t.Fatalf("final %v", res)
	}
	_ = n.toUE.SendRequest(inDialogReq("ACK", callID, toTag(res), "1"))
	n.waitState(StateActive)
	return c, res
}

// next is the next request of the UE, whatever its method.
func (n *net) next() inReq {
	n.t.Helper()
	select {
	case r := <-n.fromUE:
		return r
	case <-time.After(3 * time.Second):
		n.t.Fatal("timeout waiting for a request from UE")
	}
	return inReq{}
}

// quiet fails when the UE sends anything within d.
func (n *net) quiet(d time.Duration) {
	n.t.Helper()
	select {
	case r := <-n.fromUE:
		n.t.Fatalf("unexpected %s from UE:\n%s", r.req.Method, r.req)
	case <-time.After(d):
	}
}

func timerOK(se string) map[string]string {
	return map[string]string{"Session-Expires": se, "Require": "timer"}
}

func TestSessionExpiresHeader(t *testing.T) {
	for _, tc := range []struct {
		line      string
		secs      int
		refresher string
		ok        bool
	}{
		{"Session-Expires: 1800", 1800, "", true},
		{"Session-Expires: 90;refresher=uac", 90, "uac", true},
		{"x: 120 ; Refresher = UAS", 120, "uas", true},
		{"Session-Expires: soon", 0, "", false},
		{"Supported: timer", 0, "", false},
	} {
		raw := "UPDATE sip:ue@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1;branch=z9hG4bKa\r\nFrom: <tel:1>;tag=a\r\n" +
			"To: <tel:2>;tag=b\r\nCall-ID: c\r\nCSeq: 2 UPDATE\r\n" + tc.line + "\r\nMin-SE: 600\r\nContent-Length: 0\r\n\r\n"
		m, err := sip.ParseMessage([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		secs, refresher, ok := sessionExpires(m)
		if secs != tc.secs || refresher != tc.refresher || ok != tc.ok {
			t.Errorf("%q: got %d %q %v", tc.line, secs, refresher, ok)
		}
		if minSE(m) != 600 {
			t.Errorf("%q: Min-SE %d", tc.line, minSE(m))
		}
	}
}

// The live INVITE names no refresher: the caller keeps the role, and when it
// stays silent we refresh the session ourselves instead of hanging up.
func TestSessionInboundPeerRefreshes(t *testing.T) {
	fastSession(t, 30*time.Millisecond) // interval 2.7 s: half 1.35 s, three quarters 2.025 s
	n := newNet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, res := n.answered("st1", "Session-Expires", "90", "Min-SE", "90")
	if got := headerValue(res, "Session-Expires"); got != "90;refresher=uac" {
		t.Errorf("200 Session-Expires %q", got)
	}
	if !hasTag(optionTags(res, "Require"), "timer") || !hasTag(optionTags(res, "Supported"), "timer") {
		t.Errorf("200 must require and support timer:\n%s", res)
	}
	tag := toTag(res)

	// The caller refreshes in time; our answer repeats the agreement.
	time.Sleep(500 * time.Millisecond)
	upd := inDialogReq("UPDATE", "st1", tag, "2").Add("Supported", "timer").Add("Session-Expires", "90;refresher=uac")
	start := time.Now()
	r2, err := n.toUE.Do(ctx, upd, nil)
	if err != nil || r2.StatusCode != 200 || headerValue(r2, "Session-Expires") != "90;refresher=uac" ||
		!hasTag(optionTags(r2, "Require"), "timer") {
		t.Fatalf("UPDATE answer: %v %v", r2, err)
	}

	// Then it stops: at three quarters of the new interval the refresh is ours.
	u := n.recv(sip.UPDATE)
	if d := time.Since(start); d < 1700*time.Millisecond || d > 2700*time.Millisecond {
		t.Errorf("our refresh after %v, want about 2.025s", d)
	}
	if headerValue(u.req, "Session-Expires") != "90;refresher=uac" || !hasTag(optionTags(u.req, "Supported"), "timer") ||
		headerValue(u.req, "Min-SE") != "90" || headerValue(u.req, "Contact") == "" || len(u.req.Body()) != 0 || toTag(u.req) != "net" {
		t.Errorf("refresh UPDATE:\n%s", u.req)
	}
	moved := timerOK("90;refresher=uac")
	moved["Contact"] = "<sip:127.0.0.1:9900;Dsp=moved>"
	respond(u, 200, "OK", "", moved, "")

	// The role is ours now: the next refresh comes at half the interval, to
	// the target the answer named.
	start = time.Now()
	u = n.recv(sip.UPDATE)
	if d := time.Since(start); d < 1150*time.Millisecond || d > 1900*time.Millisecond {
		t.Errorf("second refresh after %v, want about 1.35s", d)
	}
	if u.req.Recipient.String() != "sip:127.0.0.1:9900;Dsp=moved" {
		t.Errorf("refresh sent to %s", u.req.Recipient.String())
	}

	// A caller that no longer knows the call: we hang up.
	respond(u, 481, "Call/Transaction Does Not Exist", "", nil, "")
	bye := n.recv(sip.BYE)
	_ = bye.conn.Respond(bye.req, 200, "OK")
	n.waitState(StateEnded)
	if _, cause := c.State(); !strings.Contains(cause, "session refresh: 481") {
		t.Errorf("cause %q", cause)
	}
}

func TestSessionInboundWeRefresh(t *testing.T) {
	fastSession(t, 20*time.Millisecond)
	n := newNet(t)
	_, res := n.answered("st2", "Session-Expires", "90;refresher=uas")
	if headerValue(res, "Session-Expires") != "90;refresher=uas" || !hasTag(optionTags(res, "Require"), "timer") {
		t.Errorf("200:\n%s", res)
	}
	start := time.Now()
	u := n.recv(sip.UPDATE)
	if d := time.Since(start); d < 750*time.Millisecond {
		t.Errorf("refresh after %v, want about 0.9s", d)
	}
	// Glare, then an interval the peer finds too short: each is retried.
	respond(u, 491, "Request Pending", "", nil, "")
	u = n.recv(sip.UPDATE)
	respond(u, 422, "Session Interval Too Small", "", map[string]string{"Min-SE": "120"}, "")
	u = n.recv(sip.UPDATE)
	if headerValue(u.req, "Session-Expires") != "120;refresher=uac" || headerValue(u.req, "Min-SE") != "120" {
		t.Errorf("refresh after 422:\n%s", u.req)
	}
	// An answer without Session-Expires switches the timer off.
	respond(u, 200, "OK", "", nil, "")
	n.quiet(1500 * time.Millisecond)
}

func TestSessionInboundRoles(t *testing.T) {
	fastSession(t, 2*time.Millisecond) // interval 180 ms
	n := newNet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// No timer asked for: none in the answer, nothing to refresh.
	_, res := n.answered("st3")
	if headerValue(res, "Session-Expires") != "" || hasTag(optionTags(res, "Require"), "timer") {
		t.Errorf("200 without a timer:\n%s", res)
	}
	n.quiet(250 * time.Millisecond)
	bye := inDialogReq("BYE", "st3", toTag(res), "2")
	if r, err := n.toUE.Do(ctx, bye, nil); err != nil || r.StatusCode != 200 {
		t.Fatalf("BYE: %v %v", r, err)
	}
	n.waitState(StateEnded)

	// A caller that cannot refresh leaves the role to us, without Require.
	c, res := n.answered("st4", "Supported", "100rel", "Session-Expires", "90")
	if headerValue(res, "Session-Expires") != "90;refresher=uas" || hasTag(optionTags(res, "Require"), "timer") {
		t.Errorf("200 for a caller without timer support:\n%s", res)
	}
	u := n.recv(sip.UPDATE)
	respond(u, 200, "OK", "", timerOK("90;refresher=uac"), "")
	// Its UPDATE without Session-Expires ends the timer.
	if r, err := n.toUE.Do(ctx, inDialogReq("UPDATE", "st4", toTag(res), "2"), nil); err != nil || r.StatusCode != 200 ||
		headerValue(r, "Session-Expires") != "" {
		t.Fatalf("UPDATE without timer: %v %v", r, err)
	}
	n.quiet(250 * time.Millisecond)
	// One with an interval below the minimum is refused, in a call and at its start.
	small := inDialogReq("UPDATE", "st4", toTag(res), "3").Add("Session-Expires", "60")
	if r, err := n.toUE.Do(ctx, small, nil); err != nil || r.StatusCode != 422 || headerValue(r, "Min-SE") != "90" {
		t.Fatalf("UPDATE with a short interval: %v %v", r, err)
	}
	go func() { _ = c.Hangup() }()
	b := n.recv(sip.BYE)
	_ = b.conn.Respond(b.req, 200, "OK")
	n.waitState(StateEnded)
	inv := n.invite("st5", "", liveOffer(t)).Add("Session-Expires", "60")
	if r, err := n.toUE.Do(ctx, inv, nil); err != nil || r.StatusCode != 422 || headerValue(r, "Min-SE") != "90" {
		t.Fatalf("INVITE with a short interval: %v %v", r, err)
	}

	// An UPDATE before the answer leaves the timer of the INVITE alone.
	inv = n.invite("st6", "", liveOffer(t)).Add("Session-Expires", "90")
	final := make(chan *sip.Response, 1)
	go func() { r, _ := n.toUE.Do(ctx, inv, nil); final <- r }()
	c = <-n.incomin
	if r, err := n.toUE.Do(ctx, inDialogReq("UPDATE", "st6", c.localTag, "2"), nil); err != nil || r.StatusCode != 200 ||
		headerValue(r, "Session-Expires") != "" {
		t.Fatalf("early UPDATE: %v %v", r, err)
	}
	_ = c.Answer(netip.MustParseAddrPort("127.0.0.1:40102"))
	if r := <-final; r == nil || headerValue(r, "Session-Expires") != "90;refresher=uac" {
		t.Fatalf("200 after an early UPDATE: %v", r)
	}
	_ = n.toUE.SendRequest(inDialogReq("ACK", "st6", c.localTag, "1"))
	n.waitState(StateActive)
	if r, err := n.toUE.Do(ctx, inDialogReq("BYE", "st6", c.localTag, "3"), nil); err != nil || r.StatusCode != 200 {
		t.Fatalf("BYE: %v %v", r, err)
	}
	n.waitState(StateEnded)
}

func TestSessionOutbound(t *testing.T) {
	fastSession(t, 5*time.Millisecond) // interval 450 ms, refresh timeout 100 ms
	n := newNet(t)
	c, err := n.m.Dial("+447700900002", netip.MustParseAddrPort("127.0.0.1:41100"))
	if err != nil {
		t.Fatal(err)
	}
	inv := n.recv(sip.INVITE)
	if headerValue(inv.req, "Session-Expires") != "1800" || !hasTag(optionTags(inv.req, "Supported"), "timer") ||
		headerValue(inv.req, "Min-SE") != "" {
		t.Errorf("INVITE:\n%s", inv.req)
	}

	// A far side that wants a longer interval: the INVITE is sent again.
	respond(inv, 422, "Session Interval Too Small", "x", map[string]string{"Min-SE": "3600"}, "")
	ack := n.recv(sip.ACK)
	if ack.req.CSeq().SeqNo != 1 || ack.req.Via().Params.GetOr("branch", "") != inv.req.Via().Params.GetOr("branch", "x") {
		t.Errorf("ACK for 422:\n%s", ack.req)
	}
	inv2 := n.recv(sip.INVITE)
	if inv2.req.CSeq().SeqNo != 2 || headerValue(inv2.req, "Session-Expires") != "3600" || headerValue(inv2.req, "Min-SE") != "3600" ||
		inv2.req.CallID().Value() != c.ID() || fromTag(inv2.req) != fromTag(inv.req) || toTag(inv2.req) != "" ||
		headerValue(inv2.req, "Route") != "<sip:orig@scscf.test;lr>" || inv2.req.Recipient.String() != "tel:+447700900002" {
		t.Errorf("second INVITE:\n%s", inv2.req)
	}
	dlg := map[string]string{"Contact": "<sip:127.0.0.1:9900;Dsp=y>", "Record-Route": "<sip:127.0.0.1:9900;lr>",
		"Session-Expires": "90;refresher=uac", "Require": "timer"}
	respond(inv2, 200, "OK", "callee", dlg, answerSDP)
	if ack = n.recv(sip.ACK); ack.req.CSeq().SeqNo != 2 || toTag(ack.req) != "callee" {
		t.Errorf("ACK:\n%s", ack.req)
	}
	n.waitState(StateActive)

	// We refresh at half the interval; the far side then takes the role over.
	start := time.Now()
	u := n.recv(sip.UPDATE)
	if d := time.Since(start); d < 180*time.Millisecond {
		t.Errorf("refresh after %v, want about 225ms", d)
	}
	if u.req.CSeq().SeqNo != 3 || headerValue(u.req, "Session-Expires") != "3600;refresher=uac" || headerValue(u.req, "Min-SE") != "3600" ||
		toTag(u.req) != "callee" || u.req.Recipient.String() != "sip:127.0.0.1:9900;Dsp=y" {
		t.Errorf("refresh UPDATE:\n%s", u.req)
	}
	respond(u, 200, "OK", "", timerOK("90;refresher=uas"), "")

	// It never does: our own refresh follows and stays unanswered, so the
	// call is over.
	n.recv(sip.UPDATE)
	bye := n.recv(sip.BYE)
	_ = bye.conn.Respond(bye.req, 200, "OK")
	n.waitState(StateEnded)
	if _, cause := c.State(); !strings.HasPrefix(cause, "session refresh: ") {
		t.Errorf("cause %q", cause)
	}
}

// The 2xx to an UPDATE without an offer has no SDP (RFC 3311 §5.2); a
// re-INVITE without one is answered with our offer (RFC 3261 §14.2). This is
// how a network refreshes the session.
func TestModifyWithoutOffer(t *testing.T) {
	n := newNet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, res := n.answered("mo1")
	tag := toTag(res)
	r, err := n.toUE.Do(ctx, inDialogReq("UPDATE", "mo1", tag, "2"), nil)
	if err != nil || r.StatusCode != 200 || len(r.Body()) != 0 || headerValue(r, "Content-Type") != "" {
		t.Fatalf("200 to an UPDATE without SDP: %v %v", r, err)
	}
	r, err = n.toUE.Do(ctx, inDialogReq("INVITE", "mo1", tag, "3"), nil)
	if err != nil || r.StatusCode != 200 || !strings.Contains(string(r.Body()), "m=audio") {
		t.Fatalf("200 to a re-INVITE without SDP: %v %v", r, err)
	}
	_ = n.toUE.SendRequest(inDialogReq("ACK", "mo1", tag, "3"))
	with := inDialogReq("UPDATE", "mo1", tag, "4").Add("Content-Type", "application/sdp")
	with.Body = liveOffer(t)
	if r, err = n.toUE.Do(ctx, with, nil); err != nil || r.StatusCode != 200 || !strings.Contains(string(r.Body()), "m=audio") {
		t.Fatalf("200 to an UPDATE with an offer: %v %v", r, err)
	}
}

// A peer that answers our refreshes with errors is asked again; when that
// does not help, the call ends where its session does.
func TestSessionRefusedRefresh(t *testing.T) {
	fastSession(t, 5*time.Millisecond) // interval 450 ms, ends 150 ms before that
	n := newNet(t)
	c, _ := n.answered("st7", "Session-Expires", "90;refresher=uas")
	start := time.Now()
	updates := 0
	for {
		r := n.next()
		if r.req.Method == sip.BYE {
			_ = r.conn.Respond(r.req, 200, "OK")
			break
		}
		if r.req.Method != sip.UPDATE {
			t.Fatalf("unexpected %s", r.req.Method)
		}
		updates++
		respond(r, 503, "Service Unavailable", "", nil, "")
	}
	if d := time.Since(start); updates < 2 || d < 250*time.Millisecond {
		t.Errorf("%d refreshes, BYE after %v; want retries and the end near 300ms", updates, d)
	}
	n.waitState(StateEnded)
	if _, cause := c.State(); cause != "session expired: 503 Service Unavailable" {
		t.Errorf("cause %q", cause)
	}
}

// The answer to a refresh that is no longer current changes nothing: neither
// after the call has ended nor after the peer has refreshed the session.
func TestSessionStaleRefresh(t *testing.T) {
	fastSession(t, 5*time.Millisecond) // refresh timeout 100 ms
	n := newNet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, res := n.answered("st8", "Session-Expires", "90;refresher=uas")
	u := n.recv(sip.UPDATE)
	if r, err := n.toUE.Do(ctx, inDialogReq("BYE", "st8", toTag(res), "2"), nil); err != nil || r.StatusCode != 200 {
		t.Fatalf("BYE: %v %v", r, err)
	}
	n.waitState(StateEnded)
	respond(u, 481, "Call/Transaction Does Not Exist", "", nil, "")
	n.quiet(200 * time.Millisecond)

	c, res := n.answered("st9", "Session-Expires", "90;refresher=uas")
	n.recv(sip.UPDATE) // stays unanswered
	theirs := inDialogReq("UPDATE", "st9", toTag(res), "2").Add("Supported", "timer").Add("Session-Expires", "90;refresher=uac")
	if r, err := n.toUE.Do(ctx, theirs, nil); err != nil || r.StatusCode != 200 {
		t.Fatalf("UPDATE of the peer: %v %v", r, err)
	}
	n.quiet(250 * time.Millisecond) // our refresh timed out meanwhile
	if st, cause := c.State(); st != StateActive {
		t.Fatalf("call is %v (%s)", st, cause)
	}
}

// A hangup after the INVITE was repeated for a 422 cancels the second one.
func TestOutboundCancelAfterRetry(t *testing.T) {
	n := newNet(t)
	c, err := n.m.Dial("+447700900006", netip.MustParseAddrPort("127.0.0.1:41102"))
	if err != nil {
		t.Fatal(err)
	}
	inv := n.recv(sip.INVITE)
	respond(inv, 422, "Session Interval Too Small", "x", map[string]string{"Min-SE": "3600"}, "")
	n.recv(sip.ACK)
	inv2 := n.recv(sip.INVITE)
	respond(inv2, 180, "Ringing", "r", map[string]string{"Contact": "<sip:127.0.0.1:9900>"}, "")
	n.waitState(StateRinging)
	go func() { _ = c.Hangup() }()
	cn := n.recv(sip.CANCEL)
	if cn.req.CSeq().SeqNo != 2 || cn.req.Via().Params.GetOr("branch", "") != inv2.req.Via().Params.GetOr("branch", "x") {
		t.Errorf("CANCEL:\n%s", cn.req)
	}
	_ = cn.conn.Respond(cn.req, 200, "OK")
	respond(inv2, 487, "Request Terminated", "r", nil, "")
	if ack := n.recv(sip.ACK); ack.req.CSeq().SeqNo != 2 {
		t.Errorf("ACK:\n%s", ack.req)
	}
	n.waitState(StateEnded)
	if _, cause := c.State(); cause != "cancelled" {
		t.Errorf("cause %q", cause)
	}
}

// A re-INVITE of the peer refreshes the session like an UPDATE does: the
// interval starts anew, so our own refresh moves with it.
func TestSessionRefreshedByReInvite(t *testing.T) {
	fastSession(t, 5*time.Millisecond) // interval 450 ms, our refresh at 337 ms
	n := newNet(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, res := n.answered("st10", "Session-Expires", "90")
	time.Sleep(200 * time.Millisecond)
	re := inDialogReq("INVITE", "st10", toTag(res), "2").Add("Supported", "timer").
		Add("Session-Expires", "90;refresher=uac").Add("Content-Type", "application/sdp")
	re.Body = liveOffer(t)
	r, err := n.toUE.Do(ctx, re, nil)
	if err != nil || r.StatusCode != 200 || headerValue(r, "Session-Expires") != "90;refresher=uac" ||
		!hasTag(optionTags(r, "Require"), "timer") || !strings.Contains(string(r.Body()), "m=audio") {
		t.Fatalf("200 to the refreshing re-INVITE: %v %v", r, err)
	}
	_ = n.toUE.SendRequest(inDialogReq("ACK", "st10", toTag(res), "2"))
	n.quiet(250 * time.Millisecond) // the refresh planned before it would have come by now
	n.recv(sip.UPDATE)
}
