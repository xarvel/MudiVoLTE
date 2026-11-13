package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// Test intervals are shorter than production (30 s idle, then a 5 s probe).
const regressionGone = 7 * time.Second

// A phone in an echo test disappears without a BYE (the battery died, the
// phone left the Wi-Fi, Linphone was killed). The line must come back.
func TestRegressionEchoPhoneGoneHoldsLine(t *testing.T) {
	rig := newTestRig(t, &Config{IncomingAll: true}, true)
	rig.mgr.phoneIdle, rig.mgr.phoneProbe = 100*time.Millisecond, 100*time.Millisecond
	ph := newTestPhone(t)
	if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration: %v %v", res, err)
	}
	dlg, _, err := ph.call(rig.srvAddr, "600")
	if err != nil {
		t.Fatalf("echo call: %v", err)
	}
	ph.talk(dlg.InviteResponse.Body(), 300*time.Millisecond, -1)
	ph.ua.Close()
	ph.sipSocket.Close()
	ph.rtp.Close()
	waitRegression(t, func() bool { return rig.mgr.current() == nil }, regressionGone)
	if rig.mgr.current() == nil {
		return
	}
	call := newFakeIMSCall("after-echo", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900123")
	t.Fatalf("after %s without the phone the line is still held; a call from the network got %d", regressionGone, call.rejected.Load())
}

// The same during a real call from the network: the phone is gone, the call
// goes on.
func TestRegressionNetworkCallPhoneGone(t *testing.T) {
	rig := newTestRig(t, &Config{IncomingAll: true}, true)
	rig.mgr.phoneIdle, rig.mgr.phoneProbe = 100*time.Millisecond, 100*time.Millisecond
	ph := newTestPhone(t)
	if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration: %v %v", res, err)
	}
	call := newFakeIMSCall("in-gone", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900123")
	select {
	case dlg := <-ph.incoming:
		if err := dlg.RespondSDP(ph.sdp()); err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no INVITE")
	}
	waitFor(t, call.answered.Load, "not answered in the network")
	if !call.rang.Load() {
		t.Fatal("phones rang without 180 to the network")
	}
	ph.ua.Close()
	ph.sipSocket.Close()
	ph.rtp.Close()
	waitRegression(t, func() bool { return rig.mgr.current() == nil }, regressionGone)
	if !call.hungup.Load() || rig.mgr.current() != nil {
		t.Fatalf("after %s without the phone the network call is not hung up and the line is held", regressionGone)
	}
}

// regressionUDPPush is the Contact of Linphone with push parameters over UDP, the
// one TestSIPRegisterResponseFitsUDP takes from a live phone.
func regressionUDPPush() []sip.HeaderKV {
	token := strings.Repeat("a1", 32)
	return []sip.HeaderKV{{K: "pn-prid", V: token + ":voip&" + token + ":remote"}, {K: "pn-provider", V: "apns"},
		{K: "pn-param", V: "ABCD1234.org.linphone.phone.voip&remote"}, {K: "pn-silent", V: "1"}, {K: "pn-timeout", V: "0"},
		{K: "pn-msg-str", V: "IM_MSG"}, {K: "pn-call-str", V: "IC_MSG"}, {K: "pn-groupchat-str", V: "GC_MSG"},
		{K: "pn-call-snd", V: "notes_of_the_optimistic.caf"}, {K: "pn-msg-snd", V: "msg.caf"}, {K: "transport", V: "udp"}}
}

// A text longer than one piece, to a phone on UDP whose Contact carries push
// parameters, must arrive in pieces.
func TestRegressionLongTextToUDPPhoneWithPush(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	ph := newTestPhoneUser(t, "127.0.0.1", "pixel")
	ph.instance = `"<urn:uuid:5f0c6d3e-0000-4000-8000-000000000203>"`
	ph.pn = regressionUDPPush()
	if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration: %v %v", res, err)
	}
	b := rig.lan.reg.forUser("pixel")[0]
	t.Logf("Request-URI of a request to this phone: %d bytes", len(b.contact.String()))

	// 400 Cyrillic letters: 800 bytes, 6 SMS parts, pieces of at most 700.
	text := strings.Repeat("\u044b", 400)
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ok, err := rig.lan.sendText(c, "pixel", "+447700900123", "", text, "sms-0011223344")
	if !ok {
		t.Fatalf("a %d-byte SMS was not sent to the phone: %v", len(text), err)
	}
	var received strings.Builder
	for received.Len() < len(text) {
		msg := ph.nextMessage(t, time.Second)
		if len(msg.String()) > sip.UDPMTUSize-200 {
			t.Fatal("a piece exceeds the SIP UDP limit")
		}
		received.Write(msg.Body())
	}
	if received.String() != text {
		t.Fatal("the delivered pieces changed the text")
	}
}

// A phone that has signed out (Expires: 0) has asked to be left alone.
func TestRegressionSignedOutPhoneStillPushed(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, true)
	fp := newFakePusher()
	rig.lan.pusher = fp
	ph := newIPhone(t)
	registerOK(t, ph, tlsAddr)
	ph.unreg = true
	registerOK(t, ph, tlsAddr)
	if n := len(rig.lan.reg.forUser("iphone")); n != 0 {
		t.Fatalf("%d bindings after the sign-out", n)
	}
	call := newFakeIMSCall("in-out", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900123")
	select {
	case <-fp.got:
		t.Errorf("the phone that signed out got a push for the call")
	case <-time.After(1500 * time.Millisecond):
	}
	if code := call.rejected.Load(); code != rejectDecline {
		t.Errorf("no phone is left, the call must be declined at once; rejected code = %d", code)
	}
}

// A phone's 200 crosses our CANCEL (the caller hung up, or another phone took
// the call): PROTOCOLS.md 4.5, "Race: ACK+BYE to a late 200".
func TestRegressionAnswerCrossingCancel(t *testing.T) {
	rig := newTestRig(t, &Config{IncomingAll: true}, true)
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	addr := pc.LocalAddr().(*net.UDPAddr)
	rig.lan.reg.update(binding{user: "pixel", contact: sip.Uri{Scheme: "sip", User: "pixel", Host: "127.0.0.1", Port: addr.Port},
		source: addr.String(), transport: "udp", expires: time.Now().Add(time.Hour)})
	call := newFakeIMSCall("in-cross", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900123")

	read := func(d time.Duration) *sip.Request {
		buf := make([]byte, 4096)
		_ = pc.SetReadDeadline(time.Now().Add(d))
		n, _, err := pc.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		m, err := sip.NewParser().ParseSIP(buf[:n])
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		r, _ := m.(*sip.Request)
		return r
	}
	send := func(req *sip.Request, code int, reason string, body []byte) {
		res := sip.NewResponseFromRequest(req, code, reason, body)
		res.AppendHeader(&sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: "pixel", Host: "127.0.0.1", Port: addr.Port}})
		if body != nil {
			res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		}
		if _, err := pc.WriteToUDP([]byte(res.String()), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: rig.lan.port}); err != nil {
			t.Fatal(err)
		}
	}
	inv := read(3 * time.Second)
	if inv == nil || !inv.IsInvite() {
		t.Fatalf("no INVITE: %v", inv)
	}
	inv.To().Params.Add("tag", "phone-tag")
	send(inv, 180, "Ringing", nil)
	time.Sleep(200 * time.Millisecond)

	rig.mgr.onIMSEvent(call, CallStateEnded) // the caller hangs up: CANCEL to the phone
	var cancel *sip.Request
	for deadline := time.Now().Add(3 * time.Second); cancel == nil && time.Now().Before(deadline); {
		if r := read(time.Second); r != nil && r.IsCancel() {
			cancel = r
		}
	}
	if cancel == nil {
		t.Fatal("no CANCEL")
	}
	send(cancel, 200, "OK", nil)
	sdp := fmt.Sprintf("v=0\r\no=p 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio %d RTP/AVP 9\r\n", 50000)
	send(inv, 200, "OK", []byte(sdp)) // it was on its way when the CANCEL came

	var ack, bye bool
	for deadline := time.Now().Add(6 * time.Second); !(ack && bye) && time.Now().Before(deadline); {
		r := read(time.Second)
		switch {
		case r == nil:
		case r.Method == sip.ACK:
			ack = true
		case r.Method == sip.BYE:
			bye = true
			send(r, 200, "OK", nil)
		}
	}
	if !ack || !bye {
		t.Fatalf("after its 200 the phone got ACK=%v BYE=%v: it stays in a call with nobody", ack, bye)
	}
}

func waitRegression(t *testing.T, ok func() bool, duration time.Duration) {
	t.Helper()
	deadline := time.Now().Add(duration)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A phone on hold need not send RTP: a reply to OPTIONS keeps its call alive.
func TestRegressionSilentPhoneRespondsToProbe(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	rig.mgr.phoneIdle, rig.mgr.phoneProbe = 50*time.Millisecond, 100*time.Millisecond
	ph := newTestPhone(t)
	probes := make(chan bool, 8)
	ph.srv.OnOptions(func(req *sip.Request, tx sip.ServerTransaction) {
		tagged := req.To() != nil && req.To().Params.Has("tag")
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
		probes <- tagged
	})
	dlg, _, err := ph.call(rig.srvAddr, "600")
	if err != nil {
		t.Fatal(err)
	}
	defer dlg.Close()
	for range 3 {
		select {
		case tagged := <-probes:
			if !tagged {
				t.Fatal("OPTIONS was not in-dialog")
			}
		case <-time.After(time.Second):
			t.Fatal("no liveness probe")
		}
	}
	lc := rig.mgr.current()
	if lc == nil || lc.ctx.Err() != nil {
		t.Fatal("silent but reachable phone lost its call")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dlg.Bye(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "line held after BYE")
}

// A successful fork whose waiter has left still belongs to forkInvite until
// the result is handed over; it must not be left in a buffered results queue.
func TestRegressionForkWinnerWithoutWaiter(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	ph := newTestPhone(t)
	if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("register: %v %v", res, err)
	}
	lc, _ := rig.mgr.acquire("in")
	defer rig.mgr.release(lc)
	leg, err := rig.lan.ports.open(rig.mgr.logger)
	if err != nil {
		t.Fatal(err)
	}
	defer leg.Close()
	offer, err := rig.lan.newLegOffer(lc, leg.Port(), 1)
	if err != nil {
		t.Fatal(err)
	}
	r := rig.mgr.newRinger("", "caller", "test")
	if !r.plan(rig.lan.reg.active()) {
		t.Fatal("no phone")
	}
	ctx, cancel := context.WithCancel(lc.ctx)
	defer cancel()
	r.launch(ctx, lc, offer)
	var dlg *sipgo.DialogServerSession
	select {
	case dlg = <-ph.incoming:
	case <-time.After(time.Second):
		t.Fatal("no INVITE")
	}
	responded := make(chan struct{})
	go func() { _ = dlg.RespondSDP(ph.sdp()); close(responded) }()
	waitFor(t, lc.answered.Load, "the fork did not take the answer")
	cancel() // deliberately no waitFork: the successful answer has no owner
	select {
	case <-ph.byeGot:
	case <-time.After(time.Second):
		t.Fatal("abandoned winner got no BYE")
	}
	select {
	case <-responded:
	case <-time.After(time.Second):
		t.Fatal("abandoned winner got no ACK")
	}
}

func TestRegressionInternalPhoneDisappears(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	rig.mgr.phoneIdle, rig.mgr.phoneProbe = 100*time.Millisecond, 100*time.Millisecond
	a, b := newTestPhoneUser(t, "127.0.0.1", "pixel"), newTestPhoneUser(t, "127.0.0.1", "iphone")
	for _, ph := range []*testPhone{a, b} {
		if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
			t.Fatalf("register: %v %v", res, err)
		}
	}
	dialed := make(chan *sipgo.DialogClientSession, 1)
	go func() { d, _, _ := a.call(rig.srvAddr, "iphone"); dialed <- d }()
	select {
	case dlg := <-b.incoming:
		if err := dlg.RespondSDP(b.sdp()); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("no INVITE")
	}
	caller := <-dialed
	if caller == nil {
		t.Fatal("caller did not connect")
	}
	defer caller.Close()
	b.sipSocket.Close()
	b.ua.Close()
	b.rtp.Close()
	select {
	case <-a.byeGot:
	case <-time.After(time.Second):
		t.Fatal("caller got no BYE after the other phone disappeared")
	}
	waitRegression(t, func() bool { return rig.mgr.current() == nil }, regressionGone)
	if rig.mgr.current() != nil {
		t.Fatal("internal call held the line")
	}
}
