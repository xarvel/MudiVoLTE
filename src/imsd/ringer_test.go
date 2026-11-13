package main

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/xarvel/MudiVoLTE/volte/srtp"
)

// fakePusher records the pushes instead of sending them to FlexiAPI.
type fakePusher struct {
	mu        sync.Mutex
	callIDs   []string
	users     []string
	providers []string
	got       chan string
}

func newFakePusher() *fakePusher { return &fakePusher{got: make(chan string, 8)} }

func (f *fakePusher) push(_ context.Context, p pushParams, kind, callID string) error {
	f.mu.Lock()
	f.callIDs = append(f.callIDs, callID)
	f.users = append(f.users, p.User)
	f.providers = append(f.providers, p.Provider)
	f.mu.Unlock()
	f.got <- callID
	return nil
}

func (f *fakePusher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.callIDs)
}

const iphoneInstance = `"<urn:uuid:7d3c1e2a-0000-4000-8000-0000000000ip>"`

// newIPhone is Linphone on an iPhone set up by QR code: TLS, SRTP, the same
// +sip.instance on every registration and the push parameters in the Contact.
func newIPhone(t *testing.T) *testPhone {
	t.Helper()
	p := newTLSTestPhone(t, "iphone", suitePtr(srtp.AES128CMSHA1_80))
	p.instance = iphoneInstance
	p.pn = []sip.HeaderKV{{K: "pn-provider", V: "apns"}, {K: "pn-param", V: "ABCD1234.org.linphone.phone.voip&remote"},
		{K: "pn-prid", V: "0a1b2c3d:voip&4e5f6a7b:remote"}}
	return p
}

const androidInstance = `"<urn:uuid:3b9e5f10-0000-4000-8000-0000000000an>"`

// newAndroid is Linphone on an Android phone set up by QR code: TLS, SRTP and
// the FCM push parameters in the Contact (pn-param is the Firebase project
// number, pn-prid the FCM token, which holds a ':').
func newAndroid(t *testing.T) *testPhone {
	t.Helper()
	p := newTLSTestPhone(t, "pixel", suitePtr(srtp.AES128CMSHA1_80))
	p.instance = androidInstance
	p.pn = []sip.HeaderKV{{K: "pn-provider", V: "fcm"}, {K: "pn-param", V: "123456789012"},
		{K: "pn-prid", V: "dXyZ_1:APA91b-x_y"}}
	return p
}

// sleeping registers a phone and closes its connection, as iOS does when
// Linphone goes to the background (or Android when it stops Linphone): the
// binding stays, the connection is gone.
func sleeping(t *testing.T, rig *testRig, tlsAddr string, ph *testPhone) {
	t.Helper()
	registerOK(t, ph, tlsAddr)
	ph.ua.Close()
	waitFor(t, func() bool {
		for _, b := range rig.lan.reg.forUser(ph.user) {
			if rig.lan.reachable(b) {
				return false
			}
		}
		return true
	}, "the server still sees the phone's connection")
}

func sleepingIPhone(t *testing.T, rig *testRig, tlsAddr string) {
	t.Helper()
	sleeping(t, rig, tlsAddr, newIPhone(t))
}

func TestPushWakesSleepingIPhone(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, true)
	fp := newFakePusher()
	rig.lan.pusher = fp
	sleepingIPhone(t, rig, tlsAddr)

	call := newFakeIMSCall("in-push", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	var callID string
	select {
	case callID = <-fp.got:
	case <-time.After(3 * time.Second):
		t.Fatal("no push to the sleeping iPhone")
	}
	if call.rejected.Load() != 0 {
		t.Fatal("the call was declined while the iPhone was being woken")
	}

	// Linphone woken by the push registers again over a new connection.
	ph := newIPhone(t)
	registerOK(t, ph, tlsAddr)
	var dlg *sipgo.DialogServerSession
	select {
	case dlg = <-ph.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the iPhone that came back got no INVITE")
	}
	if got := dlg.InviteRequest.CallID().Value(); got != callID {
		t.Fatalf("the INVITE has Call-ID %q, the push named %q", got, callID)
	}
	if err := dlg.RespondSDP(ph.sdp()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, call.answered.Load, "the network was not answered after the iPhone picked up")
	if r := ph.talk(dlg.InviteRequest.Body(), time.Second, -1); r < 1500 {
		t.Fatalf("no audio to the woken iPhone: RMS %.0f", r)
	}
	if n := fp.count(); n != 1 {
		t.Fatalf("%d pushes, want 1: the iPhone came back before the retry", n)
	}
	rig.mgr.onIMSEvent(call, CallStateEnded)
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// An iPhone that never comes back is pushed twice (iOS may have unloaded
// Linphone, the first push only starts it), and the call ends after the ring
// time as missed.
func TestPushRetriedThenMissed(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, true)
	fp := newFakePusher()
	rig.lan.pusher = fp
	sleepingIPhone(t, rig, tlsAddr)
	start := time.Now()
	call := newFakeIMSCall("in-push-missed", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	for call.rejected.Load() == 0 {
		if time.Since(start) > 10*time.Second {
			t.Fatal("the call to an iPhone that never came back did not end")
		}
		time.Sleep(20 * time.Millisecond)
	}
	d := time.Since(start)
	if d < 4*time.Second || d > 8*time.Second {
		t.Fatalf("the call ended after %v, want about the ring time (5 s)", d)
	}
	if n := fp.count(); n != 2 {
		t.Fatalf("%d pushes, want 2", n)
	}
	if fp.callIDs[0] != fp.callIDs[1] {
		t.Fatalf("the retry named another Call-ID: %v", fp.callIDs)
	}
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// The caller hangs up before the pushed iPhone wakes: when it comes back it
// gets the INVITE with the Call-ID of the push and a CANCEL right after, so
// Linphone closes the call it shows as missed instead of ringing on.
func TestPushedPhoneBackAfterCallerHungUp(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, true)
	fp := newFakePusher()
	rig.lan.pusher = fp
	sleepingIPhone(t, rig, tlsAddr)
	call := newFakeIMSCall("in-push-gone", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	var callID string
	select {
	case callID = <-fp.got:
	case <-time.After(3 * time.Second):
		t.Fatal("no push to the sleeping iPhone")
	}
	rig.mgr.onIMSEvent(call, CallStateEnded)
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released after the caller hung up")

	ph := newIPhone(t)
	registerOK(t, ph, tlsAddr)
	var dlg *sipgo.DialogServerSession
	select {
	case dlg = <-ph.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the iPhone that woke up after the call got no INVITE to close it")
	}
	if got := dlg.InviteRequest.CallID().Value(); got != callID {
		t.Fatalf("the INVITE has Call-ID %q, the push named %q", got, callID)
	}
	select {
	case <-dlg.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("no CANCEL after the INVITE: the iPhone would ring for a call that is over")
	}
	if call.answered.Load() {
		t.Fatal("the network was answered")
	}
	// Only once: a second registration of the same iPhone gets nothing.
	ph2 := newIPhone(t)
	registerOK(t, ph2, tlsAddr)
	select {
	case <-ph2.incoming:
		t.Fatal("the ended call was sent to the iPhone twice")
	case <-time.After(time.Second):
	}
}

// Android: Linphone whose service the system has stopped is woken the same
// way, through FCM.
func TestPushWakesStoppedAndroid(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, true)
	fp := newFakePusher()
	rig.lan.pusher = fp
	sleeping(t, rig, tlsAddr, newAndroid(t))

	call := newFakeIMSCall("in-push-android", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	var callID string
	select {
	case callID = <-fp.got:
	case <-time.After(3 * time.Second):
		t.Fatal("no push to the stopped Android phone")
	}
	fp.mu.Lock()
	provider, user := fp.providers[0], fp.users[0]
	fp.mu.Unlock()
	if provider != "fcm" || user != "pixel" {
		t.Fatalf("push went to %s over %s", user, provider)
	}
	ph := newAndroid(t)
	registerOK(t, ph, tlsAddr)
	var dlg *sipgo.DialogServerSession
	select {
	case dlg = <-ph.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the Android phone that came back got no INVITE")
	}
	if got := dlg.InviteRequest.CallID().Value(); got != callID {
		t.Fatalf("the INVITE has Call-ID %q, the push named %q", got, callID)
	}
	if err := dlg.RespondSDP(ph.sdp()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, call.answered.Load, "the network was not answered after the Android phone picked up")
	rig.mgr.onIMSEvent(call, CallStateEnded)
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// Android with its service running (a live connection): rung at once, no push.
func TestNoPushToLiveAndroid(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, true)
	fp := newFakePusher()
	rig.lan.pusher = fp
	ph := newAndroid(t)
	registerOK(t, ph, tlsAddr)
	call := newFakeIMSCall("in-live-android", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	select {
	case dlg := <-ph.incoming:
		_ = dlg.Respond(486, "Busy Here", nil)
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE did not reach the Android phone")
	}
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
	if n := fp.count(); n != 0 {
		t.Fatalf("%d pushes to an Android phone with a live connection", n)
	}
}

// Linphone open on the iPhone: the INVITE goes into its connection, no push.
func TestNoPushToLiveIPhone(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, true)
	fp := newFakePusher()
	rig.lan.pusher = fp
	ph := newIPhone(t)
	registerOK(t, ph, tlsAddr)
	call := newFakeIMSCall("in-live", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	var dlg *sipgo.DialogServerSession
	select {
	case dlg = <-ph.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE did not reach the open iPhone")
	}
	if err := dlg.RespondSDP(ph.sdp()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, call.answered.Load, "the network was not answered")
	if n := fp.count(); n != 0 {
		t.Fatalf("%d pushes to an iPhone with a live connection", n)
	}
	rig.mgr.onIMSEvent(call, CallStateEnded)
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// Without pushes: a phone that registers while another one rings (Linphone
// was opened during the call) gets the call too, and picks it up.
func TestPhoneBackDuringRinging(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, true)
	pixel := newTestPhoneUser(t, "127.0.0.1", "pixel")
	registerOK(t, pixel, rig.srvAddr)
	call := newFakeIMSCall("in-back", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	select {
	case <-pixel.incoming: // rings, nobody picks up
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE did not reach the Pixel")
	}
	ph := newIPhone(t)
	registerOK(t, ph, tlsAddr)
	var dlg *sipgo.DialogServerSession
	select {
	case dlg = <-ph.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the phone that registered during the ringing got no INVITE")
	}
	if err := dlg.RespondSDP(ph.sdp()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, call.answered.Load, "the network was not answered")
	rig.mgr.onIMSEvent(call, CallStateEnded)
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// An internal call to a sleeping iPhone wakes it the same way.
func TestPushInternalCall(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, false)
	fp := newFakePusher()
	rig.lan.pusher = fp
	sleepingIPhone(t, rig, tlsAddr)
	pixel := newTestPhoneUser(t, "127.0.0.1", "pixel")
	registerOK(t, pixel, rig.srvAddr)
	done := make(chan error, 1)
	var caller *sipgo.DialogClientSession
	go func() {
		d, _, err := pixel.call(rig.srvAddr, "202")
		caller = d
		done <- err
	}()
	var callID string
	select {
	case callID = <-fp.got:
	case <-time.After(3 * time.Second):
		t.Fatal("no push for the internal call")
	}
	ph := newIPhone(t)
	registerOK(t, ph, tlsAddr)
	var dlg *sipgo.DialogServerSession
	select {
	case dlg = <-ph.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the woken iPhone got no INVITE")
	}
	if dlg.InviteRequest.CallID().Value() != callID {
		t.Fatal("the INVITE does not carry the Call-ID of the push")
	}
	if err := dlg.RespondSDP(ph.sdp()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("internal call: %v", err)
	}
	bye(t, caller)
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}
