package reg

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// The expiry granted in a 200 used to be taken as it was: 0, a negative
// number, or one so large that n*time.Second wrapped around. hold() then
// armed the refresh at once, and every 200 armed it at once again: Run sent
// REGISTER after REGISTER at the speed of the round trip (some 6000 a second
// on loopback), the kind of load an operator may bar a SIM for.
func TestGrantedExpiresDoesNotFloodTheNetwork(t *testing.T) {
	for _, grant := range []string{"0", "-1", "1", "9223372037", "99999999999999999999"} {
		t.Run(grant, func(t *testing.T) {
			f, r := newFakePCSCF(t), &fakeRunner{}
			f.set(func() { f.grant = grant })
			c := newClient(t, f, &fakeSIM{}, r)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { defer close(done); c.Run(ctx, nil) }()
			time.Sleep(time.Second)
			cancel()
			<-done
			// The initial REGISTER pair and perhaps a de-REGISTER, not dozens.
			if all := len(f.seen()); all > 6 {
				t.Errorf("granted expires=%s: %d REGISTER requests in one second", grant, all)
			}
		})
	}
}

// granted reads the expiry of our binding from a 200 without overflow,
// takes no more than was asked for (RFC 3261 §10.3) and calls none at all a
// dropped binding.
func TestGranted(t *testing.T) {
	const hp = "10.0.0.1:5101"
	asked := 600000 * time.Second
	for _, c := range []struct {
		header, contact string // Expires and the expires of our Contact; "" = none
		want            time.Duration
		dropped         bool
	}{
		{"", "", asked, false},
		{"3600", "", time.Hour, false},
		{"3600", "1800", 30 * time.Minute, false}, // our Contact wins
		{"0", "3600", time.Hour, false},
		{"3600", "0", 0, true},
		{"", "-1", 0, true},
		{"0", "", 0, true},
		{"", "9223372037", asked, false},           // n*time.Second would wrap around
		{"", "99999999999999999999", asked, false}, // past int64
		{"", "-99999999999999999999", 0, true},
		{"3600", "x", time.Hour, false}, // unreadable: the header's
		{"700000", "", asked, false},    // more than asked
		{"", "30", 30 * time.Second, false},
	} {
		raw := "SIP/2.0 200 OK\r\nVia: SIP/2.0/TCP " + hp + ";branch=z9hG4bK1\r\nCSeq: 2 REGISTER\r\n"
		if c.header != "" {
			raw += "Expires: " + c.header + "\r\n"
		}
		if c.contact != "" {
			raw += "Contact: <sip:u@" + hp + ";transport=tcp>;expires=" + c.contact + "\r\n"
		}
		raw += "Contact: <sip:other@10.0.0.9:5101>;expires=7\r\nContent-Length: 0\r\n\r\n" // not ours
		msg, err := sip.ParseMessage([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		got, err := granted(msg.(*sip.Response), hp, asked)
		if c.dropped != errors.Is(err, errNoBinding) || (!c.dropped && (err != nil || got != c.want)) {
			t.Errorf("Expires %q, our expires %q: got %v, %v", c.header, c.contact, got, err)
		}
	}
}

// subscribed waits for the reg-event subscription of Run and returns its
// Call-ID.
func subscribed(t *testing.T, f *fakePCSCF) string {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		f.mu.Lock()
		callID := ""
		if len(f.subs) > 0 {
			callID = f.subs[0].callID
		}
		f.mu.Unlock()
		if callID != "" {
			time.Sleep(100 * time.Millisecond) // the 200 to the SUBSCRIBE is in
			return callID
		}
	}
	t.Fatal("no reg-event subscription")
	return ""
}

// notifyShortened sends the NOTIFY of TS 24.229 §5.4.1.6 in the dialog
// callID: our contact stays active, with the event "shortened" and expires
// seconds left.
func notifyShortened(t *testing.T, c *Client, callID, expires string) {
	t.Helper()
	hp := serverPort(c)
	notify := sipnet.NewRequest("NOTIFY", "sip:x@"+hp).
		Add("Via", "SIP/2.0/TCP 127.0.0.1:9950;branch="+sipnet.NewBranch()).
		Add("From", "<"+impu+">;tag=net1").Add("To", "<"+impu+">;tag=ue").
		Add("Call-ID", callID).Add("CSeq", "2 NOTIFY").Add("Event", "reg").
		Add("Subscription-State", "active;expires=600000").Add("Content-Type", "application/reginfo+xml")
	notify.Body = []byte(`<?xml version="1.0"?><reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="partial">` +
		`<registration aor="` + impu + `" id="r1" state="active"><contact id="c1" state="active" event="shortened" expires="` + expires + `">` +
		`<uri>sip:x@` + hp + `;transport=tcp</uri></contact></registration></reginfo>`)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if res, err := network(t, c).Do(ctx, notify, nil); err != nil || res.StatusCode != 200 {
		t.Fatalf("NOTIFY: %v %v", res, err)
	}
}

// TS 24.229 §5.1.1.5A: the network asks for re-authentication with a
// reg-event NOTIFY in which our contact stays active with the event
// "shortened" and a short expires. That used to be ignored: the refresh
// stayed where the 200 had put it (3000 s on for 3600), and the S-CSCF
// dropped the registration when the short expiry ran out. Now the UE
// re-registers in time, and the S-CSCF's challenge (§5.4.1.6) takes it
// through the SIM and new SAs, once.
func TestShortenedRegistrationIsRenewed(t *testing.T) {
	f, r, s := newFakePCSCF(t), &fakeRunner{}, &fakeSIM{}
	c := newClient(t, f, s, r)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx, nil) }()
	defer func() { cancel(); <-done }()

	callID := subscribed(t, f)
	f.set(func() { f.reauth = true })
	before, sims := len(f.seen()), s.count()
	notifyShortened(t, c, callID, "2")
	var regs []seenReg
	for deadline := time.Now().Add(2500 * time.Millisecond); ; time.Sleep(20 * time.Millisecond) {
		regs = f.seen()[before:]
		if len(regs) >= 2 && regs[0].status == 401 && regs[1].answer && regs[1].status == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no re-authentication within the shortened expiry of 2 s: %+v", regs)
		}
	}
	if s.count() == sims {
		t.Error("the SIM was not asked")
	}
	time.Sleep(500 * time.Millisecond)
	if n := len(f.seen()) - before; n != 2 {
		t.Errorf("%d REGISTER requests after the shortening, want the challenged one and its answer", n)
	}
}

// A shortening moves the refresh only earlier: a full-state NOTIFY repeats
// it (with the time left by then, here at once), which moves nothing, nor
// does a longer one; a shorter one moves it again. The refresh answers it;
// should the network shorten the binding again right away, the next refresh
// comes reauthSpacing after.
func TestShorteningOnlyMovesTheRefreshEarlier(t *testing.T) {
	_, _, _, c, ctx := registered(t)
	until := func() time.Duration {
		_, due, _ := c.refreshDue()
		return time.Until(due)
	}
	if d := until(); d < 2999*time.Second {
		t.Fatalf("refresh of the 3600 s binding in %v", d)
	}
	if !c.shorten(600 * time.Second) {
		t.Fatal("shortening to 600 s ignored")
	}
	if d := until(); d < 299*time.Second || d > 300*time.Second {
		t.Fatalf("refresh in %v after a shortening to 600 s, want 300 s", d)
	}
	if c.shorten(600*time.Second) || c.shorten(1200*time.Second) || until() < 299*time.Second {
		t.Fatal("a repeat or a longer shortening moved the refresh")
	}
	if !c.shorten(100*time.Second) || until() > 50*time.Second {
		t.Fatalf("refresh in %v after a shortening to 100 s, want 50 s", until())
	}
	if !c.shorten(0) || until() > 0 {
		t.Fatalf("shortening to 0 s: refresh in %v", until())
	}
	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if d := until(); d < 2999*time.Second {
		t.Fatalf("after the refresh the next one is in %v", d)
	}
	if !c.shorten(0) {
		t.Fatal("a new shortening ignored")
	}
	if d := until(); d < reauthSpacing-time.Second || d > reauthSpacing {
		t.Fatalf("a shortening right after the refresh it asked for: next one in %v, want %v", d, reauthSpacing)
	}
}

// A shortening that arrives while a refresh is on its way may be newer than
// the 200 of that refresh, so it outlives the 200.
func TestShorteningThatCrossesARefreshStays(t *testing.T) {
	f, _, _, c, ctx := registered(t)
	stall := make(chan struct{})
	f.set(func() { f.stall = stall })
	n := len(f.seen())
	refreshed := make(chan error, 1)
	go func() { _, err := c.Refresh(ctx); refreshed <- err }()
	for deadline := time.Now().Add(3 * time.Second); len(f.seen()) == n; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("no refresh")
		}
	}
	if !c.shorten(20 * time.Second) {
		t.Fatal("shortening ignored")
	}
	f.set(func() { f.stall = nil })
	close(stall)
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
	if _, due, _ := c.refreshDue(); time.Until(due) > 10*time.Second {
		t.Fatalf("the shortening that crossed the refresh was lost: next refresh in %v", time.Until(due))
	}
}

// A refresh whose 200 drops the binding (expires 0) loses the registration,
// and Run registers anew after a pause, as after a failed registration, not
// at once: a registrar that keeps answering so is not flooded either.
func TestDroppedBindingIsRegisteredAgainAfterAPause(t *testing.T) {
	f, r := newFakePCSCF(t), &fakeRunner{}
	c := newClient(t, f, &fakeSIM{}, r)
	ctx, cancel := context.WithCancel(context.Background())
	failed := make(chan error, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.Run(ctx, func(s Status, err error) {
			if s == StatusFailed {
				failed <- err
			}
		})
	}()
	defer func() { cancel(); <-done }()

	callID := subscribed(t, f)
	f.set(func() { f.grant = "0" })
	notifyShortened(t, c, callID, "0") // refresh at once
	select {
	case err := <-failed:
		if !errors.Is(err, errNoBinding) {
			t.Fatalf("failed with %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the dropped binding went unnoticed")
	}
	n := len(f.seen())
	time.Sleep(1500 * time.Millisecond)
	if after := len(f.seen()); after != n {
		t.Fatalf("%d REGISTER requests at once after the binding was dropped, want a pause", after-n)
	}
}
