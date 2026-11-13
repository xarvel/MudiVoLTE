package main

// Ringing the devices of one call: an incoming call from the network (every
// phone) or an internal one (the devices of the called phone). Devices with a
// live binding get an INVITE at once. A phone whose Linphone sleeps has no
// connection, and after an hour no binding either (it stops refreshing it):
// an iPhone whenever Linphone is in the background, an Android phone when the
// system or a battery saver has stopped Linphone's service. It gets a push
// (flexiapi.go) naming the Call-ID the INVITE will carry, wakes, registers
// again and then gets the INVITE in its new connection ("late forking", the
// way Flexisip does it). A device that comes
// back while the call rings for any other reason (Linphone was opened) gets
// the call too. If iOS had unloaded Linphone, the first push only starts the
// app, which shows a placeholder call for a few seconds and does not register
// (EarlyPushkitDelegate in linphone-iphone): a device that has not come back
// after pushRetryAfter is pushed once more. A pushed device that comes back
// after the ringing is over (the caller hung up, another phone answered) gets
// the INVITE and at once a CANCEL: Linphone then closes the call it shows
// since the push as missed instead of ringing until its own timeout of ~20 s.

import (
	"context"
	"sync"
	"time"
)

const (
	pushRetryAfter = 3 * time.Second
	pushSends      = 2                // pushes per device and call
	maxLateForks   = 16               // devices that may come back during one call
	pushedLinger   = 25 * time.Second // a woken Linphone waits ~20 s for the INVITE
)

type ringer struct {
	m      *callManager
	lc     *lineCall
	ctx    context.Context
	user   string // "" = every phone (a call from the network); else the called login
	caller string // the From user of the INVITEs
	offer  legOffer
	what   string // "incoming" | "internal call", for the log

	live     []binding    // ringing at once
	sleeping []pushParams // woken by a push

	results chan forkResult
	alive   chan int

	mu     sync.Mutex
	n      int                      // slots in waitFork: devices rung or expected
	rung   map[string]bool          // devices that got an INVITE into a live connection
	pushed map[string]*pushedDevice // devices woken by a push, by deviceKey
}

type pushedDevice struct {
	callID string        // named in the push and carried by the INVITE
	slot   int           // its result slot in waitFork
	back   chan struct{} // closed when it has registered again
	done   bool
}

// deviceKey names a device: by its +sip.instance, else by the fallback.
func deviceKey(user, instance, fallback string) string {
	if instance != "" {
		return user + "|" + instance
	}
	return user + "|@" + fallback
}

func (m *callManager) newRinger(user, caller, what string) *ringer {
	return &ringer{m: m, user: user, caller: caller, what: what,
		rung: map[string]bool{}, pushed: map[string]*pushedDevice{}}
}

// plan picks the devices to ring from the bindings and the saved push
// parameters; false means there is nobody to ring.
func (r *ringer) plan(bindings []binding) bool {
	l := r.m.lan
	liveKeys := map[string]bool{}
	for _, b := range bindings {
		if r.user != "" && b.user != r.user {
			continue
		}
		if !l.reachable(b) {
			r.m.logger.Info(r.what+": the phone's connection is gone", "user", b.user, "transport", b.transport, "from", b.source)
			continue
		}
		r.live = append(r.live, b)
		liveKeys[deviceKey(b.user, b.instance, b.source)] = true
	}
	if l.pusher != nil {
		for _, p := range l.push.all() {
			if (r.user != "" && p.User != r.user) || !p.canPush() || liveKeys[deviceKey(p.User, p.Instance, "")] {
				continue
			}
			r.sleeping = append(r.sleeping, p)
		}
	}
	return len(r.live)+len(r.sleeping) > 0
}

// launch sends the INVITEs to the live devices and the pushes to the sleeping
// ones. A pushed device counts as ringing: the call waits for it until the
// ring time is over.
func (r *ringer) launch(ctx context.Context, lc *lineCall, offer legOffer) {
	r.ctx, r.lc, r.offer = ctx, lc, offer
	n := len(r.live) + len(r.sleeping)
	r.results = make(chan forkResult)
	r.alive = make(chan int, n+maxLateForks)
	l := r.m.lan
	r.mu.Lock()
	defer r.mu.Unlock()
	r.n = n
	for i, b := range r.live {
		r.rung[deviceKey(b.user, b.instance, b.source)] = true
		go l.forkInvite(ctx, lc, i, b, r.caller, offer.forDevice(b), r.results, r.alive, "")
	}
	for j, p := range r.sleeping {
		pd := &pushedDevice{callID: newPushCallID(), slot: len(r.live) + j, back: make(chan struct{})}
		r.pushed[deviceKey(p.User, p.Instance, "")] = pd
		r.alive <- pd.slot
		go r.pushLoop(p, pd)
	}
	lc.ringer.Store(r)
	if len(r.sleeping) > 0 {
		go r.leftovers()
	}
}

// leftovers hands the pushed devices that have not come back by the end of
// the ringing to the call manager, which ends their call when they do.
func (r *ringer) leftovers() {
	<-r.ctx.Done()
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, pd := range r.pushed {
		if !pd.done {
			pd.done = true
			close(pd.back)
			r.m.notePushed(key, latePush{callID: pd.callID, caller: r.caller, offer: r.offer, until: time.Now().Add(pushedLinger)})
		}
	}
}

// slots is the number of results waitFork is to expect so far.
func (r *ringer) slots() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func (r *ringer) pushLoop(p pushParams, pd *pushedDevice) {
	for try := 1; try <= pushSends; try++ {
		start := time.Now()
		ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
		err := r.m.lan.pusher.push(ctx, p, "call", pd.callID)
		cancel()
		took := time.Since(start).Round(time.Millisecond).String()
		switch {
		case r.ctx.Err() != nil:
			return
		case err != nil:
			r.m.logger.Warn(r.what+": push to the phone failed", "user", p.User, "try", try, "took", took, "err", err)
		default:
			r.m.logger.Info(r.what+": push sent to the phone", "user", p.User, "try", try, "took", took)
		}
		if try == pushSends {
			return
		}
		select {
		case <-pd.back:
			return
		case <-r.ctx.Done():
			return
		case <-time.After(pushRetryAfter):
		}
	}
}

// deviceBack rings a device that has registered while the call rings: a
// phone woken by the push gets the INVITE with the Call-ID of the push. It
// reports whether the device was this call's.
func (r *ringer) deviceBack(b binding) bool {
	if r.user != "" && b.user != r.user {
		return false
	}
	key := deviceKey(b.user, b.instance, b.source)
	r.mu.Lock()
	if r.ctx == nil || r.rung[key] {
		r.mu.Unlock()
		return false
	}
	if r.ctx.Err() != nil || r.lc.answered.Load() {
		// Too late to ring: a woken device gets its call ended.
		pd := r.pushed[deviceKey(b.user, b.instance, "")]
		if pd == nil || pd.done || b.instance == "" {
			r.mu.Unlock()
			return false
		}
		pd.done = true
		close(pd.back)
		lp := latePush{callID: pd.callID, caller: r.caller, offer: r.offer}
		r.mu.Unlock()
		go r.m.lan.endPushedCall(b, lp, r.m.logger)
		return true
	}
	slot, callID, wasPushed := 0, "", false
	if pd := r.pushed[deviceKey(b.user, b.instance, "")]; pd != nil && !pd.done && b.instance != "" {
		pd.done = true
		close(pd.back)
		slot, callID, wasPushed = pd.slot, pd.callID, true
	} else {
		if r.n >= cap(r.alive) {
			r.mu.Unlock()
			return true
		}
		slot = r.n
		r.n++
	}
	r.rung[key] = true
	r.mu.Unlock()
	r.m.logger.Info(r.what+": the phone came back, ringing it", "user", b.user, "transport", b.transport, "pushed", wasPushed)
	go r.m.lan.forkInvite(r.ctx, r.lc, slot, b, r.caller, r.offer.forDevice(b), r.results, r.alive, callID)
	return true
}

// latePush is a device woken for a call that ended before it came back.
type latePush struct {
	callID string
	caller string
	offer  legOffer
	until  time.Time
}

// notePushed remembers a pushed device whose call is over.
func (m *callManager) notePushed(key string, lp latePush) {
	m.lateMu.Lock()
	defer m.lateMu.Unlock()
	if m.late == nil {
		m.late = map[string]latePush{}
	}
	now := time.Now()
	for k, v := range m.late {
		if now.After(v.until) {
			delete(m.late, k)
		}
	}
	m.late[key] = lp
}

// deviceBack hands a fresh registration to the call that rings now, or ends
// the call a pushed device woke up for if that call is already over.
func (m *callManager) deviceBack(b binding) {
	if lc := m.current(); lc != nil {
		if r := lc.ringer.Load(); r != nil && r.deviceBack(b) {
			return
		}
	}
	if b.instance == "" {
		return
	}
	key := deviceKey(b.user, b.instance, "")
	m.lateMu.Lock()
	lp, ok := m.late[key]
	delete(m.late, key)
	m.lateMu.Unlock()
	if ok && time.Now().Before(lp.until) {
		go m.lan.endPushedCall(b, lp, m.logger)
	}
}
