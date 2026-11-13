package main

// Line manager: one SIM, one call at a time. It connects the network call
// (imsCall, netstack.go) with a phone in the LAN (sipgo) and starts the audio
// bridge.
//
//   incoming:  network → allow-list → INVITE to all phones → whoever picks
//              up, we answer the network for them (Answer) → bridge;
//   outgoing:  phone → destination policy → Dial → 180 on network
//              ringing → 200 on answer → bridge;
//   echo test: phone → echo_ext → own voice through AMR-WB (no network);
//   internal:  phone → login or short number of another phone →
//              INVITE to all its devices → phone ↔ phone bridge.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

type lineCall struct {
	id     int64
	dir    string // in | out | echo
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	ims    imsCall
	leg    *rtpLeg
	format lanFormat
	dtmfPT int
	sdpVer uint64

	imsDone     chan struct{} // the network has ended the call
	imsDoneOnce sync.Once
	ringing     chan struct{} // out: the network reported ringing/early media
	ringOnce    sync.Once
	answered    atomic.Bool // in: already picked up (choosing the winner of the fork)
	dtmf        chan byte
	ringer      atomic.Pointer[ringer] // the devices being rung (ringer.go); a device that registers joins

	// Internal call: the leg of the second phone and the Call-IDs of the dialogs
	// with its devices (a re-INVITE finds its leg by them).
	peer        *rtpLeg
	peerFormat  lanFormat
	peerDTMF    int
	peerCallIDs []string

	// dialogs are the dialogs (sipgo IDs) with the phones of this call. A
	// request inside a dialog (re-INVITE, UPDATE, INFO) is acted on only when
	// the dialog is one of these (lanSIP.inDialog).
	dialogs map[string]bool
}

func (lc *lineCall) isPeerCall(callID string) bool {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	for _, id := range lc.peerCallIDs {
		if id == callID {
			return true
		}
	}
	return false
}

// addDialog records a dialog of this call; an empty ID (a dialog not
// established yet) is ignored.
func (lc *lineCall) addDialog(id string) {
	if id == "" {
		return
	}
	lc.mu.Lock()
	if lc.dialogs == nil {
		lc.dialogs = map[string]bool{}
	}
	lc.dialogs[id] = true
	lc.mu.Unlock()
}

func (lc *lineCall) ownsDialog(id string) bool {
	lc.mu.Lock()
	defer lc.mu.Unlock()
	return lc.dialogs[id]
}

type callManager struct {
	cfg    *Config
	sip    SIPConfig
	logger *slog.Logger
	dialer imsDialer // nil: no network (sip-test mode)
	lan    *lanSIP
	missed *missedLog // nil: missed calls are not recorded

	// How long to wait for silent devices after all live ones have declined (waitFork).
	forkGrace             time.Duration
	phoneIdle, phoneProbe time.Duration // silent RTP triggers a bounded SIP liveness check

	mu     sync.Mutex
	active *lineCall
	seq    int64

	// Pushed devices whose call ended before they came back (ringer.go).
	lateMu sync.Mutex
	late   map[string]latePush
}

func newCallManager(cfg *Config, sipCfg SIPConfig, dialer imsDialer, logger *slog.Logger) *callManager {
	return &callManager{cfg: cfg, sip: sipCfg, dialer: dialer, logger: logger, forkGrace: 8 * time.Second,
		phoneIdle: 30 * time.Second, phoneProbe: 5 * time.Second,
		missed: newMissedLog(cfg.MissedCalls, logger)}
}

func (m *callManager) acquire(dir string) (*lineCall, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active != nil {
		return nil, false
	}
	m.seq++
	ctx, cancel := context.WithCancel(context.Background())
	lc := &lineCall{
		id: m.seq, dir: dir, ctx: ctx, cancel: cancel,
		imsDone: make(chan struct{}), ringing: make(chan struct{}), dtmf: make(chan byte, 32),
		sdpVer: uint64(time.Now().Unix()),
	}
	m.active = lc
	return lc, true
}

func (m *callManager) release(lc *lineCall) {
	m.mu.Lock()
	if m.active == lc {
		m.active = nil
	}
	m.mu.Unlock()
	lc.cancel()
	lc.mu.Lock()
	leg, peer := lc.leg, lc.peer
	lc.mu.Unlock()
	if leg != nil {
		leg.Close()
	}
	if peer != nil {
		peer.Close()
	}
}

func (m *callManager) current() *lineCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active
}

// hangupNet hangs up the network call but waits no longer than 12 s: a BYE
// can hang on a transport the operator has cut (§86), and the line must not
// get stuck.
func (m *callManager) hangupNet(call imsCall) {
	if call == nil {
		return
	}
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		done <- call.Hangup(ctx)
	}()
	select {
	case err := <-done:
		if err != nil {
			m.logger.Warn("call: hanging up in the network", "err", err)
		}
	case <-time.After(12 * time.Second):
		m.logger.Warn("call: the network does not confirm the hangup, freeing the line without it")
	}
}

// shutdown is for the daemon exit: it hangs up the current call.
func (m *callManager) shutdown() {
	if lc := m.current(); lc != nil {
		lc.mu.Lock()
		call := lc.ims
		lc.mu.Unlock()
		m.hangupNet(call)
		lc.cancel()
	}
}

// networkDown leaves local calls alone: the phones and their RTP sockets
// outlive an IMS session. Daemon exit still uses shutdown.
func (m *callManager) networkDown() {
	if lc := m.current(); lc != nil && (lc.dir == "in" || lc.dir == "out") {
		lc.cancel()
	}
}

// onIMSEvent handles the events of network calls.
func (m *callManager) onIMSEvent(call imsCall, state CallState) {
	lc := m.current()
	if lc == nil || call == nil {
		return
	}
	lc.mu.Lock()
	if lc.dir == "out" && lc.ims == nil && call.Direction() == CallOutgoing &&
		state == CallStateDialing {
		lc.ims = call // needed to cancel the dialling (CANCEL) before the answer
	}
	match := lc.ims != nil && lc.ims.ID() == call.ID()
	lc.mu.Unlock()
	if !match {
		return
	}
	switch state {
	case CallStateRinging, CallStateEarlyMedia:
		lc.ringOnce.Do(func() { close(lc.ringing) })
	case CallStateEnded, CallStateFailed:
		lc.imsDoneOnce.Do(func() { close(lc.imsDone) })
	}
}

// --- Incoming from the network ---

// We reject network calls only with 6xx codes. On a 4xx/5xx the network tries to
// deliver the call through the CS domain (reginfo lists an MSC contact next
// to ours): the modem goes into CSFB on 3G, the IMS PDN drops, and the
// following calls bypass IMS (FINDINGS §87, 03.11 20:50). A 6xx forbids the
// proxy to try other branches (RFC 3261 §16.7).
const (
	rejectBusy    = 600 // Busy Everywhere
	rejectDecline = 603 // Decline
	rejectMedia   = 606 // Not Acceptable
)

func (m *callManager) incomingFromNetwork(call imsCall, from string) {
	masked := maskNumber(from)
	reject := func(code int, reason string) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := call.Reject(ctx, code, reason); err != nil {
			m.logger.Error("incoming: reject", "code", code, "err", err)
		}
	}
	if !m.cfg.IncomingAll && !numberAllowed(m.cfg.Allow, from) {
		m.logger.Info("incoming: declined (caller not allowed)", "from", masked)
		reject(rejectDecline, "Decline")
		m.missed.add(from, missedNotAllowed)
		return
	}
	lc, ok := m.acquire("in")
	if !ok {
		m.logger.Info("incoming: line busy", "from", masked)
		reject(rejectBusy, "Busy Everywhere")
		m.missed.add(from, missedLineBusy)
		return
	}
	lc.mu.Lock()
	lc.ims = call
	lc.mu.Unlock()
	go m.runIncoming(lc, call, from)
}

type forkResult struct {
	idx    int // index of the device in the list of bindings
	dlg    *sipgo.DialogClientSession
	sdp    []byte
	user   string
	secure bool // the device is on TLS: it got the offer with SRTP keys
	err    error
	code   int  // final SIP rejection code; 0 = no response (timeout, drop)
	busy   bool // 486/600: the device is busy
	alive  bool // the device answered something (100/180/…): the binding is alive
}

// forkOutcome is the result of waiting for the devices' responses.
type forkOutcome struct {
	win      forkResult // dlg != nil: picked up
	declined bool       // 603 from a live device: a person pressed "Decline"
	busy     bool       // one of the devices is busy
}

// waitFork waits for the responses from the devices of one call. The first
// to pick up wins. A 603 from any device ends the wait at once: a person has
// declined, there is no point in waiting for the rest. If all devices that
// showed signs of life have already declined and the silent ones (dead
// bindings: the phone left the Wi-Fi or changed its port while the
// registration has not expired yet) have sent nothing, it waits forkGrace
// more and finishes without waiting for their 32 s transaction timeout. gone
// means the caller has given up (the second result is true). slots is the
// number of devices so far: it grows when a device comes back during the
// ringing (ringer.go), and a device woken by a push counts from the start.
func (m *callManager) waitFork(ctx context.Context, slots func() int, results <-chan forkResult, alive <-chan int, gone <-chan struct{}) (forkOutcome, bool) {
	var out forkOutcome
	var isAlive, done []bool
	grow := func(k int) {
		for len(done) < k {
			isAlive, done = append(isAlive, false), append(done, false)
		}
	}
	pending := func() int {
		grow(slots())
		k := 0
		for i := range done {
			if !done[i] {
				k++
			}
		}
		return k
	}
	alivePending := func() int {
		k := 0
		for i := range isAlive {
			if isAlive[i] && !done[i] {
				k++
			}
		}
		return k
	}
	var grace <-chan time.Time
	for pending() > 0 {
		select {
		case i := <-alive:
			if i >= 0 {
				grow(i + 1)
				if !done[i] {
					isAlive[i] = true
					grace = nil // a live device is still ringing, wait for it
				}
			}
		case r := <-results:
			if r.idx >= 0 {
				grow(r.idx + 1)
				done[r.idx] = true
			}
			if r.err == nil {
				out.win = r
				return out, false
			}
			if r.code == 603 {
				out.declined = true
				return out, false
			}
			out.busy = out.busy || r.busy
			if pending() > 0 && alivePending() == 0 && grace == nil {
				grace = time.After(m.forkGrace)
			}
		case <-grace:
			return out, false
		case <-gone:
			return out, true
		case <-ctx.Done():
			return out, false
		}
	}
	return out, false
}

func (m *callManager) runIncoming(lc *lineCall, call imsCall, from string) {
	defer m.release(lc)
	masked := maskNumber(from)
	reject := func(code int, reason string) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := call.Reject(ctx, code, reason); err != nil {
			m.logger.Error("incoming: reject", "code", code, "err", err)
		}
	}
	r := m.newRinger("", callerUser(from), "incoming")
	if !r.plan(m.lan.reg.active()) {
		m.logger.Warn("incoming: no phone is connected, declining with 603", "from", masked)
		reject(rejectDecline, "Decline")
		m.missed.add(from, missedNoPhone)
		return
	}
	leg, err := m.lan.ports.open(m.logger)
	if err != nil {
		m.logger.Error("incoming: RTP", "err", err)
		reject(rejectDecline, "Decline")
		m.missed.add(from, missedError)
		return
	}
	lc.mu.Lock()
	lc.leg = leg
	lc.mu.Unlock()
	offer, err := m.lan.newLegOffer(lc, leg.Port(), uint64(lc.id))
	if err != nil {
		m.logger.Error("incoming: SRTP keys", "err", err)
		reject(rejectDecline, "Decline")
		m.missed.add(from, missedError)
		return
	}

	m.logger.Info("incoming: ringing the phones", "from", masked, "phones", len(r.live), "pushed", len(r.sleeping))
	ringCtx, ringCancel := context.WithTimeout(lc.ctx, time.Duration(m.sip.RingSec)*time.Second)
	defer ringCancel()
	r.launch(ringCtx, lc, offer)
	if err := call.Ring(); err != nil {
		m.logger.Warn("incoming: 180 to the network failed", "err", err)
	}
	out, callerGone := m.waitFork(ringCtx, r.slots, r.results, r.alive, lc.imsDone)
	if callerGone {
		m.logger.Info("incoming: the caller hung up before the answer", "from", masked)
		m.missed.add(from, missedHungUp)
		return // ringCancel → the phones get a CANCEL
	}
	ringCancel() // CANCEL to the other phones
	win := out.win
	if win.dlg == nil {
		select {
		case <-lc.imsDone:
			m.missed.add(from, missedHungUp)
			return
		default:
		}
		code, reason, what, why := rejectDecline, "Decline", "nobody answered", missedNoAnswer
		switch {
		case out.declined:
			what, why = "a phone declined", missedDeclined
		case out.busy:
			code, reason, why = rejectBusy, "Busy Everywhere", missedBusy
		}
		m.logger.Info("incoming: "+what, "from", masked, "code", code)
		reject(code, reason)
		m.missed.add(from, why)
		return
	}
	dlg := win.dlg
	defer dlg.Close()
	stopWatch := func() {}
	byePhone := func() {
		stopWatch()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = dlg.Bye(ctx)
	}
	ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = dlg.Ack(ackCtx)
	ackCancel()
	if err := m.lan.applyAnswer(lc, leg, win, offer); err != nil {
		m.logger.Error("incoming: the answer of the phone has no usable SDP", "err", err)
		byePhone()
		reject(rejectMedia, "Not Acceptable")
		m.missed.add(from, missedError)
		return
	}
	select {
	case <-lc.imsDone:
		m.logger.Info("incoming: the caller left at the moment of the answer", "from", masked)
		byePhone()
		m.missed.add(from, missedHungUp)
		return
	default:
	}
	ansCtx, ansCancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = call.Answer(ansCtx)
	ansCancel()
	if err != nil {
		m.logger.Error("incoming: answering in the network failed", "err", err)
		byePhone()
		m.missed.add(from, missedError)
		return
	}
	m.logger.Info("incoming: connected", "from", masked, "phone", win.user, "srtp", leg.secure())
	stopWatch = m.watchPhone(lc, leg, dlg, phoneTarget(dlg.InviteResponse))
	defer stopWatch()
	m.bridgeAndWait(lc, call, leg, dlg.Context().Done(), byePhone)
}

// --- Outgoing from a phone ---

type dialResult struct {
	call imsCall
	err  error
}

func (m *callManager) outgoingCall(req *sip.Request, tx sip.ServerTransaction, user, target string) {
	l := m.lan
	if m.dialer == nil {
		l.respond(req, tx, 503, "No Network (sip-test)")
		return
	}
	num, err := normalizeDialed(target, m.sip.DefaultCountry)
	if err != nil {
		l.respond(req, tx, 484, "Address Incomplete")
		return
	}
	if !dialAllowed(m.sip.DialAllow, num) {
		m.logger.Warn("outgoing: destination not allowed", "user", user, "to", maskNumber(num))
		l.respond(req, tx, 403, "Destination Not Allowed")
		return
	}
	plan, ok := l.chooseFromOffer(req)
	if !ok {
		l.respond(req, tx, 488, "Not Acceptable Here")
		return
	}
	lc, ok := m.acquire("out")
	if !ok {
		l.respond(req, tx, 486, "Busy Here")
		return
	}
	defer m.release(lc)
	dlg, err := l.dialogsFor(req.Transport()).ReadInvite(req, tx)
	if err != nil {
		m.logger.Error("outgoing: dialog", "err", err)
		l.respond(req, tx, 500, "Server Internal Error")
		return
	}
	defer dlg.Close()
	lc.addDialog(dlg.ID)
	_ = dlg.Respond(100, "Trying", nil)
	answer, leg, err := l.prepareLeg(lc, plan)
	if err != nil {
		m.logger.Error("outgoing: RTP", "err", err)
		_ = dlg.Respond(503, "Service Unavailable", nil)
		return
	}
	m.logger.Info("outgoing: dialling", "user", user, "to", maskNumber(num), "codec", plan.format.Name, "srtp", leg.secure())

	dialCtx, dialCancel := context.WithCancel(lc.ctx)
	defer dialCancel()
	resCh := make(chan dialResult, 1)
	go func() {
		c, err := m.dialer.Dial(dialCtx, num)
		resCh <- dialResult{call: c, err: err}
	}()
	ringing := lc.ringing
	for {
		select {
		case <-ringing:
			ringing = nil
			_ = dlg.Respond(180, "Ringing", nil)
		case <-dlg.Context().Done():
			m.logger.Info("outgoing: cancelled by the phone", "to", maskNumber(num))
			m.cancelDial(lc, dialCancel, resCh)
			return
		case r := <-resCh:
			if r.err != nil {
				code, reason := sipCodeFromDialErr(r.err)
				m.logger.Info("outgoing: not connected", "to", maskNumber(num), "code", code, "err", r.err)
				_ = dlg.Respond(code, reason, nil)
				return
			}
			lc.mu.Lock()
			lc.ims = r.call
			lc.mu.Unlock()
			if err := dlg.RespondSDP(answer); err != nil {
				m.logger.Error("outgoing: 200 OK to the phone", "err", err)
				m.hangupNet(r.call)
				return
			}
			m.logger.Info("outgoing: connected", "to", maskNumber(num))
			stopWatch := m.watchPhone(lc, leg, dlg, phoneTarget(req))
			defer stopWatch()
			m.bridgeAndWait(lc, r.call, leg, dlg.Context().Done(), func() {
				stopWatch()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = dlg.Bye(ctx)
			})
			return
		}
	}
}

// cancelDial handles a phone giving up before the answer: CANCEL to the
// network (through Hangup of the call from the dialing event) or
// cancellation of the Dial context, then it waits for the outcome.
func (m *callManager) cancelDial(lc *lineCall, dialCancel context.CancelFunc, resCh <-chan dialResult) {
	lc.mu.Lock()
	call := lc.ims
	lc.mu.Unlock()
	m.hangupNet(call)
	dialCancel()
	select {
	case r := <-resCh:
		if r.err == nil && r.call != nil {
			// The network answered just as we cancelled: hang up.
			m.hangupNet(r.call)
		}
	case <-time.After(40 * time.Second):
		m.logger.Warn("outgoing: the call attempt did not end after the cancel")
	}
}

// sipCodeFromDialErr returns the network's response code for the phone (503
// otherwise).
func sipCodeFromDialErr(err error) (int, string) {
	var de *dialError
	if errors.As(err, &de) && de.Code >= 400 && de.Code < 700 {
		switch de.Code {
		case 401, 407:
			return 503, "Service Unavailable"
		}
		reason := de.Reason
		if reason == "" {
			reason = "Call Failed"
		}
		return de.Code, reason
	}
	return 503, "Service Unavailable"
}

// --- Echo test ---

func (m *callManager) echoCall(req *sip.Request, tx sip.ServerTransaction, user string) {
	l := m.lan
	plan, ok := l.chooseFromOffer(req)
	if !ok {
		l.respond(req, tx, 488, "Not Acceptable Here")
		return
	}
	lc, ok := m.acquire("echo")
	if !ok {
		l.respond(req, tx, 486, "Busy Here")
		return
	}
	defer m.release(lc)
	dlg, err := l.dialogsFor(req.Transport()).ReadInvite(req, tx)
	if err != nil {
		l.respond(req, tx, 500, "Server Internal Error")
		return
	}
	defer dlg.Close()
	lc.addDialog(dlg.ID)
	answer, leg, err := l.prepareLeg(lc, plan)
	if err != nil {
		_ = dlg.Respond(503, "Service Unavailable", nil)
		return
	}
	if err := dlg.RespondSDP(answer); err != nil {
		return
	}
	m.logger.Info("echo test: connected", "user", user, "codec", plan.format.Name, "srtp", leg.secure())
	stopWatch := m.watchPhone(lc, leg, dlg, phoneTarget(req))
	defer stopWatch()
	ectx, ecancel := context.WithCancel(lc.ctx)
	go runEcho(ectx, leg, m.logger)
	select {
	case <-dlg.Context().Done():
	case <-lc.ctx.Done():
		stopWatch()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = dlg.Bye(ctx)
		cancel()
	}
	ecancel()
	m.logger.Info("echo test: ended", "user", user)
}

// --- Phone-to-phone call ---

// internalCall handles a phone dialling the login or short number of another
// phone: all devices of that phone ring, the first to pick up gets the call,
// the audio goes over the Wi-Fi through the bridge, and the network and the
// SIM take no part. The call does occupy the line: an incoming call from the
// network meanwhile gets 600 (busy).
func (m *callManager) internalCall(req *sip.Request, tx sip.ServerTransaction, user, peer string) {
	l := m.lan
	if peer == user {
		l.respond(req, tx, 486, "Busy Here")
		return
	}
	plan, ok := l.chooseFromOffer(req)
	if !ok {
		l.respond(req, tx, 488, "Not Acceptable Here")
		return
	}
	r := m.newRinger(peer, user, "internal call")
	if !r.plan(l.reg.forUser(peer)) {
		m.logger.Info("internal call: the phone is offline", "from", user, "to", peer)
		l.respond(req, tx, 480, "Temporarily Unavailable")
		return
	}
	lc, ok := m.acquire("internal")
	if !ok {
		l.respond(req, tx, 486, "Busy Here")
		return
	}
	defer m.release(lc)
	dlg, err := l.dialogsFor(req.Transport()).ReadInvite(req, tx)
	if err != nil {
		l.respond(req, tx, 500, "Server Internal Error")
		return
	}
	defer dlg.Close()
	lc.addDialog(dlg.ID)
	_ = dlg.Respond(100, "Trying", nil)
	answer, legA, err := l.prepareLeg(lc, plan)
	if err != nil {
		_ = dlg.Respond(503, "Service Unavailable", nil)
		return
	}
	f := plan.format
	legB, err := l.ports.open(m.logger)
	if err != nil {
		_ = dlg.Respond(503, "Service Unavailable", nil)
		return
	}
	lc.mu.Lock()
	lc.peer = legB
	lc.mu.Unlock()
	offerB, err := l.newLegOffer(lc, legB.Port(), uint64(lc.id)+1<<32)
	if err != nil {
		_ = dlg.Respond(503, "Service Unavailable", nil)
		return
	}

	m.logger.Info("internal call: ringing", "from", user, "to", peer, "devices", len(r.live), "pushed", len(r.sleeping))
	ringCtx, ringCancel := context.WithTimeout(lc.ctx, time.Duration(m.sip.RingSec)*time.Second)
	defer ringCancel()
	r.launch(ringCtx, lc, offerB)
	_ = dlg.Respond(180, "Ringing", nil)
	out, callerGone := m.waitFork(ringCtx, r.slots, r.results, r.alive, dlg.Context().Done())
	if callerGone {
		m.logger.Info("internal call: cancelled by the caller", "from", user, "to", peer)
		return // ringCancel → the devices get a CANCEL
	}
	ringCancel()
	win := out.win
	if win.dlg == nil {
		code, reason, what := 480, "Temporarily Unavailable", "not answered"
		switch {
		case out.declined:
			code, reason, what = 603, "Decline", "declined by the called phone"
		case out.busy:
			code, reason = 486, "Busy Here"
		}
		m.logger.Info("internal call: "+what, "from", user, "to", peer, "code", code)
		_ = dlg.Respond(code, reason, nil)
		return
	}
	dlgB := win.dlg
	defer dlgB.Close()
	stopA, stopB := func() {}, func() {}
	byeB := func() {
		stopB()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = dlgB.Bye(ctx)
	}
	byeA := func() {
		stopA()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = dlg.Bye(ctx)
	}
	ackCtx, ackCancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = dlgB.Ack(ackCtx)
	ackCancel()
	fB, dtmfB, err := l.answerToLeg(legB, win, offerB)
	if err != nil {
		m.logger.Error("internal call: the answering phone sent no usable SDP", "err", err)
		byeB()
		_ = dlg.Respond(488, "Not Acceptable Here", nil)
		return
	}
	lc.mu.Lock()
	lc.peerFormat, lc.peerDTMF = fB, dtmfB
	lc.mu.Unlock()
	select {
	case <-dlg.Context().Done():
		byeB()
		return
	default:
	}
	if err := dlg.RespondSDP(answer); err != nil {
		m.logger.Error("internal call: 200 OK to the caller", "err", err)
		byeB()
		return
	}
	m.logger.Info("internal call: connected", "from", user, "to", win.user, "codecs", f.Name+" <-> "+fB.Name,
		"srtp", fmt.Sprintf("%t <-> %t", legA.secure(), legB.secure()))
	stopA = m.watchPhone(lc, legA, dlg, phoneTarget(req))
	stopB = m.watchPhone(lc, legB, dlgB, phoneTarget(dlgB.InviteResponse))
	defer stopA()
	defer stopB()
	bctx, bcancel := context.WithCancel(lc.ctx)
	defer bcancel()
	go runBridge(bctx, legA, legB, m.sip.JitterFrames, m.logger)
	select {
	case <-dlg.Context().Done():
		m.logger.Info("internal call: ended by the caller", "from", user)
		bcancel()
		byeB()
	case <-dlgB.Context().Done():
		m.logger.Info("internal call: ended by the called phone", "to", win.user)
		bcancel()
		byeA()
	case <-lc.ctx.Done():
		bcancel()
		byeA()
		byeB()
	}
}

// --- Common bridge ---

// bridgeAndWait carries the audio between the network and the phone until
// either side ends the call.
func (m *callManager) bridgeAndWait(lc *lineCall, call imsCall, leg *rtpLeg, phoneGone <-chan struct{}, byePhone func()) {
	netLeg, err := newIMSLeg(call, m.logger)
	if err != nil {
		m.logger.Error("bridge: network media", "err", err)
		m.hangupNet(call)
		byePhone()
		return
	}
	m.logger.Info("bridge: audio", "network", netLeg.describe(), "phone", lc.format.Name)
	leg.setDTMFHandler(func(d byte) {
		select {
		case lc.dtmf <- d:
		default:
		}
	})
	go m.dtmfSender(lc, call)
	bctx, bcancel := context.WithCancel(lc.ctx)
	defer bcancel()
	go runBridge(bctx, netLeg, leg, m.sip.JitterFrames, m.logger)

	var maxCall <-chan time.Time
	if m.cfg.MaxCallSec > 0 {
		maxCall = time.After(time.Duration(m.cfg.MaxCallSec) * time.Second)
	}
	select {
	case <-phoneGone:
		m.logger.Info("call: the phone hung up")
		bcancel()
		m.hangupNet(call)
	case <-lc.imsDone:
		m.logger.Info("call: the other party hung up")
		bcancel()
		byePhone()
	case <-maxCall:
		m.logger.Info("call: max_call_sec reached, hanging up")
		bcancel()
		m.hangupNet(call)
		byePhone()
	case <-lc.ctx.Done():
		bcancel()
		m.hangupNet(call)
		byePhone()
	}
}

// dtmfSender sends the tones from the phone to the network one at a time
// (SendDTMF blocks for the duration of a tone).
func (m *callManager) dtmfSender(lc *lineCall, call imsCall) {
	for {
		select {
		case <-lc.ctx.Done():
			return
		case d := <-lc.dtmf:
			ctx, cancel := context.WithTimeout(lc.ctx, 5*time.Second)
			if err := call.SendDTMF(ctx, string(d)); err != nil {
				m.logger.Warn("DTMF to the network", "err", err)
			}
			cancel()
		}
	}
}

// phoneDTMF handles a tone that came in a SIP INFO.
func (m *callManager) phoneDTMF(d byte) {
	if lc := m.current(); lc != nil {
		select {
		case lc.dtmf <- d:
		default:
		}
	}
}
