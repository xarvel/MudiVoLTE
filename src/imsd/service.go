package main

// Service mode (S5): the daemon holds the whole chain itself and restores it.
//
//	modem in external mode → LTE → IMS PDN (a data call, datacall.go) → /32 routes
//	to the P-CSCF → registration, calls, SMS → watching → on a failure, tear
//	down and bring up again; after a visit to 3G and repeated failures, a
//	radio restart.
//
// The SIP server for the phones lives as long as the process: while IMS is
// being brought up again, the phones stay registered and their calls get
// 503. The service does not take on switching the modem to external mode
// (that means a modem reboot): `mudi-volte setup` does that.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/xarvel/MudiVoLTE/volte/ipsec"
	"github.com/xarvel/MudiVoLTE/volte/reg"
	"github.com/xarvel/MudiVoLTE/volte/sms"
)

// Reasons for the end of a session: they decide whether a radio restart is
// needed.
const (
	endStop        = "stop"
	endNotExternal = "not-external"
	endNoLTE       = "no-lte"
	endPDN         = "pdn-failed"
	endHelper      = "helper-unusable" // the helper cannot work on this installation
	endHelperFail  = "helper-failed"   // the data call failed on the router, without the network
	endPDNLost     = "pdn-lost"
	endRAT         = "rat-fallback"
	endReg         = "registration-failed"
	endSetup       = "setup-failed"
)

// pdnGone tells whether a session that ended for reason has lost its PDN:
// the network dropped it, the interface lost its address, or the helper that
// held the data call is gone and the modem drops the call after it. The
// registration was bound to the address of that PDN, so nothing reaches the
// P-CSCF any more.
func pdnGone(reason string) bool {
	return reason == endPDNLost || reason == endHelperFail
}

// regGrace is how long we put up with no registration while the PDN is alive.
const regGrace = 5 * time.Minute

// maxRadioCycles caps the radio restarts per hour: each one takes down the
// router's Internet, and an operator without VoLTE for the SIM refuses
// forever.
const maxRadioCycles = 3

// netSwitch holds the current IMS stack for the line manager; nil until the
// network is up.
type netSwitch struct {
	mu sync.Mutex
	st *netStack
}

func (n *netSwitch) set(st *netStack) {
	n.mu.Lock()
	n.st = st
	n.mu.Unlock()
}

func (n *netSwitch) Dial(ctx context.Context, to string) (imsCall, error) {
	n.mu.Lock()
	st := n.st
	n.mu.Unlock()
	if st == nil {
		return nil, &dialError{Code: 503, Reason: "Service Unavailable"}
	}
	return st.Dial(ctx, to)
}

type service struct {
	cfg   *Config
	log   *slog.Logger
	link  *ATLink
	modem *modem
	state *stateWriter
	net   *netSwitch
	mgr   *callManager // nil without a sip block
	sms   *smsBridge   // nil without the sip and sms blocks
	// sleep is how the loop waits between sessions; replaced in tests.
	sleep func(ctx context.Context, d time.Duration) error
	// sweep removes the XFRM entries of ours a predecessor left behind
	// (sweepIPsec); nil: none to look for. Replaced in tests.
	sweep func(ctx context.Context) (states, policies int, err error)
	// crash counts the processes in a row that ended without a stop
	// (crashes.go); nil: none counted.
	crash *crashCount
	// up brings IMS up and holds it for one session; nil: bringUp. Replaced
	// in tests.
	up func(ctx context.Context, tr *regTracker) (string, error)

	ratMu      sync.Mutex
	lastNonLTE time.Time
}

func runService(cfg *Config, logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	link := newATLink()
	s := &service{cfg: cfg, log: logger, link: link, modem: newModem(link, logger),
		state: newStateWriter(cfg.stateFile(), logger), net: &netSwitch{}, sleep: sleepCtx,
		sweep: sweepIPsec(cfg), crash: startCrashCount(crashFile(cfg), logger)}
	s.state.update(func(st *serviceState) { st.CrashRestarts = s.crash.n })
	healthy := time.AfterFunc(crashHealthy, func() {
		if s.crash.healthy() {
			s.state.update(func(st *serviceState) { st.CrashRestarts = 0 })
		}
	})
	defer healthy.Stop()
	// Every return below is an end the daemon chose, with an error or after a
	// stop: the next start is no restart after a crash. A panic, a kill or an
	// exit elsewhere never gets there.
	end := func(err error) error {
		healthy.Stop()
		s.crash.stopped()
		return err
	}
	if err := cfg.checkIMSProfile(); err != nil {
		s.state.fail(err)
		return end(fmt.Errorf("service: %w", err))
	}
	if cfg.SIP != nil {
		sc := cfg.SIP.withDefaults()
		sc.PhonesFile = cfg.phonesFile()
		sc.PushFile = cfg.pushFile()
		s.mgr = newCallManager(cfg, sc, s.net, logger)
		lan, err := startLANSIP(sc, s.mgr, logger)
		if err != nil {
			s.state.fail(fmt.Errorf("SIP server: %w", err))
			return end(fmt.Errorf("service: SIP: %w", err))
		}
		defer lan.Close()
		s.state.phones = lan.onlineUsers
		s.state.secure = lan.secureUsers
		if cfg.SMS != nil {
			s.sms = newSMSBridge(*cfg.SMS, cfg.smsInbox(), lan, logger)
			lan.setSMS(s.sms, s.sms.phoneOnline)
			go s.sms.run(ctx)
		}
		if sc.ProvisionPort > 0 {
			number := func() string { return s.state.snapshot().Number }
			if prov, err := startProvisioning(sc, lan.port, lan.tlsPort, number, logger); err != nil {
				logger.Warn("phone setup by QR code is off", "err", err)
			} else {
				defer prov.Close()
			}
		}
	}
	killStaleDSI(cfg.dsiHelper(), logger)
	logger.Info("service: starting", "sip", cfg.SIP != nil, "incoming_all", cfg.IncomingAll,
		"allow", len(cfg.Allow), "codecs", strings.Join(callConfig(cfg, "", logger).Codecs, ","))
	s.loop(ctx)
	if s.mgr != nil {
		s.mgr.shutdown()
	}
	if err := s.removeOwnedIPsec(context.Background(), "shutdown"); err != nil {
		logger.Warn("service: could not remove owned IPsec", "err", err)
	}
	s.state.update(func(st *serviceState) { st.Phase, st.Registered = "stopped", false })
	logger.Info("service: stopped")
	return end(nil)
}

// sweepIPsec removes the XFRM entries of ours, with the tool that installs
// them (ipsec_tool): ip is the fallback for a firmware where netlink
// misbehaves, so the sweep does not depend on netlink there either.
func sweepIPsec(cfg *Config) func(ctx context.Context) (int, int, error) {
	var r ipsec.Runner = ipsec.Default()
	if cfg.IPsecTool == "ip" {
		r = ipsec.ExecRunner{}
	}
	return func(ctx context.Context) (int, int, error) { return ipsec.RemoveOwnedWith(ctx, r) }
}

// removeOwnedIPsec sweeps entries left by a process that could not run the
// in-memory registration teardown. The reqid owner tag keeps unrelated IPsec
// states and policies out of the sweep.
func (s *service) removeOwnedIPsec(parent context.Context, stage string) error {
	if s.sweep == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	states, policies, err := s.sweep(ctx)
	if states != 0 || policies != 0 {
		s.log.Warn("service: removed owned IPsec entries", "stage", stage, "states", states, "policies", policies)
	}
	return err
}

// sweepStale removes what a predecessor that died left in the SAD and SPD
// and tells whether that is done. A failure does not keep the line down:
// the entries left cannot keep a registration out (a new one takes fresh
// random ports and SPIs, and should a selector of it meet a stale policy
// all the same, the attempt that fails on it removes that policy on its way
// back, see 4.1 of PROTOCOLS.md). The loop tries again before each session
// until the sweep succeeds.
func (s *service) sweepStale(ctx context.Context, stage string) bool {
	if err := s.removeOwnedIPsec(ctx, stage); err != nil {
		s.log.Warn("service: stale IPsec entries not removed, trying again before the next session",
			"stage", stage, "err", err)
		return false
	}
	return true
}

func (s *service) loop(ctx context.Context) {
	s.crashWait(ctx)
	stage, swept := "startup", false // the sweep of stale IPsec entries
	var lastLost time.Time
	var cycles []time.Time
	failures := 0 // sessions that failed in a row: the wait grows with them
	// strikes counts the failures the radio or the network had a say in, in
	// a row: since the last registration or radio restart, either of which
	// starts the count anew.
	strikes := 0
	for ctx.Err() == nil {
		if !swept {
			swept, stage = s.sweepStale(ctx, stage), "retry"
		}
		started := time.Now()
		reason, registered, err := s.session(ctx)
		if ctx.Err() != nil {
			return
		}
		s.log.Warn("service: IMS session ended", "reason", reason, "err", err)
		if err != nil {
			s.state.fail(fmt.Errorf("%s: %w", reason, err))
		}
		if time.Since(started) > 30*time.Minute {
			failures, strikes = 0, 0 // ran for a long time: start counting failures anew
		}
		if registered {
			// The line was up: what failed before has nothing to do with the end
			// of this session. The wait still grows: a registration that stands
			// for seconds and goes again must not make the loop register every
			// 5 s; only a session of 30 minutes resets it.
			strikes = 0
		}
		failures++
		if reason != endHelper && reason != endHelperFail {
			strikes++
		}
		s.state.update(func(st *serviceState) {
			st.Phase, st.Registered = "recovering", false
			st.Restarts++
		})

		cycle := false
		switch reason {
		case endRAT, endReg:
			cycle = true
		case endPDNLost:
			// After a visit to 3G, bringing the PDN up again is not enough (§87);
			// without traces of 3G the radio is restarted only on the second drop
			// in a row.
			cycle = s.sawNonLTE(3*time.Minute) || (!lastLost.IsZero() && time.Since(lastLost) < 15*time.Minute)
			lastLost = time.Now()
		case endPDN, endNoLTE, endSetup:
			cycle = strikes >= 2
		case endHelper, endHelperFail:
			// Neither the radio nor the network had a say in it, and a radio
			// restart takes the router's Internet down for nothing (§131):
			// only the wait grows, and the next refusal is not the second.
		case endNotExternal:
			failures, strikes = 0, 0 // not a failure: wait until the modem is put back into external mode
			_ = s.sleep(ctx, 30*time.Second)
			continue
		}
		cycles = recentOnly(cycles, time.Hour)
		if cycle && len(cycles) >= maxRadioCycles {
			s.log.Warn("service: radio restart skipped", "in_last_hour", len(cycles))
			cycle = false
		}
		if cycle {
			cycles = append(cycles, time.Now())
			s.state.update(func(st *serviceState) { st.Phase = "radio-restart" })
			if err := s.modem.radioCycle(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("service: radio restart", "err", err)
			}
			// That was the measure: the next failure is a first again, and it
			// takes another one after it for the next restart.
			strikes = 0
		}
		_ = s.sleep(ctx, retryDelay(failures))
	}
}

// crashWait holds back the first session of a process that procd started
// again after its predecessor ended without a stop: the longer the run of
// such ends, the longer the wait (crashDelay), so that a daemon that keeps
// dying does not place a data call and register with the operator every
// 10 s, each one a new PDN and a new REGISTER.
func (s *service) crashWait(ctx context.Context) {
	if s.crash == nil || s.crash.n == 0 {
		return
	}
	n, d := s.crash.n, crashDelay(s.crash.n)
	s.log.Warn("service: started again after the daemon ended without a stop", "in_a_row", n, "wait", d)
	msg := fmt.Sprintf("the daemon ended without a stop %d time(s) in a row", n)
	if d > 0 {
		msg += fmt.Sprintf("; waiting %s before connecting to the operator", d)
	}
	s.state.update(func(st *serviceState) { st.CrashRestarts = n })
	s.state.fail(errors.New(msg))
	if d == 0 {
		return
	}
	s.state.update(func(st *serviceState) { st.Phase, st.Registered = "recovering", false })
	_ = s.sleep(ctx, d)
}

// recentOnly returns the timestamps no older than window.
func recentOnly(ts []time.Time, window time.Duration) []time.Time {
	out := ts[:0]
	for _, t := range ts {
		if time.Since(t) < window {
			out = append(out, t)
		}
	}
	return out
}

func retryDelay(failures int) time.Duration {
	steps := []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute}
	if failures-1 < len(steps) && failures > 0 {
		return steps[failures-1]
	}
	return 5 * time.Minute
}

func (s *service) noteRAT(rat string) {
	if rat == "3G" || rat == "2G" {
		s.ratMu.Lock()
		s.lastNonLTE = time.Now()
		s.ratMu.Unlock()
	}
	s.state.update(func(st *serviceState) { st.RAT = rat })
}

func (s *service) sawNonLTE(window time.Duration) bool {
	s.ratMu.Lock()
	defer s.ratMu.Unlock()
	return !s.lastNonLTE.IsZero() && time.Since(s.lastNonLTE) < window
}

// session is one full bring-up of IMS and its life until a failure or a stop.
// registered tells whether the line got as far as a registration.
func (s *service) session(ctx context.Context) (reason string, registered bool, err error) {
	up := s.up
	if up == nil {
		up = s.bringUp
	}
	tr := newRegTracker()
	reason, err = up(ctx, tr)
	return reason, tr.stood(), err
}

func (s *service) bringUp(ctx context.Context, tr *regTracker) (string, error) {
	s.state.update(func(st *serviceState) {
		st.Phase, st.Registered = "modem", false
		st.Interface, st.Address, st.PCSCF = "", "", nil
	})
	ext, err := s.modem.externalMode(ctx)
	if err != nil {
		return endSetup, fmt.Errorf("modem: %w", err)
	}
	if !ext {
		return endNotExternal, errors.New("the modem is not in External VoLTE mode (run: mudi-volte setup)")
	}
	if err := s.modem.waitService(ctx, 3*time.Minute); err != nil {
		return endNoLTE, err
	}
	if _, rat, err := s.modem.radio(ctx); err == nil {
		s.noteRAT(rat)
	}

	profile := imsProfile(ctx, s.cfg, s.link)
	s.state.update(func(st *serviceState) { st.Phase = "pdn" })
	call, err := startDataCall(ctx, s.cfg, profile, s.log)
	switch {
	case isUnusable(err):
		return endHelper, err
	case isHostSide(err):
		return endHelperFail, err
	case err != nil:
		return endPDN, err
	}
	defer call.Stop()

	env, reason, err := s.waitPDN(ctx, profile, call)
	if err != nil {
		return reason, err
	}
	routes, err := addHostRoutes(env.iface, env.pcscf)
	defer routes.remove()
	if err != nil {
		return endSetup, err
	}
	ensureFirewall(s.log)
	s.state.update(func(st *serviceState) {
		st.Phase, st.Interface, st.Address = "registering", env.iface, env.local.String()
		st.PCSCF = nil
		for _, ip := range env.pcscf {
			st.PCSCF = append(st.PCSCF, ip.String())
		}
	})

	st, err := buildStack(ctx, s.cfg, s.link, env, s.log)
	if err != nil {
		return endSetup, err
	}
	s.wire(st)
	s.net.set(st)
	defer s.net.set(nil)

	stopReg := s.holdRegistration(ctx, st, tr)

	reason, werr := s.watch(ctx, call, env, tr)
	if reason != endStop {
		s.log.Warn("service: tearing IMS down", "reason", reason, "err", werr)
	}
	if s.mgr != nil {
		s.mgr.networkDown() // local calls and phone registrations survive an IMS restart
	}
	stopReg(reason)
	return reason, werr
}

// holdRegistration keeps st registered for the life of a session. The
// function it returns ends the registration for the reason the session ended
// with and waits until it is gone: with a de-REGISTER, except when the PDN is
// gone (pdnGone). Then the request could not leave and its answer could not
// come, and the 5 s of waiting for it went into every recovery of the line;
// the registration left behind is replaced by the one of the next session
// (reg.ErrAccessLost).
func (s *service) holdRegistration(ctx context.Context, st *netStack, tr *regTracker) (stop func(reason string)) {
	regCtx, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		st.reg.Run(regCtx, func(rs reg.Status, err error) { s.onRegStatus(st, tr, rs, err) })
	}()
	return func(reason string) {
		if pdnGone(reason) {
			cancel(reg.ErrAccessLost)
		} else {
			cancel(nil)
		}
		select {
		case <-done:
		case <-time.After(15 * time.Second):
			s.log.Warn("service: registration did not stop in 15 s")
		}
	}
}

func (s *service) wire(st *netStack) {
	st.sms.OnMessage = func(m sms.Message) error {
		err := saveSMS(s.cfg, s.log, m)
		if err == nil && s.sms != nil {
			s.sms.kick() // to the phones now, not at the next read of the spool
		}
		return err
	}
	if s.mgr != nil {
		st.onIncoming = func(c *netCall, from string) { s.mgr.incomingFromNetwork(c, from) }
		st.onEvent = func(c *netCall, cs CallState) { s.mgr.onIMSEvent(c, cs) }
		return
	}
	st.onIncoming = func(c *netCall, from string) { handleIncomingCall(c, from, s.cfg, s.log) }
}

func (s *service) onRegStatus(st *netStack, tr *regTracker, rs reg.Status, err error) {
	tr.set(rs)
	switch rs {
	case reg.StatusRegistered:
		number := ""
		if b, ok := st.reg.Binding(); ok {
			number = uriNumber(b.Preferred)
		}
		s.log.Info("service: registered", "number", maskNumber(number))
		s.state.update(func(x *serviceState) {
			x.Phase, x.Registered, x.Number = "registered", true, number
		})
	case reg.StatusFailed:
		s.log.Warn("service: registration failed", "err", err)
		s.state.update(func(x *serviceState) { x.Phase, x.Registered = "registering", false })
		s.state.fail(err)
	case reg.StatusRegistering:
		s.state.update(func(x *serviceState) { x.Phase, x.Registered = "registering", false })
	}
}

// waitPDN waits for the address: after NET_IS_CONN it does not appear on the
// interface at once. A failure ends the session with the reason it returns:
// pdn-failed, or helper-failed when the helper died or someone else stopped
// it meanwhile, as in watch.
func (s *service) waitPDN(ctx context.Context, profile int, call *dataCall) (pdnEnv, string, error) {
	var last error
	for i := 0; i < 10; i++ {
		env, err := discoverPDN(ctx, s.cfg, s.link, profile, s.log)
		if err == nil {
			return env, "", nil
		}
		last = err
		t := time.NewTimer(2 * time.Second)
		select {
		case <-call.Down():
			t.Stop()
			reason, err := callDown(call, endPDN)
			return pdnEnv{}, reason, err
		case <-ctx.Done():
			t.Stop()
			return pdnEnv{}, endPDN, ctx.Err()
		case <-t.C:
		}
	}
	return pdnEnv{}, endPDN, last
}

// callDown is the end of a session whose data call is down (Down is
// closed): byNetwork when the network ended the call, helper-failed when
// the helper died or someone else stopped it. Then the call is placed again,
// with no word against the radio.
func callDown(call *dataCall, byNetwork string) (string, error) {
	err := errors.New(call.Reason())
	if !call.ByNetwork() {
		return endHelperFail, err
	}
	return byNetwork, err
}

// watch waits for a failure: the PDN is gone (a dsi event or the address has
// disappeared), the modem has fallen back to 3G, or there has been no
// registration for long; it updates the state along the way.
func (s *service) watch(ctx context.Context, call *dataCall, env pdnEnv, tr *regTracker) (string, error) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	nonLTE := 0
	for n := 1; ; n++ {
		select {
		case <-ctx.Done():
			return endStop, nil
		case <-call.Down():
			return callDown(call, endPDNLost)
		case <-tick.C:
		}
		if ip, err := firstIPv4(env.iface); err != nil || !ip.Equal(env.local) {
			return endPDNLost, fmt.Errorf("%s lost the IMS address", env.iface)
		}
		if n%2 == 0 { // every 10 s: radio access type and the list of phones
			if _, rat, err := s.modem.radio(ctx); err == nil {
				s.noteRAT(rat)
				if rat == "3G" || rat == "2G" {
					nonLTE++
				} else {
					nonLTE = 0
				}
				if nonLTE >= 3 {
					return endRAT, fmt.Errorf("the modem stays on %s", rat)
				}
			}
		}
		if d := tr.unhealthyFor(); d > regGrace {
			return endReg, fmt.Errorf("not registered for %s", d.Round(time.Second))
		}
	}
}

// regTracker tracks since when there has been no registration (switching
// between registering and failed does not reset the count), and whether
// there has been one at all.
type regTracker struct {
	mu       sync.Mutex
	badSince time.Time
	ever     bool
}

func newRegTracker() *regTracker { return &regTracker{badSince: time.Now()} }

func (t *regTracker) set(s reg.Status) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if s == reg.StatusRegistered {
		t.badSince, t.ever = time.Time{}, true
	} else if t.badSince.IsZero() {
		t.badSince = time.Now()
	}
}

// stood tells whether the session got as far as a registration.
func (t *regTracker) stood() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ever
}

func (t *regTracker) unhealthyFor() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.badSince.IsZero() {
		return 0
	}
	return time.Since(t.badSince)
}

// uriNumber — "tel:+447700…" / "sip:+447700…@domain;user=phone" → "+447700…".
// The temporary identity derived from the IMSI (sip:IMSI@…) does not count
// as a number.
func uriNumber(uri string) string {
	u := strings.Trim(uri, "<> ")
	u = strings.TrimPrefix(strings.TrimPrefix(u, "tel:"), "sip:")
	if i := strings.IndexAny(u, "@;"); i >= 0 {
		u = u[:i]
	}
	if d := digitsOnly(u); d != "" && strings.HasPrefix(u, "+") {
		return "+" + d
	}
	return ""
}

// hostRoutes are the /32 routes to the P-CSCF through the IMS interface
// (§71): the default route points into the internet PDN.
type hostRoutes struct {
	iface string
	dst   []string
}

func addHostRoutes(iface string, ips []net.IP) (*hostRoutes, error) {
	r := &hostRoutes{iface: iface}
	for _, ip := range ips {
		dst := ip.String() + "/32"
		if out, err := exec.Command("ip", "route", "replace", dst, "dev", iface).CombinedOutput(); err != nil {
			return r, fmt.Errorf("ip route replace %s dev %s: %v: %s", dst, iface, err, bytes.TrimSpace(out))
		}
		r.dst = append(r.dst, dst)
	}
	return r, nil
}

func (r *hostRoutes) remove() {
	if r == nil {
		return
	}
	for _, dst := range r.dst {
		_ = exec.Command("ip", "route", "del", dst, "dev", r.iface).Run()
	}
}

// firewallRules are the fw4 rules for IMS (§87, §88): the IMS interface is
// outside the fw4 zones. ESP is always let in, and traffic the kernel has
// decrypted (new TCP connections from the P-CSCF to port-s) is let in when it
// came through IPsec. A package file in /usr/share/nftables.d/chain-pre/input/
// installs these rules permanently; this is a safety net in case the chain
// was reloaded without it.
var firewallRules = []struct{ marker, rule string }{
	{"meta l4proto esp", `insert rule inet fw4 input iifname "rmnet_data*" meta l4proto esp counter accept comment "mudi-volte: IMS ESP in"`},
	{"meta ipsec exists", `insert rule inet fw4 input iifname "rmnet_data*" meta ipsec exists counter accept comment "mudi-volte: IMS IPsec in"`},
}

func ensureFirewall(log *slog.Logger) {
	out, err := exec.Command("nft", "list", "chain", "inet", "fw4", "input").CombinedOutput()
	if err != nil {
		log.Warn("firewall: cannot read fw4 input chain", "err", err)
		return
	}
	for _, r := range firewallRules {
		if bytes.Contains(out, []byte(r.marker)) {
			continue
		}
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(r.rule + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			log.Warn("firewall: rule not added", "rule", r.marker, "err", err, "out", string(bytes.TrimSpace(out)))
			continue
		}
		log.Warn("firewall: rule was missing, added to the running chain", "rule", r.marker)
	}
}
