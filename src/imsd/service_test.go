package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/call"
	"github.com/xarvel/MudiVoLTE/volte/reg"
	volsim "github.com/xarvel/MudiVoLTE/volte/sim"
	"github.com/xarvel/MudiVoLTE/volte/sipnet"
	"github.com/xarvel/MudiVoLTE/volte/sms"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// --- Modem replies (live samples from the Mudi, 03.11) ---

func TestModemParsers(t *testing.T) {
	if v, ok := parseQCFGIMS("\r\n+QUIMSUB: 1,\"SUB1\",\"L\"\r\n\r\n+QCFG: \"ims\",2,0\r\n\r\nOK\r\n"); !ok || v != 2 {
		t.Errorf("QCFG ims: %d %v", v, ok)
	}
	if _, ok := parseQCFGIMS("\r\n+QCFG: \"usbnet\",1\r\nOK"); ok {
		t.Error("a foreign QCFG taken for ims")
	}
	if v, ok := parseCEREG("\r\n+CEREG: 0,1\r\n\r\nOK\r\n"); !ok || v != 1 {
		t.Errorf("CEREG: %d %v", v, ok)
	}
	if v, ok := parseCOPSAct("\r\n+COPS: 0,0,\"Operator\",13\r\n\r\nOK\r\n"); !ok || v != 13 || ratFromAct(v) != "LTE" {
		t.Errorf("COPS: %d %v", v, ok)
	}
	for act, want := range map[int]string{7: "LTE", 12: "NR", 2: "3G", 6: "3G", 0: "2G", 99: ""} {
		if got := ratFromAct(act); got != want {
			t.Errorf("AcT %d: %q, want %q", act, got, want)
		}
	}
}

// fakeModem is an ATLink with canned answers per command; QUIMSUB is always
// confirmed.
func fakeModem(answers map[string]string, log *[]string) *modem {
	const pin = "\r\n+QUIMSUB: 1,\"SUB1\",\"L\"\r\n"
	link := &ATLink{Retries: 1, Run: func(_ context.Context, cmd string) (string, error) {
		if cmd == "AT+QUIMSUB=1;+QUIMSUB?" {
			return pin + "\r\nOK\r\n", nil
		}
		prefix := ""
		if inner, ok := strings.CutPrefix(cmd, "AT+QUIMSUB=1;+QUIMSUB?;"); ok {
			cmd, prefix = "AT"+inner, pin
		}
		if log != nil {
			*log = append(*log, cmd)
		}
		if a, ok := answers[cmd]; ok {
			return prefix + a, nil
		}
		return prefix + "\r\nOK\r\n", nil
	}}
	m := newModem(link, quietLog())
	m.sleep = func(ctx context.Context, d time.Duration) error { return ctx.Err() }
	return m
}

func TestModemRadioCycle(t *testing.T) {
	var cmds []string
	m := fakeModem(map[string]string{
		"AT+CEREG?": "\r\n+CEREG: 0,1\r\nOK",
		"AT+COPS?":  "\r\n+COPS: 0,0,\"Op\",7\r\nOK",
	}, &cmds)
	if err := m.radioCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(cmds, " ")
	if !strings.HasPrefix(got, "AT+CFUN=4 AT+CFUN=1 AT+CEREG?") {
		t.Errorf("command order: %s", got)
	}
	ext, err := fakeModem(map[string]string{`AT+QCFG="ims"`: "+QCFG: \"ims\",1,1\r\nOK"}, nil).externalMode(context.Background())
	if err != nil || ext {
		t.Errorf("built-in mode taken for external: %v %v", ext, err)
	}
}

// A service stopped during the pause must not leave the radio off: nothing
// else would turn it on (§118).
func TestModemRadioCycleStoppedStillTurnsRadioOn(t *testing.T) {
	var cmds []string
	m := fakeModem(map[string]string{}, &cmds)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.sleep = func(c context.Context, d time.Duration) error { cancel(); return c.Err() }
	if err := m.radioCycle(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("radioCycle: %v", err)
	}
	if got := strings.Join(cmds, " "); got != "AT+CFUN=4 AT+CFUN=1" {
		t.Errorf("commands: %s", got)
	}
}

func TestModemWaitServiceRejects3G(t *testing.T) {
	m := fakeModem(map[string]string{
		"AT+CEREG?": "+CEREG: 0,1\r\nOK",
		"AT+COPS?":  "+COPS: 0,0,\"Op\",2\r\nOK", // UTRAN
	}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m.sleep = func(ctx context.Context, d time.Duration) error { return sleepCtx(ctx, 10*time.Millisecond) }
	if err := m.waitService(ctx, 50*time.Millisecond); err == nil || !strings.Contains(err.Error(), "3G") {
		t.Fatalf("3G accepted as service: %v", err)
	}
}

// --- Service: small parts ---

func TestRegTracker(t *testing.T) {
	tr := newRegTracker()
	tr.badSince = time.Now().Add(-10 * time.Minute)
	tr.set(reg.StatusRegistering)
	tr.set(reg.StatusFailed)
	if tr.unhealthyFor() < 9*time.Minute {
		t.Error("switching registering/failed reset the count")
	}
	tr.set(reg.StatusRegistered)
	if tr.unhealthyFor() != 0 {
		t.Error("count not reset after registration")
	}
	tr.set(reg.StatusFailed)
	// Two readings of the clock can be the same instant on a fast machine
	// (macOS counts in 41 ns ticks), so the new count may still read 0.
	if d := tr.unhealthyFor(); tr.badSince.IsZero() || d < 0 || d > time.Second {
		t.Errorf("new count: %v", d)
	}
}

func TestRecentOnly(t *testing.T) {
	now := time.Now()
	ts := []time.Time{now.Add(-2 * time.Hour), now.Add(-30 * time.Minute), now.Add(-time.Minute)}
	if got := recentOnly(ts, time.Hour); len(got) != 2 {
		t.Fatalf("within the hour: %v", got)
	}
}

func TestRetryDelay(t *testing.T) {
	if retryDelay(1) != 5*time.Second || retryDelay(5) != 2*time.Minute || retryDelay(50) != 5*time.Minute {
		t.Errorf("%v %v %v", retryDelay(1), retryDelay(5), retryDelay(50))
	}
}

// --- Service: a data call that was not placed ---

// runLoop runs the service loop on a modem with LTE service until it has
// waited n times. It returns the waits, the AT commands and the state. The
// options change the service before the loop starts.
func runLoop(t *testing.T, cfg *Config, n int, options ...func(*service)) (waits []time.Duration, cmds []string, st serviceState) {
	t.Helper()
	m := fakeModem(map[string]string{
		`AT+QCFG="ims"`: "\r\n+QCFG: \"ims\",2,0\r\n\r\nOK\r\n",
		"AT+CEREG?":     "\r\n+CEREG: 0,1\r\n\r\nOK\r\n",
		"AT+COPS?":      "\r\n+COPS: 0,0,\"Op\",7\r\n\r\nOK\r\n",
	}, &cmds)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s := &service{cfg: cfg, log: quietLog(), link: m.link, modem: m,
		state: newStateWriter(filepath.Join(t.TempDir(), "state.json"), quietLog()), net: &netSwitch{}}
	s.sleep = func(c context.Context, d time.Duration) error {
		if waits = append(waits, d); len(waits) == n {
			cancel()
		}
		return c.Err()
	}
	for _, o := range options {
		o(s)
	}
	s.loop(ctx)
	if len(waits) != n {
		t.Fatalf("the loop waited %d times, not %d: %v", len(waits), n, waits)
	}
	return waits, cmds, s.state.snapshot()
}

// Without a helper it can use, or with a call that fails on the router, the
// daemon has nothing a radio restart could mend, and each one takes down the
// router's Internet (§131).
func TestLoopNoRadioRestartWithoutHelper(t *testing.T) {
	missing := filepath.Join(t.TempDir(), helperProgram)
	noLibrary, _ := writeFakeHelper(t, `echo '{"v":1,"event":"error","stage":"library_load","code":0}'; exit 1`+"\n")
	setup, _ := writeFakeHelper(t, `echo '{"v":1,"event":"error","stage":"setup","code":24}'; exit 1`+"\n")
	noInit, _ := writeFakeHelper(t, `echo '{"v":1,"event":"library"}'
echo '{"v":1,"event":"error","stage":"dsi_init","code":-1}'; exit 1
`)
	param, _ := writeFakeHelper(t, `echo '{"v":1,"event":"library"}'
echo '{"v":1,"event":"error","stage":"dsi_set_data_call_param","code":-1,"param":1}'; exit 1
`)
	crash, _ := writeFakeHelper(t, `echo '{"v":1,"event":"library"}'; kill -SEGV $$`+"\n")
	crashPlacing, _ := writeFakeHelper(t, `echo '{"v":1,"event":"library"}'
echo '{"v":1,"event":"ready","pid":1,"subscription":1,"profile":2,"family":"'"$3"'","tries":1}'
kill -SEGV $$
`)
	for _, tc := range []struct{ name, helper, reason string }{
		{"missing", missing, endHelper},
		{"no library", noLibrary, endHelper},
		{"no pipe for the helper", setup, endHelper},
		{"dsi_init fails", noInit, endHelperFail},
		{"a parameter refused", param, endHelperFail},
		{"a crash in the library", crash, endHelperFail},
		{"a crash while the call is placed", crashPlacing, endHelperFail},
	} {
		name := tc.name
		cfg := defaultConfig()
		cfg.IMSProfile, cfg.DSIHelper = 2, tc.helper
		waits, cmds, st := runLoop(t, cfg, 4)
		if !strings.HasPrefix(st.LastError, tc.reason+": ") || st.Restarts != 4 {
			t.Errorf("%s: %d restarts, last error %q", name, st.Restarts, st.LastError)
		}
		if slices.Contains(cmds, "AT+CFUN=4") {
			t.Errorf("%s: the radio was restarted: %v", name, cmds)
		}
		if want := []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute}; !slices.Equal(waits, want) {
			t.Errorf("%s: waits %v, want %v", name, waits, want)
		}
	}
}

// A call the network refuses is another matter: the second refusal in a row
// restarts the radio, as before.
func TestLoopRadioRestartAfterRefusedDataCall(t *testing.T) {
	cfg := defaultConfig()
	cfg.IMSProfile = 2
	cfg.DSIHelper, _ = writeFakeHelper(t, `echo '{"v":1,"event":"net_down"}'`+"\n")
	_, cmds, st := runLoop(t, cfg, 2)
	if !strings.HasPrefix(st.LastError, endPDN+": ") || !strings.Contains(st.LastError, "refused the data call") {
		t.Errorf("last error %q", st.LastError)
	}
	if n := strings.Count(strings.Join(cmds, " "), "AT+CFUN=4 AT+CFUN=1"); n != 1 {
		t.Errorf("%d radio restarts after two refusals, want 1: %v", n, cmds)
	}
}

// A session the helper failed is no strike against the radio: the refusal
// after it is the first, not the second.
func TestLoopHelperFailureIsNoStrike(t *testing.T) {
	cfg := defaultConfig()
	cfg.IMSProfile = 2
	// The first run finds no library (an upgrade under way), the rest are refused.
	cfg.DSIHelper, _ = writeFakeHelper(t, `if [ $(wc -l < "$(dirname "$0")/args") -eq 1 ]; then
	echo '{"v":1,"event":"error","stage":"library_load","code":0}'
	exit 1
fi
echo '{"v":1,"event":"net_down"}'
`)
	_, cmds, st := runLoop(t, cfg, 3)
	if !strings.HasPrefix(st.LastError, endPDN+": ") {
		t.Errorf("last error %q", st.LastError)
	}
	if n := strings.Count(strings.Join(cmds, " "), "AT+CFUN=4 AT+CFUN=1"); n != 1 {
		t.Errorf("%d radio restarts after a helper failure and two refusals, want 1: %v", n, cmds)
	}
}

// A call the helper lost without the network is placed again; only a loss by
// the network counts towards a radio restart.
func TestWatchTellsWhoEndedTheCall(t *testing.T) {
	for _, byNetwork := range []bool{true, false} {
		call := &dataCall{down: make(chan struct{})}
		call.markDown("gone", byNetwork)
		s := &service{log: quietLog()}
		reason, err := s.watch(context.Background(), call, pdnEnv{}, newRegTracker())
		want := endHelperFail
		if byNetwork {
			want = endPDNLost
		}
		if reason != want || err == nil || err.Error() != "gone" {
			t.Errorf("by the network %v: %s, %v", byNetwork, reason, err)
		}
	}
}

// --- Service: the registration at the end of a session ---

// fakeIMS is the network's side of a registration, on loopback: a 401 with
// an AKA challenge on the unprotected port, a 200 to REGISTER and SUBSCRIBE
// on the protected one. It checks nothing, the tests of volte/reg do that.
// The first reg-event subscription is granted for a second, so the UE
// refreshes it within its dialog half a second later; the refresh is granted
// for long. Once lost it answers nothing more, like the P-CSCF behind a PDN
// that is gone.
type fakeIMS struct {
	plain, protected *sipnet.Listener

	mu        sync.Mutex
	refreshed bool     // a SUBSCRIBE came within the dialog of the first one
	deregs    int      // REGISTER requests with Expires: 0
	lost      bool     // the PDN is gone
	afterLoss []string // the methods of what came after that
}

func newFakeIMS(t *testing.T) *fakeIMS {
	t.Helper()
	n, lo := &fakeIMS{}, netip.MustParseAddrPort("127.0.0.1:0")
	var err error
	if n.plain, err = sipnet.Listen(lo, n.challenge, nil); err != nil {
		t.Fatal(err)
	}
	if n.protected, err = sipnet.Listen(lo, n.serve, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.plain.Close(); n.protected.Close() })
	return n
}

func (n *fakeIMS) challenge(c *sipnet.Conn, req *sip.Request) {
	nonce := base64.StdEncoding.EncodeToString(make([]byte, 32)) // RAND and AUTN
	_ = c.Respond(req, 401, "Unauthorized",
		sip.NewHeader("WWW-Authenticate", `Digest realm="ims.test", nonce="`+nonce+`", algorithm=AKAv1-MD5, qop="auth"`),
		sip.NewHeader("Security-Server", fmt.Sprintf("ipsec-3gpp;alg=hmac-md5-96;prot=esp;mod=trans;ealg=null;"+
			"spi-c=7001;spi-s=7002;port-c=9950;port-s=%d", n.protected.Addr().Port())))
}

func (n *fakeIMS) serve(c *sipnet.Conn, req *sip.Request) {
	expires := ""
	if h := req.GetHeader("Expires"); h != nil {
		expires = h.Value()
	}
	inDialog := false
	if to := req.To(); to != nil {
		_, inDialog = to.Params.Get("tag")
	}
	n.mu.Lock()
	lost := n.lost
	switch {
	case lost:
		n.afterLoss = append(n.afterLoss, string(req.Method))
	case req.Method == sip.SUBSCRIBE && inDialog:
		n.refreshed = true
	case req.Method == sip.REGISTER && expires == "0":
		n.deregs++
	}
	n.mu.Unlock()
	if lost {
		return
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	switch req.Method {
	case sip.REGISTER:
		if expires != "0" {
			expires = "3600"
		}
		res.AppendHeader(sip.NewHeader("Expires", expires))
	case sip.SUBSCRIBE:
		granted := "600000"
		if !inDialog {
			granted = "1"
		}
		res.To().Params.Add("tag", "net")
		res.AppendHeader(sip.NewHeader("Expires", granted))
	default:
		res = sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil)
	}
	_ = c.Send(res)
}

// seen tells what the network got: whether the UE has refreshed its
// subscription, how many de-REGISTER requests came, and what came after the
// loss of the PDN.
func (n *fakeIMS) seen() (refreshed bool, deregs int, afterLoss []string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.refreshed, n.deregs, slices.Clone(n.afterLoss)
}

func (n *fakeIMS) lose() {
	n.mu.Lock()
	n.lost = true
	n.mu.Unlock()
}

// uePorts returns a client and a server port for the UE that nothing holds
// on 127.0.0.1. Left to reg, the ports are random in 20000-59999, where a
// service of the host or a connection of another test may hold one: the
// registration then fails with "address already in use" and is repeated
// 5 s later, with its SAs set up twice. These ports lie below the ephemeral
// ranges of Linux (from 32768) and macOS (from 49152), so no outgoing
// connection takes one meanwhile.
func uePorts(t *testing.T) (portC, portS uint16) {
	t.Helper()
	var free []uint16
	for try := 0; len(free) < 2; try++ {
		if try == 1000 {
			t.Fatalf("no free ports for the UE in 20000-31999, found %v", free)
		}
		p := uint16(20000 + rand.IntN(12000))
		if slices.Contains(free, p) {
			continue
		}
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			continue // taken
		}
		ln.Close()
		free = append(free, p)
	}
	return free[0], free[1]
}

// fixedSIM answers every AKA challenge with the same keys.
type fixedSIM struct{}

func (fixedSIM) Authenticate(context.Context, [16]byte, [16]byte) (volsim.AuthResult, error) {
	return volsim.AuthResult{RES: make([]byte, 8), CK: make([]byte, 16), IK: make([]byte, 16)}, nil
}

// xfrmLog takes the changes to the kernel's SAs and policies and only counts
// them.
type xfrmLog struct {
	mu   sync.Mutex
	cmds []string
}

func (x *xfrmLog) Run(_ context.Context, args ...string) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.cmds = append(x.cmds, strings.Join(args, " "))
	return nil
}

func (x *xfrmLog) count(prefix string) int {
	x.mu.Lock()
	defer x.mu.Unlock()
	n := 0
	for _, c := range x.cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// A session that ended because its PDN is gone gives the registration up at
// once: the de-REGISTER reached nobody, and the 5 s the daemon waited for
// its answer went into every recovery of the line. The SAs go all the same.
// A session that ends with the PDN alive de-registers as before.
func TestSessionEndDeregistersOnlyOverALivePDN(t *testing.T) {
	for _, tc := range []struct {
		reason  string
		pdnGone bool
	}{
		{endHelperFail, true},
		{endPDNLost, true},
		{endStop, false},
		{endRAT, false},
		{endReg, false},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			ims, xfrm, book := newFakeIMS(t), &xfrmLog{}, &logBook{}
			portC, portS := uePorts(t)
			st, err := newNetStack("", reg.Config{IMPI: "001010000000001@ims.test", IMPU: "sip:001010000000001@ims.test",
				Domain: "ims.test", UEAddr: netip.MustParseAddr("127.0.0.1"), PCSCF: ims.plain.Addr(),
				PortC: portC, PortS: portS, IPsec: xfrm, Log: book.logger()}, fixedSIM{}, call.Config{Log: quietLog()},
				sms.Config{Domain: "ims.test", Log: quietLog()}, quietLog())
			if err != nil {
				t.Fatal(err)
			}
			s := &service{cfg: defaultConfig(), log: quietLog(), net: &netSwitch{},
				state: newStateWriter(filepath.Join(t.TempDir(), "state.json"), quietLog())}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stopReg := s.holdRegistration(ctx, st, newRegTracker())
			// However the test ends, the registration writes no state after it.
			t.Cleanup(func() { stopReg(tc.reason) })

			// Registered and subscribed: the UE has nothing more to send until
			// a refresh of the registration is due. That the network has the
			// SUBSCRIBE does not tell it: until the UE has taken the 200 the
			// subscription is under way, and the end of the session would cut
			// it short. The UE refreshes the subscription within its dialog
			// only once it stands on its side; a refresh that the end cuts
			// short goes without a word.
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
				if refreshed, _, _ := ims.seen(); refreshed && s.state.snapshot().Registered {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("not registered and subscribed in 10 s:\n%s", book)
				}
			}
			if tc.pdnGone {
				ims.lose()
			}
			if tc.reason == endStop {
				cancel() // the service stops
			}

			start := time.Now()
			stopReg(tc.reason)
			if took := time.Since(start); took > 2*time.Second {
				t.Errorf("the registration took %s to go", took.Round(time.Millisecond))
			}
			_, deregs, afterLoss := ims.seen()
			if tc.pdnGone {
				if len(afterLoss) != 0 || strings.Contains(book.String(), "level=WARN") {
					t.Errorf("sent into the lost PDN: %v; the log:\n%s", afterLoss, book)
				}
			} else if deregs != 1 {
				t.Errorf("%d de-REGISTER requests, want 1; the log:\n%s", deregs, book)
			}
			if st.reg.Conn() != nil {
				t.Error("the registration is still held")
			}
			if adds, dels := xfrm.count("xfrm state add"), xfrm.count("xfrm state delete"); adds != 4 || dels != 4 {
				t.Errorf("SA adds=%d deletes=%d, want 4/4", adds, dels)
			}
			if adds, dels := xfrm.count("xfrm policy add"), xfrm.count("xfrm policy delete"); adds != 8 || dels != 8 {
				t.Errorf("policy adds=%d deletes=%d, want 8/8", adds, dels)
			}
		})
	}
}

func TestURINumber(t *testing.T) {
	for in, want := range map[string]string{
		"tel:+447700900001": "+447700900001",
		"<sip:+447700900001@ims.example.org;user=phone>":        "+447700900001",
		"sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org": "",
		"": "",
	} {
		if got := uriNumber(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestNetSwitchWithoutNetwork(t *testing.T) {
	var n netSwitch
	_, err := n.Dial(context.Background(), "+447700900001")
	var de *dialError
	if !errors.As(err, &de) || de.Code != 503 {
		t.Fatalf("without a network want 503: %v", err)
	}
}

func TestDialAllowAll(t *testing.T) {
	if !dialAllowed([]string{"*"}, "+995599000000") || !dialAllowed([]string{"*"}, "1985") {
		t.Error("\"*\" must allow everything")
	}
	sc := SIPConfig{Listen: "192.168.8.1:5060", Accounts: []SIPAccount{{User: "pixel", Password: "0123456789ab"}},
		DialAllow: []string{"*"}}.withDefaults()
	if err := sc.validate(); err != nil {
		t.Errorf("\"*\" failed the config check: %v", err)
	}
}

func TestRegistrarPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "phones.json")
	r := newRegistrar()
	r.load(path)
	var udp, tcp sip.Uri
	if err := sip.ParseUri("sip:pixel@192.168.8.100:39012;transport=udp", &udp); err != nil {
		t.Fatal(err)
	}
	if err := sip.ParseUri("sip:iphone@192.168.8.101:5060;transport=tcp", &tcp); err != nil {
		t.Fatal(err)
	}
	r.update(binding{user: "pixel", contact: udp, source: "192.168.8.100:39012", transport: "udp", expires: time.Now().Add(time.Hour)})
	r.update(binding{user: "iphone", contact: tcp, source: "192.168.8.101:50111", transport: "tcp", expires: time.Now().Add(time.Hour)})

	r2 := newRegistrar()
	if n := r2.load(path); n != 1 {
		t.Fatalf("%d bindings restored, want one UDP", n)
	}
	b := r2.active()[0]
	if b.user != "pixel" || b.source != "192.168.8.100:39012" || b.contact.Port != 39012 {
		t.Errorf("binding: %+v", b)
	}
	if got := r2.users(); len(got) != 1 || got[0] != "pixel" {
		t.Errorf("users: %v", got)
	}
	// An expired one is not restored.
	r2.update(binding{user: "pixel", contact: udp, source: "192.168.8.100:39012", transport: "udp", expires: time.Now().Add(-time.Second)})
	if n := newRegistrar().load(path); n != 0 {
		t.Errorf("expired binding restored: %d", n)
	}
}

func TestRegistrarSameInstance(t *testing.T) {
	var ch sip.ContactHeader
	if _, err := sip.ParseAddressValue(`<sip:iphone@192.168.8.137:50426;transport=udp>;+org.linphone.specs="lime,groupchat/1.1";`+
		`+sip.instance="<urn:uuid:0A1B2C3D-1111-2222-3333-444455556666>";expires=3600`, &ch.Address, &ch.Params); err != nil {
		t.Fatal(err)
	}
	const dev = "urn:uuid:0a1b2c3d-1111-2222-3333-444455556666"
	if got := contactInstance(&ch); got != dev {
		t.Fatalf("+sip.instance: %q", got)
	}

	path := filepath.Join(t.TempDir(), "phones.json")
	r := newRegistrar()
	r.load(path)
	uri := func(s string) sip.Uri {
		var u sip.Uri
		if err := sip.ParseUri(s, &u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	exp := time.Now().Add(time.Hour)
	r.update(binding{user: "iphone", contact: uri("sip:iphone@192.168.8.137:54448"), source: "192.168.8.137:54448", transport: "udp", instance: dev, expires: exp})
	// Without an instance (a file from an old version, another softphone) a
	// binding neither replaces nor gets replaced.
	r.update(binding{user: "iphone", contact: uri("sip:iphone@192.168.8.140:5060"), source: "192.168.8.140:5060", transport: "udp", expires: exp})
	// The same instance under another login is someone else's binding: left alone.
	r.update(binding{user: "pixel", contact: uri("sip:pixel@192.168.8.109:37238"), source: "192.168.8.109:37238", transport: "udp", instance: dev, expires: exp})

	r2 := newRegistrar()
	r2.load(path) // the instance survives a daemon restart
	if n := r2.update(binding{user: "iphone", contact: uri("sip:iphone@192.168.8.137:50426"), source: "192.168.8.137:50426", transport: "udp", instance: dev, expires: exp}); n != 1 {
		t.Fatalf("%d bindings replaced, want one", n)
	}
	ports := map[int]bool{}
	for _, b := range r2.forUser("iphone") {
		ports[b.contact.Port] = true
	}
	if len(ports) != 2 || !ports[50426] || !ports[5060] {
		t.Errorf("iphone: ports %v, want 50426 and 5060", ports)
	}
	if len(r2.forUser("pixel")) != 1 {
		t.Error("pixel binding is gone")
	}
}

func TestPrintStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	w := newStateWriter(path, quietLog())
	w.phones = func() []string { return []string{"pixel"} }
	w.update(func(s *serviceState) {
		s.Phase, s.Registered, s.Number = "registered", true, "+447700900001"
		s.Interface, s.Address, s.PCSCF, s.RAT = "rmnet_data1", "198.51.100.207", []string{"192.0.2.28"}, "LTE"
	})
	var buf bytes.Buffer
	if code := printStatus(&buf, path, time.Now()); code != 0 {
		t.Fatalf("exit code %d, output:\n%s", code, buf.String())
	}
	for _, want := range []string{"online", "+447700900001", "rmnet_data1", "pixel"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, buf.String())
		}
	}
	buf.Reset()
	if code := printStatus(&buf, filepath.Join(t.TempDir(), "none.json"), time.Now()); code != 3 {
		t.Errorf("no file: exit code %d", code)
	}
}

// The router boots with its clock behind (by 14 minutes on the Mudi on
// 2026-11-07), and NTP steps it forward once the internet is up. "registered
// for" counts on the monotonic clock: the first write after the step puts
// since right.
func TestStateClockStep(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	w := newStateWriter(path, quietLog())
	boot := time.Date(2026, 11, 7, 10, 31, 0, 0, time.UTC) // the clock at the boot, 14 minutes behind
	var up, step time.Duration                             // time since the boot; NTP's correction
	w.now = func() time.Time { return boot.Add(up + step) }
	w.mono = func() time.Time { return boot.Add(up) }
	read := func() serviceState {
		t.Helper()
		var s serviceState
		raw, err := os.ReadFile(path)
		if err == nil {
			err = json.Unmarshal(raw, &s)
		}
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	up = time.Minute
	w.update(func(s *serviceState) { s.Phase, s.Registered = "registered", true })
	up = 2 * time.Minute
	w.fail(errors.New("registration refresh: 500"))
	step = 14 * time.Minute // NTP; nothing is written at the step itself
	up = 10 * time.Minute
	w.update(func(s *serviceState) { s.RAT = "LTE" }) // as the watch loop does every 10 s

	s := read()
	if want := boot.Add(15 * time.Minute); !s.Since.Equal(want) {
		t.Errorf("since %v, want %v: registered 9 minutes before this write", s.Since, want)
	}
	if d := s.UpdatedAt.Sub(s.Since); d != 9*time.Minute {
		t.Errorf("updated_at - since = %v, want 9m0s: the web pages show it", d)
	}
	if want := boot.Add(16 * time.Minute); s.LastErrorAt == nil || !s.LastErrorAt.Equal(want) {
		t.Errorf("last_error_at %v, want %v", s.LastErrorAt, want)
	}
	var buf bytes.Buffer
	printStatus(&buf, path, s.UpdatedAt.Add(5*time.Second))
	for _, want := range []string{"registered for 9m0s", "Last error (8m0s ago)"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, buf.String())
		}
	}
	// The clock stepped back after the last write: nothing goes negative.
	buf.Reset()
	printStatus(&buf, path, s.UpdatedAt.Add(-14*time.Minute))
	if !strings.Contains(buf.String(), "registered for 9m0s") {
		t.Errorf("clock stepped back after the write:\n%s", buf.String())
	}

	// Without a step since stays where it is; a new phase starts from the
	// clock as it is now.
	up = 11 * time.Minute
	w.update(nil)
	if s := read(); !s.Since.Equal(boot.Add(15 * time.Minute)) {
		t.Errorf("since moved without a step: %v", s.Since)
	}
	up = 12 * time.Minute
	w.update(func(s *serviceState) { s.Phase, s.Registered = "recovering", false })
	if s, want := read(), boot.Add(26*time.Minute); !s.Since.Equal(want) {
		t.Errorf("since after a phase change %v, want %v", s.Since, want)
	}
}

// One reply from the other slot (0,0) does not make the modem "non-external".
func TestModemExternalModeRechecks(t *testing.T) {
	n := 0
	m := fakeModem(nil, nil)
	m.link.Run = func(_ context.Context, cmd string) (string, error) {
		if !strings.HasSuffix(cmd, `+QCFG="ims"`) {
			return "\r\n+QUIMSUB: 1,\"SUB1\",\"L\"\r\nOK\r\n", nil
		}
		n++
		if n == 1 {
			return "\r\n+QUIMSUB: 1,\"SUB1\",\"L\"\r\n+QCFG: \"ims\",0,0\r\nOK\r\n", nil
		}
		return "\r\n+QUIMSUB: 1,\"SUB1\",\"L\"\r\n+QCFG: \"ims\",2,0\r\nOK\r\n", nil
	}
	if ext, err := m.externalMode(context.Background()); err != nil || !ext || n != 2 {
		t.Fatalf("ext=%v err=%v reads=%d", ext, err, n)
	}
}

// query: slot selection and the request in one line; a compound line that
// gives ERROR falls back to the old path of two calls.
func TestATLinkQueryPinsInOneLine(t *testing.T) {
	var calls []string
	link := &ATLink{Retries: 1, Run: func(_ context.Context, cmd string) (string, error) {
		calls = append(calls, cmd)
		return "\r\n+QUIMSUB: 1,\"SUB1\",\"L\"\r\n+CEREG: 0,1\r\nOK\r\n", nil
	}}
	out, err := link.query(context.Background(), "AT+CEREG?")
	if err != nil || !strings.Contains(out, "+CEREG: 0,1") || len(calls) != 1 || calls[0] != "AT+QUIMSUB=1;+QUIMSUB?;+CEREG?" {
		t.Fatalf("out=%q err=%v calls=%q", out, err, calls)
	}
	calls = nil
	link.Run = func(_ context.Context, cmd string) (string, error) {
		calls = append(calls, cmd)
		switch cmd {
		case "AT+QUIMSUB=1;+QUIMSUB?":
			return "\r\n+QUIMSUB: 1,\"SUB1\",\"L\"\r\nOK\r\n", nil
		case "AT+CEREG?":
			return "\r\n+CEREG: 0,1\r\nOK\r\n", nil
		}
		return "\r\nERROR\r\n", nil
	}
	if out, err := link.query(context.Background(), "AT+CEREG?"); err != nil || !strings.Contains(out, "+CEREG: 0,1") {
		t.Fatalf("fallback: out=%q err=%v calls=%q", out, err, calls)
	}
}
