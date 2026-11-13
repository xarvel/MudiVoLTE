package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/MudiVoLTE/volte/reg"
)

// --- Service: what the loop counts towards a radio restart ---

// A radio restart is the measure taken: the count of failures in a row starts
// anew after it ("on the second in a row", PROTOCOLS.md 2.2). Four refusals
// of the data call in a row restart the radio at the second and the fourth;
// before, every refusal after the second did it again, three outages of the
// router's Internet within about two minutes.
func TestLoopRadioRestartsDoNotComeBackToBack(t *testing.T) {
	cfg := defaultConfig()
	cfg.IMSProfile = 2
	cfg.DSIHelper, _ = writeFakeHelper(t, `echo '{"v":1,"event":"net_down"}'`+"\n")
	waits, cmds, _ := runLoop(t, cfg, 4)
	if n := strings.Count(strings.Join(cmds, " "), "AT+CFUN=4 AT+CFUN=1"); n != 2 {
		t.Errorf("%d radio restarts after four refusals in a row, want 2 (waits %v): %v", n, waits, cmds)
	}
}

// scriptedUp plays the sessions in turn: each one ends with its reason, and
// after a registration when registered is set.
type scriptedSession struct {
	reason     string
	registered bool
}

func scriptedUp(sessions ...scriptedSession) (func(*service), *int) {
	ran := new(int)
	return func(s *service) {
		s.up = func(ctx context.Context, tr *regTracker) (string, error) {
			x := sessions[min(*ran, len(sessions)-1)]
			*ran++
			if x.registered {
				tr.set(reg.StatusRegistered)
			}
			return x.reason, errors.New("scripted")
		}
	}, ran
}

// A registration in between ends a run of failures as well: a refusal, then
// a registration that the helper lost, then a refusal is two firsts, not a
// second. Before, the count stood across the registration.
func TestLoopRegistrationStartsTheStrikesAnew(t *testing.T) {
	cfg := defaultConfig()
	up, _ := scriptedUp(
		scriptedSession{endPDN, false},
		scriptedSession{endHelperFail, true},
		scriptedSession{endPDN, false},
	)
	waits, cmds, _ := runLoop(t, cfg, 3, up)
	if slices.Contains(cmds, "AT+CFUN=4") {
		t.Errorf("the radio was restarted for a refusal after a registration: %v", cmds)
	}
	// The wait still grows: a registration that does not last is no reason to
	// register again at once.
	if want := []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second}; !slices.Equal(waits, want) {
		t.Errorf("waits %v, want %v", waits, want)
	}
	// Without the registration it is the second refusal in a row.
	up, _ = scriptedUp(
		scriptedSession{endPDN, false},
		scriptedSession{endHelperFail, false},
		scriptedSession{endPDN, false},
	)
	if _, cmds, _ = runLoop(t, cfg, 3, up); strings.Count(strings.Join(cmds, " "), "AT+CFUN=4 AT+CFUN=1") != 1 {
		t.Errorf("want one radio restart after two refusals around a helper failure: %v", cmds)
	}
}

// A helper that crashes between net_up and the address on the interface is
// a failure on the router, as it is once the session runs (watch): before,
// waitPDN made it pdn-failed, a strike, and two such crashes took the
// router's Internet down with AT+CFUN=4/1.
func TestLoopHelperCrashWhileWaitingForTheAddressIsNoStrike(t *testing.T) {
	cfg := defaultConfig()
	cfg.IMSProfile = 2
	cfg.DSIHelper, _ = writeFakeHelper(t, `echo '{"v":1,"event":"library"}'
echo '{"v":1,"event":"ready","pid":1,"subscription":1,"profile":2,"family":"'"$3"'","tries":1}'
echo '{"v":1,"event":"net_up"}'
kill -SEGV $$
`)
	_, cmds, st := runLoop(t, cfg, 2)
	if !strings.HasPrefix(st.LastError, endHelperFail+": ") {
		t.Errorf("a helper that crashed after net_up ended the session as %q, want %s", st.LastError, endHelperFail)
	}
	if slices.Contains(cmds, "AT+CFUN=4") {
		t.Errorf("two helper crashes restarted the radio: %v", cmds)
	}
}

// --- Service: entries a predecessor left in the SAD and SPD ---

// A sweep that fails does not keep the line down: the sessions go on, and
// the sweep is tried again before each of them until it works. Before, a
// failure of the sweep at the start ended the service, and procd started it
// again every 10 s to the same end.
func TestLoopStaleIPsecSweepIsRetriedNotFatal(t *testing.T) {
	cfg := defaultConfig()
	var events []string
	up, ran := scriptedUp(scriptedSession{endHelperFail, false})
	sweep := func(s *service) {
		s.sweep = func(context.Context) (int, int, error) {
			events = append(events, "sweep")
			if len(events) < 4 { // the first two
				return 0, 0, errors.New("list XFRM policies: operation not permitted")
			}
			return 4, 8, nil
		}
		next := s.up
		s.up = func(ctx context.Context, tr *regTracker) (string, error) {
			events = append(events, "session")
			return next(ctx, tr)
		}
	}
	runLoop(t, cfg, 4, up, sweep)
	want := []string{"sweep", "session", "sweep", "session", "sweep", "session", "session"}
	if *ran != 4 || !slices.Equal(events, want) {
		t.Errorf("%d sessions; events %v, want %v", *ran, events, want)
	}
}

// With ipsec_tool "ip", the fallback for a firmware where netlink
// misbehaves, the sweep goes through ip as well.
func TestSweepIPsecFollowsTheTool(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	script := "#!/bin/sh\necho \"$*\" >> '" + log + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "ip"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cfg := defaultConfig()
	cfg.IPsecTool = "ip"
	if n, p, err := sweepIPsec(cfg)(context.Background()); err != nil || n != 0 || p != 0 {
		t.Fatalf("sweep through ip: %d states, %d policies, %v", n, p, err)
	}
	if raw, _ := os.ReadFile(log); !strings.HasPrefix(string(raw), "-o xfrm policy list\n") {
		t.Errorf("ip was not asked for the policies: %q", raw)
	}
}

// --- Service: restarts after a crash ---

// The file in /var/run counts the processes in a row that ended without a
// stop, and the wait before the first session grows with them. A clean stop
// or 30 minutes of running count anew.
func TestCrashCountAcrossProcesses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crashes.json")
	start := func() *crashCount { return startCrashCount(path, quietLog()) }
	want := []time.Duration{0, 0, 10 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for i, d := range want {
		// None of them records an end, as after a panic or a kill.
		if c := start(); c.n != i || crashDelay(c.n) != d {
			t.Errorf("start %d: %d crashes before it, wait %v; want %d, %v", i+1, c.n, crashDelay(c.n), i, d)
		}
	}
	start().stopped()
	if c := start(); c.n != 0 {
		t.Errorf("after a clean stop: %d crashes", c.n)
	}
	c := start() // after a crash
	if c.n != 1 || !c.healthy() {
		t.Fatalf("a process after one crash: n %d", c.n)
	}
	if c := start(); c.n != 1 {
		t.Errorf("a crash after a process that ran long enough counts %d in a row, want 1", c.n)
	}
	c = start()
	c.stopped()
	if c.healthy() {
		t.Error("healthy changed the count after the stop")
	}
	if c := start(); c.n != 0 {
		t.Errorf("a stop was undone: %d crashes", c.n)
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := start(); c.n != 0 {
		t.Errorf("an unreadable file counts %d crashes", c.n)
	}
}

// A process started after crashes waits before it places the data call,
// and the state shows the count.
func TestLoopWaitsAfterCrashesBeforeThePDN(t *testing.T) {
	cfg := defaultConfig()
	cfg.IMSProfile = 2
	var args string
	cfg.DSIHelper, args = writeFakeHelper(t, `echo '{"v":1,"event":"net_down"}'`+"\n")
	path := filepath.Join(t.TempDir(), "crashes.json")
	if err := writeJSONAtomic(path, crashRecord{PID: 1, Running: true, Crashes: 2}); err != nil {
		t.Fatal(err)
	}
	var called []bool // whether the helper had run, at each wait
	crashed := func(s *service) {
		s.crash = startCrashCount(path, quietLog())
		next := s.sleep
		s.sleep = func(c context.Context, d time.Duration) error {
			_, err := os.Stat(args)
			called = append(called, err == nil)
			return next(c, d)
		}
	}
	waits, _, st := runLoop(t, cfg, 2, crashed)
	if want := []time.Duration{30 * time.Second, 5 * time.Second}; !slices.Equal(waits, want) {
		t.Errorf("waits %v, want %v (the third start in a row after a crash)", waits, want)
	}
	if !slices.Equal(called, []bool{false, true}) {
		t.Errorf("the helper had run at the waits: %v, want only at the second", called)
	}
	if st.CrashRestarts != 3 {
		t.Errorf("crash_restarts %d, want 3", st.CrashRestarts)
	}
	var buf bytes.Buffer
	file := filepath.Join(t.TempDir(), "state.json")
	if err := writeJSONAtomic(file, st); err != nil {
		t.Fatal(err)
	}
	printStatus(&buf, file, time.Now())
	if !strings.Contains(buf.String(), "Restarts of the service after a crash: 3 in a row") {
		t.Errorf("status:\n%s", buf.String())
	}
}

// After a single crash the line comes back at once: procd has waited 10 s.
func TestLoopNoWaitAfterOneCrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "crashes.json")
	if err := writeJSONAtomic(path, crashRecord{PID: 1, Running: true}); err != nil {
		t.Fatal(err)
	}
	up, ran := scriptedUp(scriptedSession{endHelperFail, false})
	crashed := func(s *service) { s.crash = startCrashCount(path, quietLog()) }
	waits, _, st := runLoop(t, defaultConfig(), 1, up, crashed)
	if *ran != 1 || !slices.Equal(waits, []time.Duration{5 * time.Second}) || st.CrashRestarts != 1 {
		t.Errorf("%d sessions, waits %v, crash_restarts %d", *ran, waits, st.CrashRestarts)
	}
}
