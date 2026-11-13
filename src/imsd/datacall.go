package main

// The IMS PDN is a data call placed from the host (app note ch. 4.3, §71).
// mudi-dsi-helper (src/dsi-helper) places it through the firmware's DSI
// library (docs/PROTOCOLS.md, section 2.2) and tells what happens as JSON
// lines on its stdout. The call lives as long as the helper. The helper takes
// the call down when its stdin closes: that is how the daemon stops it, and
// what happens by itself should the daemon die (§131).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	helperProgram  = "mudi-dsi-helper"
	helperProtocol = 1
	// The helper's own lines are short; a library may print anything.
	helperLineMax = 2048
)

// How long the helper may take. Variables, for the tests.
var (
	// From its start to the answer to the call: the helper gives the
	// library 15 s to get ready, and the network gets a minute to answer.
	helperReplyWait = 80 * time.Second
	// From the end of its stdin to its exit: the helper gives the modem 2 s
	// to confirm that the call is down.
	helperStopWait = 5 * time.Second
)

// helperEvent is one line from the helper.
type helperEvent struct {
	V       int    `json:"v"`
	Event   string `json:"event"`
	Stage   string `json:"stage"`  // error: what failed
	Code    int    `json:"code"`   // error: with what; dsi_event: which one; exiting: the exit status
	Param   int    `json:"param"`  // error in dsi_set_data_call_param: which parameter
	Signal  int    `json:"signal"` // stopping: the signal that asked for it; 0: the end of stdin
	PID     int    `json:"pid"`    // ready: the rest
	Profile int    `json:"profile"`
	Family  string `json:"family"`
	Tries   int    `json:"tries"` // requests for a handle
}

// failure turns an error event into the error it reports.
func (ev helperEvent) failure() error {
	switch ev.Stage {
	case "library_load", "library_symbol":
		// The helper's stderr, which is in the log, tells what is wrong.
		return fmt.Errorf("%s cannot use the firmware's libdsi_netctrl.so (%s)", helperProgram, ev.Stage)
	case "dsi_set_data_call_param":
		return fmt.Errorf("%s: %s failed for parameter %d (code %d)", helperProgram, ev.Stage, ev.Param, ev.Code)
	}
	return fmt.Errorf("%s: %s failed (code %d)", helperProgram, ev.Stage, ev.Code)
}

// How far the helper got with a call, as its events tell. Who is to blame
// for a failure follows from it: before "library" the helper could not work
// at all, before "ready" the call failed on this router, after that the
// network had its say, unless the helper went without a word (died).
const (
	helperStarted int32 = iota // nothing said yet
	helperLoaded               // the library is loaded and has the functions
	helperPlacing              // the call is set up and goes to the modem
)

// unusable is a helper that cannot work on this installation: it is missing,
// does not start, speaks another protocol or cannot use the DSI library of
// this firmware. It would do no better for the other IP family.
type unusable struct{ err error }

func (e *unusable) Error() string { return e.err.Error() }
func (e *unusable) Unwrap() error { return e.err }

func isUnusable(err error) bool {
	var u *unusable
	return errors.As(err, &u)
}

// hostSide is a data call that failed on this router: a step before the
// call went to the modem failed, or the helper died, hung or was stopped by
// someone other than the daemon. The network had no say in it.
type hostSide struct{ err error }

func (e *hostSide) Error() string { return e.err.Error() }
func (e *hostSide) Unwrap() error { return e.err }

func isHostSide(err error) bool {
	var h *hostSide
	return errors.As(err, &h)
}

// died is the end of a helper that gave no word about the call: a crash, a
// kill. However far the call had got, that is not the network's answer.
type died struct{ err error }

func (e *died) Error() string { return e.err.Error() }
func (e *died) Unwrap() error { return e.err }

// dataCall is the IMS data call, and the helper that holds it.
type dataCall struct {
	cmd    *exec.Cmd
	stdin  io.Closer
	exited chan struct{}
	log    *slog.Logger

	reply     chan error // the answer to the call; nil: it is up
	replyOnce sync.Once
	spoke     atomic.Bool  // a line of the protocol has come
	progress  atomic.Int32 // helperStarted, helperLoaded, helperPlacing
	stopping  atomic.Bool  // the helper stops the call, whoever asked

	down      chan struct{}
	downOnce  sync.Once
	stopOnce  sync.Once
	mu        sync.Mutex
	reason    string
	byNetwork bool   // the network ended the call
	lastSaid  string // the last line on stderr
}

// startDataCall brings up the PDN of profile: IPv4v6 first, then IPv4 (the
// order of post.sh, §71). The error is unusable or hostSide when nothing
// reached the network.
func startDataCall(ctx context.Context, cfg *Config, profile int, log *slog.Logger) (*dataCall, error) {
	// The DSI library keeps one byte of the number.
	if profile < 1 || profile > 255 {
		return nil, &hostSide{fmt.Errorf("data call: %d is not a modem profile number (1 to 255)", profile)}
	}
	bin := cfg.dsiHelper()
	if err := checkHelper(bin); err != nil {
		return nil, &unusable{err}
	}
	var errs []error
	host := true // no family got as far as the network
	for _, family := range []string{"ipv4v6", "ipv4"} {
		c, err := dialDataCall(ctx, bin, profile, family, log)
		if err == nil {
			return c, nil
		}
		if isUnusable(err) {
			return nil, err // and would be for the other family
		}
		// A step may fail for one family only, so the other is tried.
		var h *hostSide
		if errors.As(err, &h) {
			err = h.err
		} else {
			host = false
		}
		errs = append(errs, fmt.Errorf("%s: %w", family, err))
		if ctx.Err() != nil {
			break
		}
	}
	err := errors.Join(errs...)
	if host {
		return nil, &hostSide{err}
	}
	return nil, err
}

// checkHelper checks the helper from the config (dsi_helper), which runs as
// root: either a bare name from PATH or an absolute path to an existing
// executable, nothing relative.
func checkHelper(bin string) error {
	if bin == "" {
		return errors.New("dsi_helper: empty")
	}
	if !strings.ContainsRune(bin, '/') {
		if _, err := exec.LookPath(bin); err != nil {
			return fmt.Errorf("dsi_helper: %w", err)
		}
		return nil
	}
	if !filepath.IsAbs(bin) {
		return fmt.Errorf("dsi_helper: an absolute path is needed, not %q", bin)
	}
	st, err := os.Stat(bin)
	if err != nil {
		return fmt.Errorf("dsi_helper: %w", err)
	}
	if !st.Mode().IsRegular() || st.Mode()&0o111 == 0 {
		return fmt.Errorf("dsi_helper: %q is not an executable file", bin)
	}
	return nil
}

func dialDataCall(ctx context.Context, bin string, profile int, family string, log *slog.Logger) (*dataCall, error) {
	cmd := exec.Command(bin, strconv.Itoa(imsSlot), strconv.Itoa(profile), family)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("starting %s: %w", bin, err)
	}
	c := &dataCall{cmd: cmd, stdin: stdin, exited: make(chan struct{}), log: log,
		reply: make(chan error, 1), down: make(chan struct{})}
	out, complaints := &lineWriter{line: c.onEvent}, &lineWriter{line: c.onStderr}
	cmd.Stdout, cmd.Stderr = out, complaints
	// Nothing but the helper should hold its pipes; if something does, Wait
	// stops waiting for it this long after the helper is gone.
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		return nil, &unusable{fmt.Errorf("starting %s: %w", bin, err)}
	}
	go c.wait(out, complaints)

	t := time.NewTimer(helperReplyWait)
	defer t.Stop()
	select {
	case err = <-c.reply:
	case <-t.C:
		err = fmt.Errorf("no reply to the data call within %s", helperReplyWait)
	case <-ctx.Done():
		c.Stop()
		return nil, ctx.Err()
	}
	if err != nil {
		err = c.blame(err) // before the stop, which the helper reports as well
		c.Stop()
		return nil, err
	}
	return c, nil
}

// blame marks a failure of the call with who had a say in it, by how far the
// helper got.
func (c *dataCall) blame(err error) error {
	var d *died
	switch {
	case c.progress.Load() == helperStarted:
		// It never loaded the library: missing, broken or hung on loading.
		return &unusable{err}
	case c.progress.Load() == helperLoaded, c.stopping.Load(), errors.As(err, &d):
		return &hostSide{err}
	}
	return err
}

// wait runs until the helper is gone.
func (c *dataCall) wait(out, complaints *lineWriter) {
	err := c.cmd.Wait()
	out.flush()
	complaints.flush()
	// All the helper said has been handled by now, so a reason it gave
	// stands. This one is for a helper that went without giving any.
	how := helperProgram + " exited"
	if err != nil {
		how += " (" + err.Error() + ")"
	}
	if c.spoke.Load() {
		c.answer(&died{errors.New(how)})
	} else {
		silent := how + " before saying anything"
		if said := c.complaint(); said != "" {
			silent += ": " + said
		}
		c.answer(errors.New(silent))
	}
	c.markDown(how, false)
	close(c.exited)
}

func (c *dataCall) answer(err error) {
	c.replyOnce.Do(func() { c.reply <- err })
}

func (c *dataCall) onEvent(line string) {
	var ev helperEvent
	if err := json.Unmarshal([]byte(line), &ev); err != nil || ev.V != helperProtocol || ev.Event == "" {
		c.log.Warn("dsi: not a line of the helper's protocol", "line", line)
		return
	}
	c.spoke.Store(true)
	switch ev.Event {
	case "library":
		c.advance(helperLoaded)
		c.log.Debug("dsi", "event", ev.Event)
	case "ready":
		c.advance(helperPlacing)
		c.log.Info("dsi", "event", ev.Event, "pid", ev.PID, "profile", ev.Profile, "family", ev.Family,
			"handle_requests", ev.Tries)
	case "net_up":
		c.advance(helperPlacing)
		c.log.Info("dsi", "event", ev.Event)
		c.answer(nil)
	case "stopping":
		// After a stop of the daemon's own this changes nothing. Otherwise
		// someone else stopped the helper, and the NO_NET that follows is
		// that stop, not the network.
		c.stopping.Store(true)
		why := helperProgram + " was stopped"
		if ev.Signal != 0 {
			why += fmt.Sprintf(" by signal %d", ev.Signal)
		}
		c.log.Info("dsi", "event", ev.Event, "signal", ev.Signal)
		c.answer(errors.New(why))
		c.markDown(why, false)
	case "net_down":
		c.advance(helperPlacing)
		c.log.Info("dsi", "event", ev.Event)
		// Before the call is up this is the network's answer to it, after
		// that the end of it.
		c.answer(errors.New("the network refused the data call (NO_NET)"))
		c.markDown("network dropped the IMS PDN (NO_NET)", true)
	case "dsi_event":
		c.log.Info("dsi", "event", ev.Event, "code", ev.Code)
	case "error":
		err := ev.failure()
		c.log.Warn("dsi", "event", ev.Event, "err", err)
		c.answer(err)
		c.markDown(err.Error(), false)
	case "exiting":
		c.log.Debug("dsi", "event", ev.Event, "code", ev.Code)
	default:
		c.log.Debug("dsi: an event this daemon does not know", "event", ev.Event)
	}
}

// onStderr logs what the helper has to say to a person, and at debug level
// what the libraries under it print.
func (c *dataCall) onStderr(line string) {
	c.mu.Lock()
	c.lastSaid = line
	c.mu.Unlock()
	if own, ok := strings.CutPrefix(line, helperProgram+": "); ok {
		c.log.Info("dsi", "helper", own)
		return
	}
	c.log.Debug("dsi", "stderr", line)
}

func (c *dataCall) complaint() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lastSaid
}

// advance notes how far the helper got. The events come one at a time.
func (c *dataCall) advance(to int32) {
	if c.progress.Load() < to {
		c.progress.Store(to)
	}
}

// markDown keeps the first reason the call is down, and whether it was the
// network's.
func (c *dataCall) markDown(reason string, byNetwork bool) {
	c.downOnce.Do(func() {
		c.mu.Lock()
		c.reason, c.byNetwork = reason, byNetwork
		c.mu.Unlock()
		close(c.down)
	})
}

// Down is closed when the PDN is lost or the helper has died.
func (c *dataCall) Down() <-chan struct{} { return c.down }

// Reason tells why, once Down is closed.
func (c *dataCall) Reason() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reason
}

// ByNetwork tells, once Down is closed, whether the network ended the call
// (NO_NET), rather than the helper dying or being stopped.
func (c *dataCall) ByNetwork() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.byNetwork
}

// Stop ends the helper, which takes the call down on its way out.
func (c *dataCall) Stop() {
	c.stopOnce.Do(func() {
		c.markDown("the data call was stopped", false)
		_ = c.stdin.Close()
		if c.gone(helperStopWait) {
			return
		}
		// The modem drops the call of a client that died.
		c.log.Warn("dsi: " + helperProgram + " does not stop, killing it")
		_ = c.cmd.Process.Kill()
		c.gone(3 * time.Second)
	})
}

func (c *dataCall) gone(within time.Duration) bool {
	t := time.NewTimer(within)
	defer t.Stop()
	select {
	case <-c.exited:
		return true
	case <-t.C:
		return false
	}
}

// killStaleDSI kills what else may hold a data call: a mudi-dsi-helper, the
// helper the config names (dsi_helper) or the firmware's dsi_netctrl_test,
// started by hand or by an earlier daemon and left running. The modem keeps
// one call for all the clients on a profile, so with one of those on the IMS
// profile, stopping our call would leave the PDN up (§131).
func killStaleDSI(helper string, log *slog.Logger) {
	stale := staleDSI(helper)
	dirs, _ := filepath.Glob("/proc/[0-9]*")
	self := os.Getpid()
	for _, dir := range dirs {
		pid, err := strconv.Atoi(filepath.Base(dir))
		if err != nil || pid == self {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil || len(raw) == 0 {
			continue
		}
		argv0 := strings.SplitN(string(raw), "\x00", 2)[0]
		exe, _ := os.Readlink(filepath.Join(dir, "exe"))
		if !stale(argv0, exe) {
			continue
		}
		if p, err := os.FindProcess(pid); err == nil && p.Signal(syscall.SIGTERM) == nil {
			log.Warn("killed a stale data-call process", "pid", pid, "name", filepath.Base(argv0))
		}
	}
}

// staleDSI tells a process that may hold a data call by its argv[0] and the
// file it runs (/proc/PID/exe). The helper from the config has to match by
// both: its name alone may be one an unrelated program has too.
func staleDSI(helper string) func(argv0, exe string) bool {
	name, file := filepath.Base(helper), ""
	if path, err := exec.LookPath(helper); err == nil {
		if real, err := filepath.EvalSymlinks(path); err == nil && filepath.IsAbs(real) {
			file = real
		}
	}
	return func(argv0, exe string) bool {
		base := filepath.Base(argv0)
		if base == helperProgram || base == "dsi_netctrl_test" {
			return true
		}
		// A helper replaced by an upgrade since it started runs a deleted file.
		exe = strings.TrimSuffix(exe, " (deleted)")
		return file != "" && base == name && exe == file
	}
}

// lineWriter hands on what is written to it, a line at a time. It takes
// everything and never fails, so the pipe behind it cannot fill up and stall
// the helper; of a line longer than helperLineMax it keeps the beginning.
type lineWriter struct {
	line func(string)
	buf  []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			w.keep(p)
			break
		}
		w.keep(p[:i])
		w.flush()
		p = p[i+1:]
	}
	return n, nil
}

func (w *lineWriter) keep(p []byte) {
	if room := helperLineMax - len(w.buf); len(p) > room {
		p = p[:room]
	}
	w.buf = append(w.buf, p...)
}

// flush ends the line, also one that came without its newline.
func (w *lineWriter) flush() {
	line := strings.TrimSpace(string(w.buf))
	w.buf = w.buf[:0]
	if line != "" {
		w.line(line)
	}
}
