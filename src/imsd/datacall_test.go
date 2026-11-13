package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// --- The data call by mudi-dsi-helper: the real helper ---
//
// The helper is built by the host's compiler against the stand-in for the
// firmware's library that its own tests use (src/dsi-helper/tests), so what
// is tested is the daemon and the helper together, down to the calls the
// library gets.

// helperBuild is the helper with a working library and two broken installations.
type helperBuild struct {
	helper   string
	missing  string
	nosymbol string
}

func buildHelper(t *testing.T) helperBuild {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip(helperProgram + " is a linux program")
	}
	if _, err := exec.LookPath("cc"); err != nil {
		t.Skip("no C compiler to build " + helperProgram + " with")
	}
	dir := t.TempDir()
	cc := func(out string, args ...string) {
		t.Helper()
		args = append(append([]string{"-O1", "-pthread", "-o", out}, args...), "-ldl")
		if msg, err := exec.Command("cc", args...).CombinedOutput(); err != nil {
			t.Fatalf("cc %s: %v\n%s", strings.Join(args, " "), err, msg)
		}
	}
	source := filepath.Join("..", "dsi-helper")
	stub := filepath.Join(dir, "libdsi_stub.so")
	cc(stub, "-shared", "-fPIC", filepath.Join(source, "tests", "dsi_stub.c"))
	// A loadable library without the required DSI exports.
	empty := filepath.Join(dir, "empty.c")
	if err := os.WriteFile(empty, []byte("int unrelated(void) { return 0; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nosymbol := filepath.Join(dir, "empty.so")
	cc(nosymbol, "-shared", "-fPIC", empty)
	build := func(name, library string) string {
		out := filepath.Join(dir, name)
		// Keep the production stop deadline: the stub's NO_NET thread may be
		// delayed on a busy host. A confirmed stop does not use the whole wait.
		cc(out, `-DMUDI_DSI_LIBRARY="`+library+`"`,
			"-DHANDLE_RETRY_MS=20", "-DHANDLE_TIMEOUT_MS=2000",
			filepath.Join(source, helperProgram+".c"))
		return out
	}
	return helperBuild{
		helper:   build(helperProgram, stub),
		missing:  build("missing", filepath.Join(dir, "missing.so")),
		nosymbol: build("nosymbol", nosymbol),
	}
}

// stubLog sets the stand-in up for one test, mode being what should go
// differently (dsi_stub.c has the list). It returns a function that reads
// what the stand-in was asked to do, and which events it sent.
func stubLog(t *testing.T, mode string) func() []string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "calls.log")
	t.Setenv("DSI_STUB_LOG", path)
	t.Setenv("DSI_STUB_MODE", mode)
	return func() []string {
		raw, _ := os.ReadFile(path)
		var calls []string
		for _, line := range strings.Split(string(raw), "\n") {
			// It also reports the signals its threads have blocked.
			if line != "" && !strings.HasPrefix(line, "thread ") {
				calls = append(calls, line)
			}
		}
		return calls
	}
}

// stubCall is what the stand-in sees of one call for profile 2: the setup for
// an IP version, then the rest.
func stubCall(ipVersion string, rest ...string) []string {
	setup := []string{"subs 1", "init 0", "handle", "param 11 num=" + ipVersion + " buf=null", "param 1 num=2 buf=null"}
	return append(setup, rest...)
}

func wantCalls(t *testing.T, got []string, want ...[]string) {
	t.Helper()
	if all := slices.Concat(want...); !slices.Equal(got, all) {
		t.Errorf("the library was asked for\n%q, want\n%q", got, all)
	}
}

// logBook is a log to read back.
type logBook struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBook) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBook) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *logBook) logger() *slog.Logger {
	return slog.New(slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// shorten sets one of the waits for the length of a test.
func shorten(t *testing.T, wait *time.Duration, to time.Duration) {
	t.Helper()
	was := *wait
	*wait = to
	t.Cleanup(func() { *wait = was })
}

func wantUp(t *testing.T, call *dataCall) {
	t.Helper()
	select {
	case <-call.Down():
		t.Fatalf("the data call went down by itself: %s", call.Reason())
	case <-time.After(200 * time.Millisecond):
	}
}

// wantDown returns the reason of the loss.
func wantDown(t *testing.T, call *dataCall) string {
	t.Helper()
	select {
	case <-call.Down():
	case <-time.After(5 * time.Second):
		t.Fatal("the loss of the data call not noticed")
	}
	return call.Reason()
}

func helperConfig(helper string) *Config {
	cfg := defaultConfig()
	cfg.DSIHelper = helper
	return cfg
}

func TestDataCallByHelper(t *testing.T) {
	b := buildHelper(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	t.Run("up, then stopped", func(t *testing.T) {
		// Exercise a confirmation later than the old 400 ms test deadline.
		calls := stubLog(t, "slow_stop=750")
		var book logBook
		call, err := startDataCall(ctx, helperConfig(b.helper), 2, book.logger())
		if err != nil {
			t.Fatal(err)
		}
		defer call.Stop()
		wantUp(t, call)
		call.Stop()
		if reason := wantDown(t, call); reason != "the data call was stopped" {
			t.Errorf("reason: %q", reason)
		}
		wantCalls(t, calls(), stubCall("10", "start", "event 1", "stop", "event 2", "release"))
		// What the helper says for a person to read is logged as its own.
		for _, want := range []string{`helper="stdin is closed: stopping"`, "family=ipv4v6", "event=net_up", "event=net_down"} {
			if !strings.Contains(book.String(), want) {
				t.Errorf("the log lacks %s:\n%s", want, book.String())
			}
		}
	})

	t.Run("lost", func(t *testing.T) {
		calls := stubLog(t, "drop")
		call, err := startDataCall(ctx, helperConfig(b.helper), 2, quietLog())
		if err != nil {
			t.Fatal(err)
		}
		defer call.Stop()
		if reason := wantDown(t, call); !strings.Contains(reason, "NO_NET") || !call.ByNetwork() {
			t.Errorf("reason: %q, by the network: %v", reason, call.ByNetwork())
		}
		call.Stop()
		wantCalls(t, calls(), stubCall("10", "start", "event 1", "event 2", "release"))
	})

	t.Run("IPv4 where IPv4v6 is refused", func(t *testing.T) {
		calls := stubLog(t, "refuse_ip=10")
		call, err := startDataCall(ctx, helperConfig(b.helper), 2, quietLog())
		if err != nil {
			t.Fatal(err)
		}
		defer call.Stop()
		wantUp(t, call)
		call.Stop()
		wantCalls(t, calls(), stubCall("10", "start", "event 2", "release"),
			stubCall("4", "start", "event 1", "stop", "event 2", "release"))
	})

	t.Run("refused", func(t *testing.T) {
		calls := stubLog(t, "refuse")
		cfg := helperConfig(b.helper)
		_, err := startDataCall(ctx, cfg, 2, quietLog())
		if err == nil || isUnusable(err) {
			t.Fatalf("want a refusal: %v", err)
		}
		for _, want := range []string{"ipv4v6: ", "ipv4: ", "NO_NET"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the error lacks %q: %v", want, err)
			}
		}
		wantCalls(t, calls(), stubCall("10", "start", "event 2", "release"), stubCall("4", "start", "event 2", "release"))

	})

	t.Run("the helper dies", func(t *testing.T) {
		calls := stubLog(t, "")
		call, err := startDataCall(ctx, helperConfig(b.helper), 2, quietLog())
		if err != nil {
			t.Fatal(err)
		}
		defer call.Stop()
		if err := call.cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		if reason := wantDown(t, call); !strings.Contains(reason, helperProgram+" exited") || call.ByNetwork() {
			t.Errorf("reason: %q, by the network: %v", reason, call.ByNetwork())
		}
		wantCalls(t, calls(), stubCall("10", "start", "event 1"))
	})

	t.Run("stopped by someone else", func(t *testing.T) {
		calls := stubLog(t, "")
		call, err := startDataCall(ctx, helperConfig(b.helper), 2, quietLog())
		if err != nil {
			t.Fatal(err)
		}
		defer call.Stop()
		wantUp(t, call)
		if err := call.cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		// Its NO_NET is the end of the stop, not the network's word.
		if reason := wantDown(t, call); reason != helperProgram+" was stopped by signal 15" || call.ByNetwork() {
			t.Errorf("reason: %q, by the network: %v", reason, call.ByNetwork())
		}
		if !call.gone(5 * time.Second) {
			t.Fatal("the helper did not finish its stop")
		}
		wantCalls(t, calls(), stubCall("10", "start", "event 1", "stop", "event 2", "release"))
	})

	t.Run("no reply", func(t *testing.T) {
		calls := stubLog(t, "silent")
		shorten(t, &helperReplyWait, 300*time.Millisecond)
		_, err := startDataCall(ctx, helperConfig(b.helper), 2, quietLog())
		if err == nil || isUnusable(err) || strings.Count(err.Error(), "no reply to the data call") != 2 {
			t.Fatalf("want no reply for either family: %v", err)
		}
		// A call that got no reply is taken back all the same.
		wantCalls(t, calls(), stubCall("10", "start", "stop", "event 2", "release"),
			stubCall("4", "start", "stop", "event 2", "release"))
	})

	t.Run("cancelled", func(t *testing.T) {
		calls := stubLog(t, "silent")
		short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		defer cancel()
		_, err := startDataCall(short, helperConfig(b.helper), 2, quietLog())
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("want the end of the context: %v", err)
		}
		wantCalls(t, calls(), stubCall("10", "start", "stop", "event 2", "release"))
	})

	t.Run("the library fails", func(t *testing.T) {
		for _, tc := range []struct {
			mode, want string
			host       bool // before the call went to the modem
		}{
			{"fail_init", "dsi_init failed (code -1)", true},
			{"fail_param=1", "dsi_set_data_call_param failed for parameter 1 (code -1)", true},
			{"never_ready", "dsi_get_data_srvc_hndl failed (code 0)", true},
			{"fail_start", "dsi_start_data_call failed (code -1)", false},
		} {
			stubLog(t, tc.mode)
			_, err := startDataCall(ctx, helperConfig(b.helper), 2, quietLog())
			if err == nil || isUnusable(err) || isHostSide(err) != tc.host ||
				strings.Count(err.Error(), helperProgram+": "+tc.want) != 2 {
				t.Errorf("%s: %v", tc.mode, err)
			}
		}
	})

	t.Run("the library prints", func(t *testing.T) {
		stubLog(t, "noise")
		var book logBook
		call, err := startDataCall(ctx, helperConfig(b.helper), 2, book.logger())
		if err != nil {
			t.Fatal(err)
		}
		call.Stop()
		// Wherever the library printed it, it comes as the helper's stderr.
		for _, want := range []string{`stderr="dsi_stub: dsi_init on stdout, buffered"`, `stderr="dsi_stub: an event on stderr"`} {
			if !strings.Contains(book.String(), want) {
				t.Errorf("the log lacks %s:\n%s", want, book.String())
			}
		}
		if strings.Contains(book.String(), "not a line") {
			t.Errorf("the library got to the events:\n%s", book.String())
		}
	})

	t.Run("unusable library", func(t *testing.T) {
		for _, bin := range []string{b.missing, b.nosymbol} {
			calls := stubLog(t, "")
			_, err := startDataCall(ctx, helperConfig(bin), 2, quietLog())
			if !isUnusable(err) {
				t.Fatalf("want an unusable library: %v", err)
			}
			wantCalls(t, calls())
		}
	})
}

// --- The data call by mudi-dsi-helper: a script in its place ---

// writeFakeHelper makes a helper of a shell script. Its arguments end up in
// the file args.
func writeFakeHelper(t *testing.T, script string) (bin, args string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh to play " + helperProgram)
	}
	dir := t.TempDir()
	bin, args = filepath.Join(dir, helperProgram), filepath.Join(dir, "args")
	script = "#!/bin/sh\necho \"$*\" >> '" + args + "'\n" + script
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, args
}

func TestHelperProtocol(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	t.Run("lines of no meaning", func(t *testing.T) {
		bin, args := writeFakeHelper(t, `echo 'diag: a library got to the events'
echo '{"v":1,"event":"of a later helper","code":7}'
echo '{"v":1,"event":"ready","pid":1,"subscription":1,"profile":2,"family":"ipv4v6","tries":1}'
echo '{"v":1,"event":"dsi_event","code":19}'
echo '{"v":1,"event":"net_up"}'
cat >/dev/null
echo '{"v":1,"event":"net_down"}'
echo '{"v":1,"event":"exiting","code":0}'
`)
		call, err := startDataCall(ctx, helperConfig(bin), 2, quietLog())
		if err != nil {
			t.Fatal(err)
		}
		defer call.Stop()
		wantUp(t, call)
		call.Stop()
		if reason := wantDown(t, call); reason != "the data call was stopped" {
			t.Errorf("reason: %q", reason)
		}
		if raw, _ := os.ReadFile(args); string(raw) != "1 2 ipv4v6\n" {
			t.Errorf("arguments: %q", raw)
		}
	})

	t.Run("another version", func(t *testing.T) {
		bin, args := writeFakeHelper(t, `echo '{"v":2,"event":"net_up"}'
exec sleep 30
`)
		shorten(t, &helperReplyWait, 300*time.Millisecond)
		shorten(t, &helperStopWait, 100*time.Millisecond)
		_, err := startDataCall(ctx, helperConfig(bin), 2, quietLog())
		if !isUnusable(err) || !strings.Contains(err.Error(), "no reply to the data call") {
			t.Fatalf("a line of another protocol taken for an answer: %v", err)
		}
		if raw, _ := os.ReadFile(args); string(raw) != "1 2 ipv4v6\n" {
			t.Errorf("arguments: %q", raw)
		}
	})

	t.Run("exit is loss", func(t *testing.T) {
		bin, _ := writeFakeHelper(t, `echo '{"v":1,"event":"net_up"}'
sleep 0.3
exit 5
`)
		call, err := startDataCall(ctx, helperConfig(bin), 2, quietLog())
		if err != nil {
			t.Fatal(err)
		}
		defer call.Stop()
		if reason := wantDown(t, call); reason != helperProgram+" exited (exit status 5)" {
			t.Errorf("reason: %q", reason)
		}
	})

	t.Run("a helper that does not stop", func(t *testing.T) {
		bin, _ := writeFakeHelper(t, `echo '{"v":1,"event":"net_up"}'
exec sleep 30
`)
		shorten(t, &helperStopWait, 200*time.Millisecond)
		var book logBook
		call, err := startDataCall(ctx, helperConfig(bin), 2, book.logger())
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		call.Stop()
		if took := time.Since(started); took > 2*time.Second {
			t.Errorf("stopping took %s", took)
		}
		select {
		case <-call.exited:
		default:
			t.Error("the helper is still there")
		}
		if !strings.Contains(book.String(), "does not stop, killing it") {
			t.Errorf("the log does not tell:\n%s", book.String())
		}
	})

	t.Run("an error", func(t *testing.T) {
		bin, args := writeFakeHelper(t, `echo '{"v":1,"event":"ready","pid":1,"subscription":1,"profile":2,"family":"'"$3"'","tries":1}'
echo '{"v":1,"event":"error","stage":"dsi_start_data_call","code":-1}'
echo '{"v":1,"event":"exiting","code":1}'
exit 1
`)
		_, err := startDataCall(ctx, helperConfig(bin), 2, quietLog())
		if err == nil || isUnusable(err) || strings.Count(err.Error(), "dsi_start_data_call failed (code -1)") != 2 {
			t.Fatalf("want the failed step for either family: %v", err)
		}
		if raw, _ := os.ReadFile(args); string(raw) != "1 2 ipv4v6\n1 2 ipv4\n" {
			t.Errorf("arguments: %q", raw)
		}
	})

	t.Run("failed on the router", func(t *testing.T) {
		shorten(t, &helperReplyWait, 300*time.Millisecond)
		shorten(t, &helperStopWait, 100*time.Millisecond)
		for name, script := range map[string]string{
			"a step":  `echo '{"v":1,"event":"library"}'; echo '{"v":1,"event":"error","stage":"dsi_init","code":-1}'; exit 1`,
			"a crash": `echo '{"v":1,"event":"library"}'; kill -SEGV $$`,
			// The call had gone to the modem, but a helper that dies has not
			// heard from the network.
			"a crash while the call is placed": `echo '{"v":1,"event":"library"}'
echo '{"v":1,"event":"ready","pid":1,"subscription":1,"profile":2,"family":"'"$3"'","tries":1}'
kill -SEGV $$`,
			"it hangs": `echo '{"v":1,"event":"library"}'; exec sleep 30`,
			"stopped by someone else": `echo '{"v":1,"event":"library"}'
echo '{"v":1,"event":"ready","pid":1,"subscription":1,"profile":2,"family":"'"$3"'","tries":1}'
echo '{"v":1,"event":"stopping","signal":15}'
echo '{"v":1,"event":"net_down"}'`,
		} {
			bin, args := writeFakeHelper(t, script+"\n")
			_, err := startDataCall(ctx, helperConfig(bin), 2, quietLog())
			if !isHostSide(err) || isUnusable(err) {
				t.Errorf("%s: %v", name, err)
			}
			// It may go otherwise for the other family.
			if raw, _ := os.ReadFile(args); string(raw) != "1 2 ipv4v6\n1 2 ipv4\n" {
				t.Errorf("%s: arguments: %q", name, raw)
			}
		}
	})

	t.Run("refused for one family, failed on the router for the other", func(t *testing.T) {
		bin, _ := writeFakeHelper(t, `echo '{"v":1,"event":"library"}'
if [ "$3" = ipv4v6 ]; then
	echo '{"v":1,"event":"error","stage":"dsi_set_data_call_param","code":-1,"param":11}'
	exit 1
fi
echo '{"v":1,"event":"ready","pid":1,"subscription":1,"profile":2,"family":"ipv4","tries":1}'
echo '{"v":1,"event":"net_down"}'
exit 3
`)
		_, err := startDataCall(ctx, helperConfig(bin), 2, quietLog())
		if err == nil || isHostSide(err) || isUnusable(err) || !strings.Contains(err.Error(), "refused the data call") {
			t.Fatalf("the network had its say: %v", err)
		}
	})

	t.Run("refused for one family, a crash for the other", func(t *testing.T) {
		bin, _ := writeFakeHelper(t, `echo '{"v":1,"event":"library"}'
echo '{"v":1,"event":"ready","pid":1,"subscription":1,"profile":2,"family":"'"$3"'","tries":1}'
[ "$3" = ipv4v6 ] && kill -SEGV $$
echo '{"v":1,"event":"net_down"}'
exit 3
`)
		_, err := startDataCall(ctx, helperConfig(bin), 2, quietLog())
		if err == nil || isHostSide(err) || isUnusable(err) || !strings.Contains(err.Error(), "refused the data call") {
			t.Fatalf("the network had its say: %v", err)
		}
	})

	t.Run("lost, and not by the network", func(t *testing.T) {
		bin, _ := writeFakeHelper(t, `echo '{"v":1,"event":"library"}'
echo '{"v":1,"event":"ready","pid":1,"subscription":1,"profile":2,"family":"ipv4v6","tries":1}'
echo '{"v":1,"event":"net_up"}'
sleep 0.3
echo '{"v":1,"event":"stopping","signal":1}'
echo '{"v":1,"event":"net_down"}'
`)
		call, err := startDataCall(ctx, helperConfig(bin), 2, quietLog())
		if err != nil {
			t.Fatal(err)
		}
		defer call.Stop()
		if reason := wantDown(t, call); reason != helperProgram+" was stopped by signal 1" || call.ByNetwork() {
			t.Errorf("reason: %q, by the network: %v", reason, call.ByNetwork())
		}
	})

	t.Run("no use on this firmware", func(t *testing.T) {
		for name, script := range map[string]string{
			"library_load":   `echo '{"v":1,"event":"error","stage":"library_load","code":2}'; exit 1`,
			"library_symbol": `echo '{"v":1,"event":"error","stage":"library_symbol","code":0}'; exit 1`,
			"says nothing":   `echo 'Error relocating /usr/sbin/mudi-dsi-helper' >&2; exit 127`,
		} {
			bin, args := writeFakeHelper(t, script+"\n")
			_, err := startDataCall(ctx, helperConfig(bin), 2, quietLog())
			if !isUnusable(err) {
				t.Errorf("%s: %v", name, err)
			}
			// It would be no better for another family, so that is not tried.
			if raw, _ := os.ReadFile(args); string(raw) != "1 2 ipv4v6\n" {
				t.Errorf("%s: arguments: %q", name, raw)
			}
			if name == "says nothing" && !strings.Contains(err.Error(), "before saying anything: Error relocating") {
				t.Errorf("the error does not tell what the helper printed: %v", err)
			}
		}
	})
}

// The helper is mandatory; a broken installation is not a network refusal.
func TestDataCallValidation(t *testing.T) {
	ctx := context.Background()
	t.Run("missing or not executable", func(t *testing.T) {
		dir := t.TempDir()
		plain := filepath.Join(dir, "plain")
		if err := os.WriteFile(plain, []byte("not executable"), 0o600); err != nil {
			t.Fatal(err)
		}
		for _, bin := range []string{filepath.Join(dir, "absent"), plain, dir, "./relative"} {
			_, err := startDataCall(ctx, helperConfig(bin), 2, quietLog())
			if !isUnusable(err) || !strings.Contains(err.Error(), "dsi_helper:") {
				t.Errorf("%s: %v", bin, err)
			}
		}
	})
	t.Run("no profile, no call", func(t *testing.T) {
		bin, args := writeFakeHelper(t, "exit 99\n")
		for _, profile := range []int{-1, 0, 256, 1001} {
			_, err := startDataCall(ctx, helperConfig(bin), profile, quietLog())
			if !isHostSide(err) || !strings.Contains(err.Error(), "not a modem profile number") {
				t.Errorf("profile %d: %v", profile, err)
			}
		}
		if _, err := os.Stat(args); !os.IsNotExist(err) {
			t.Errorf("helper run with an invalid profile: %v", err)
		}
	})
}

// What else may hold the call: by name, and the configured helper by its file
// as well.
func TestStaleDSI(t *testing.T) {
	dir := t.TempDir()
	helper := filepath.Join(dir, "dsi-call")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := filepath.EvalSymlinks(helper)
	if err != nil {
		t.Fatal(err)
	}
	stale := staleDSI(helper)
	for _, tc := range []struct {
		argv0, exe string
		want       bool
	}{
		{"/usr/sbin/mudi-dsi-helper", "/usr/sbin/mudi-dsi-helper", true},
		{"mudi-dsi-helper", "", true},
		{"/usr/bin/dsi_netctrl_test", "/usr/bin/dsi_netctrl_test", true},
		{helper, file, true},
		{"dsi-call", file + " (deleted)", true},  // replaced by an upgrade
		{"dsi-call", "/usr/bin/dsi-call", false}, // the same name, another program
		{"/bin/sh", "/bin/busybox", false},
		{"", "", false},
	} {
		if got := stale(tc.argv0, tc.exe); got != tc.want {
			t.Errorf("%q running %q: %v", tc.argv0, tc.exe, got)
		}
	}
	// A helper that is not there is known by none of its files.
	if staleDSI(filepath.Join(dir, "absent"))("absent", filepath.Join(dir, "absent")) {
		t.Error("a missing helper matched")
	}
}

func TestLineWriter(t *testing.T) {
	var got []string
	w := &lineWriter{line: func(line string) { got = append(got, line) }}
	long := strings.Repeat("x", helperLineMax+100)
	for _, chunk := range []string{"one\ntw", "o\r\n", "\n  \n", "thr", "", "ee\n" + long, long + "\nlast"} {
		if n, err := w.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("Write(%d bytes): %d, %v", len(chunk), n, err)
		}
	}
	want := []string{"one", "two", "three", long[:helperLineMax]}
	if !slices.Equal(got, want) {
		t.Fatalf("lines: %q", got)
	}
	// What came without its newline is a line when the stream ends.
	w.flush()
	w.flush()
	if !slices.Equal(got, append(want, "last")) {
		t.Fatalf("lines after the end: %q", got)
	}
}
