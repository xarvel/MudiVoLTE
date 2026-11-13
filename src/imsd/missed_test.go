package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo"
)

func TestMissedLogRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missed.jsonl")
	l := newMissedLog(path, nil)
	at := time.Date(2026, 11, 6, 13, 20, 46, 0, time.FixedZone("CET", 3600))
	l.now = func() time.Time { return at }
	l.add("+447700900789", missedNoPhone)
	l.add("", missedNoAnswer)
	l.add("07700900456", missedHungUp)

	calls, err := readMissed(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []missedCall{
		{Time: "2026-11-06T13:20:46+01:00", From: "+447700900789", Reason: missedNoPhone},
		{Time: "2026-11-06T13:20:46+01:00", From: "", Reason: missedNoAnswer},
		{Time: "2026-11-06T13:20:46+01:00", From: "07700900456", Reason: missedHungUp},
	}
	if fmt.Sprint(calls) != fmt.Sprint(want) {
		t.Fatalf("records:\n got %v\nwant %v", calls, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600: the list holds full numbers", fi.Mode().Perm())
	}

	// `mudi-volte missed clear` truncates the file under the daemon.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	l.add("+447700900123", missedDeclined)
	if calls, _ := readMissed(path); len(calls) != 1 || calls[0].From != "+447700900123" {
		t.Fatalf("after clear: %v", calls)
	}
}

func TestMissedLogTrims(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missed.jsonl")
	l := newMissedLog(path, nil)
	l.max, l.keep = 300, 3
	for i := 1; i <= 20; i++ {
		l.add(fmt.Sprintf("+4477009000%02d", i), missedNoAnswer)
	}
	calls, err := readMissed(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) < 3 || len(calls) > 4 {
		t.Fatalf("%d calls left, want the newest 3 or 4", len(calls))
	}
	if last := calls[len(calls)-1].From; last != "+447700900020" {
		t.Fatalf("newest call lost: last is %s", last)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary file left behind: %v", err)
	}
}

func TestMissedLogOff(t *testing.T) {
	l := newMissedLog("", nil)
	if l != nil {
		t.Fatal("an empty path must turn recording off")
	}
	l.add("+447700900789", missedNoPhone) // must not panic
}

func TestPrintMissed(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if rc := printMissed(&out, filepath.Join(dir, "none.jsonl")); rc != 0 || out.String() != "No missed calls.\n" {
		t.Fatalf("missing file: rc %d, %q", rc, out.String())
	}
	path := filepath.Join(dir, "missed.jsonl")
	data := `{"time":"2026-11-06T13:20:46+01:00","from":"+447700900789","reason":"no-phone"}
not json
{"time":"2026-11-06T14:02:00+01:00","from":"","reason":"caller-hung-up"}
`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if rc := printMissed(&out, path); rc != 0 {
		t.Fatalf("rc %d", rc)
	}
	want := "2026-11-06 14:02  withheld          the caller hung up before the answer\n" +
		"2026-11-06 13:20  +447700900789     no phone was connected\n" +
		"2 missed call(s); 'mudi-volte missed clear' empties the list.\n"
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
}

// TestSIPMissedCalls: every way an incoming call can go unanswered leaves a
// record with its reason; an answered call leaves none.
func TestSIPMissedCalls(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missed.jsonl")
	rig := newTestRig(t, &Config{Allow: []string{"+447700900456"}, MissedCalls: path}, true)
	records := func(n int) []missedCall {
		t.Helper()
		var calls []missedCall
		waitFor(t, func() bool {
			calls, _ = readMissed(path)
			return len(calls) >= n
		}, fmt.Sprintf("expected %d missed calls", n))
		return calls
	}
	ring := func(ph *testPhone) *sipgo.DialogServerSession {
		t.Helper()
		select {
		case dlg := <-ph.incoming:
			return dlg
		case <-time.After(3 * time.Second):
			t.Fatal("the INVITE did not reach the phone")
		}
		return nil
	}
	lineFree := func() {
		t.Helper()
		waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
	}

	// No phone connected.
	rig.mgr.incomingFromNetwork(newFakeIMSCall("in-1", CallIncoming), "+447700900456")
	records(1)
	lineFree()
	// Not in the allow list, number withheld or not.
	rig.mgr.incomingFromNetwork(newFakeIMSCall("in-2", CallIncoming), "+447700900000")
	rig.mgr.incomingFromNetwork(newFakeIMSCall("in-3", CallIncoming), "")
	records(3)

	ph := newTestPhone(t)
	if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("register: %v %v", res, err)
	}
	// A second call while the first rings: line busy. Then the phone declines.
	first := newFakeIMSCall("in-4", CallIncoming)
	rig.mgr.incomingFromNetwork(first, "+447700900456")
	dlg := ring(ph)
	second := newFakeIMSCall("in-5", CallIncoming)
	rig.mgr.incomingFromNetwork(second, "+447700900456")
	if second.rejected.Load() != rejectBusy {
		t.Fatalf("second call: %d, want %d", second.rejected.Load(), rejectBusy)
	}
	if err := dlg.Respond(603, "Decline", nil); err != nil {
		t.Fatal(err)
	}
	records(5)
	lineFree()
	// The caller hangs up while the phone rings.
	gone := newFakeIMSCall("in-6", CallIncoming)
	rig.mgr.incomingFromNetwork(gone, "+447700900456")
	ring(ph)
	rig.mgr.onIMSEvent(gone, CallStateEnded)
	records(6)
	lineFree()
	// Answered: no record.
	answered := newFakeIMSCall("in-7", CallIncoming)
	rig.mgr.incomingFromNetwork(answered, "+447700900456")
	dlg = ring(ph)
	if err := dlg.RespondSDP(ph.sdp()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, answered.answered.Load, "the network was not answered")
	rig.mgr.onIMSEvent(answered, CallStateEnded)
	lineFree()

	calls, err := readMissed(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range calls {
		got = append(got, c.From+" "+c.Reason)
	}
	want := []string{
		"+447700900456 no-phone",
		"+447700900000 not-allowed",
		" not-allowed",
		"+447700900456 line-busy",
		"+447700900456 declined",
		"+447700900456 caller-hung-up",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("records:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
