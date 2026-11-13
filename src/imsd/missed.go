package main

// Missed incoming calls, for the web page and `mudi-volte missed`: one JSON
// line per incoming call that no phone answered. Unlike the log, a record
// keeps the full number, because the list is there to call back; the file is
// for its owner only (0600). It stays short: past maxMissedBytes it is cut to
// the newest keepMissed calls. `mudi-volte missed clear` truncates it.
//
// A record keeps the router's clock at the call. A call missed before NTP
// has set the clock after a boot keeps the time the clock showed: putting it
// right later would mean rewriting the file under `missed clear`, for the
// rare call in the first minutes after a boot.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// Why a call was missed. The web page and printMissed turn these into text.
const (
	missedNoPhone    = "no-phone"       // no phone was connected
	missedNoAnswer   = "no-answer"      // the phones rang, nobody answered
	missedHungUp     = "caller-hung-up" // the caller gave up before the answer
	missedDeclined   = "declined"       // someone pressed Decline on a phone
	missedBusy       = "busy"           // a phone answered busy
	missedLineBusy   = "line-busy"      // another call had the line
	missedNotAllowed = "not-allowed"    // not in the list of allowed callers
	missedError      = "error"          // our failure; the log tells which
)

const (
	maxMissedBytes = 64 << 10
	keepMissed     = 200
)

type missedCall struct {
	Time   string `json:"time"` // RFC 3339, the router's local time
	From   string `json:"from"` // "" when the caller withheld the number
	Reason string `json:"reason"`
}

type missedLog struct {
	mu   sync.Mutex
	path string
	log  *slog.Logger
	now  func() time.Time
	max  int64 // trim past this size
	keep int   // calls left after trimming
}

// newMissedLog returns nil, which records nothing, for an empty path.
func newMissedLog(path string, log *slog.Logger) *missedLog {
	if path == "" {
		return nil
	}
	return &missedLog{path: path, log: log, now: time.Now, max: maxMissedBytes, keep: keepMissed}
}

// add records a missed call from the number the network gave. A failure only
// goes to the log: the call is over either way.
func (l *missedLog) add(from, reason string) {
	if l == nil {
		return
	}
	if from = callerUser(from); from == "anonymous" {
		from = ""
	}
	line, _ := json.Marshal(missedCall{Time: l.now().Format(time.RFC3339), From: from, Reason: reason})
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.append(append(line, '\n')); err != nil && l.log != nil {
		l.log.Warn("missed call: not recorded", "file", l.path, "err", err)
	}
}

func (l *missedLog) append(line []byte) error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(line)
	var size int64
	if fi, serr := f.Stat(); serr == nil {
		size = fi.Size()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && size > l.max {
		err = trimLines(l.path, l.keep)
	}
	return err
}

// trimLines leaves the last keep lines of the file, replacing it at once.
func trimLines(path string, keep int) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := bytes.SplitAfter(b, []byte("\n"))
	if n := len(lines); n > 0 && len(lines[n-1]) == 0 {
		lines = lines[:n-1]
	}
	if len(lines) <= keep {
		return nil
	}
	return writeFileAtomic(path, bytes.Join(lines[len(lines)-keep:], nil))
}

func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// readMissed reads the records of the file, oldest first; lines it cannot
// parse are skipped. A missing file is an empty list.
func readMissed(path string) ([]missedCall, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var calls []missedCall
	for _, line := range strings.Split(string(b), "\n") {
		var c missedCall
		if line != "" && json.Unmarshal([]byte(line), &c) == nil && c.Time != "" {
			calls = append(calls, c)
		}
	}
	return calls, nil
}

func missedReasonText(reason string) string {
	switch reason {
	case missedNoPhone:
		return "no phone was connected"
	case missedNoAnswer:
		return "nobody answered"
	case missedHungUp:
		return "the caller hung up before the answer"
	case missedDeclined:
		return "declined on a phone"
	case missedBusy:
		return "a phone was busy"
	case missedLineBusy:
		return "the line was busy with another call"
	case missedNotAllowed:
		return "not in the list of allowed callers"
	case missedError:
		return "error, see mudi-volte logs"
	}
	return reason
}

// printMissed is `mudi-imsd missed FILE`: the list for a human, newest first.
func printMissed(w io.Writer, path string) int {
	calls, err := readMissed(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "missed calls:", err)
		return 1
	}
	if len(calls) == 0 {
		fmt.Fprintln(w, "No missed calls.")
		return 0
	}
	for i := len(calls) - 1; i >= 0; i-- {
		c := calls[i]
		when := c.Time
		if t, err := time.Parse(time.RFC3339, c.Time); err == nil {
			when = t.Format("2006-01-02 15:04")
		}
		from := c.From
		if from == "" {
			from = "withheld"
		}
		fmt.Fprintf(w, "%s  %-16s  %s\n", when, from, missedReasonText(c.Reason))
	}
	fmt.Fprintf(w, "%d missed call(s); 'mudi-volte missed clear' empties the list.\n", len(calls))
	return 0
}
