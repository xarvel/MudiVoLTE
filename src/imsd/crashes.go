package main

// Restarts after a crash. procd starts a daemon that ended without a stop
// again 10 s later, without end (respawn 3600 10 0 in
// /etc/init.d/mudi-volte), and each new process places the data call and
// registers with the operator anew. What a process keeps in memory to pace
// its retries dies with it, so a small file next to the state file (in
// /var/run: tmpfs, a reboot clears it) carries across processes how many of
// them in a row ended without a stop. The next one waits the longer before
// it reaches for the network (service.crashWait), and the state shows the
// count as crash_restarts.

import (
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// crashRecord is what the file says about the process that wrote it last.
type crashRecord struct {
	PID int `json:"pid"`
	// Running stays true until the process ends by its own choice: after a
	// stop, or with an error it reports. A panic or a kill leaves it true.
	Running bool `json:"running"`
	// Crashes is the number of processes in a row before this one that
	// ended without a stop; 0 again once this one has run for a while.
	Crashes int       `json:"crashes"`
	Started time.Time `json:"started"`
}

// crashDelays are the waits before the first session after the first,
// second, ... restart in a row that follows a crash; the last one repeats.
// procd adds its own 10 s to each.
var crashDelays = []time.Duration{0, 10 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute}

// crashHealthy is how long a process has to run for a crash after it to
// count as the first in a row again.
const crashHealthy = 30 * time.Minute

func crashDelay(n int) time.Duration {
	switch {
	case n <= 0:
		return 0
	case n > len(crashDelays):
		return crashDelays[len(crashDelays)-1]
	}
	return crashDelays[n-1]
}

// crashFile lives next to the state file, in /var/run/mudi-volte.
func crashFile(cfg *Config) string {
	return filepath.Join(filepath.Dir(cfg.stateFile()), "crashes.json")
}

// crashCount is this process's line in the file.
type crashCount struct {
	path    string
	log     *slog.Logger
	n       int // processes in a row before this one that ended without a stop
	started time.Time

	mu   sync.Mutex
	done bool // the end is recorded: nothing more goes into the file
}

// startCrashCount reads what the previous process left at path and records
// this one as running.
func startCrashCount(path string, log *slog.Logger) *crashCount {
	c := &crashCount{path: path, log: log, started: time.Now()}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// The first start since the boot.
	case err != nil:
		log.Warn("crash count: cannot read", "path", path, "err", err)
	default:
		var prev crashRecord
		if err := json.Unmarshal(raw, &prev); err != nil {
			log.Warn("crash count: unreadable, counting anew", "path", path, "err", err)
		} else if prev.Running {
			c.n = prev.Crashes + 1
		}
	}
	c.write(true, c.n)
	return c
}

func (c *crashCount) write(running bool, n int) {
	rec := crashRecord{PID: os.Getpid(), Running: running, Crashes: n, Started: c.started}
	if err := writeJSONAtomic(c.path, rec); err != nil {
		c.log.Warn("crash count: cannot write", "path", c.path, "err", err)
	}
}

// healthy records that this process has run long enough: a crash from now
// on is the first in a row. It tells whether that changed the count.
func (c *crashCount) healthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done || c.n == 0 {
		return false
	}
	c.write(true, 0)
	return true
}

// stopped records an end the process chose: the next start is no restart
// after a crash.
func (c *crashCount) stopped() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	c.done = true
	c.write(false, 0)
}
