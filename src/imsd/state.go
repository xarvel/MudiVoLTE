package main

// Service state for `mudi-volte status`: a JSON file in /var/run/mudi-volte,
// written through a temporary file and rename so that a reader never sees
// half of it.

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type serviceState struct {
	// Phase: starting | modem | pdn | registering | registered | recovering |
	// radio-restart | stopped.
	Phase      string    `json:"phase"`
	Registered bool      `json:"registered"`
	Since      time.Time `json:"since"`
	Number     string    `json:"number,omitempty"`
	Interface  string    `json:"interface,omitempty"`
	Address    string    `json:"address,omitempty"`
	PCSCF      []string  `json:"pcscf,omitempty"`
	RAT        string    `json:"rat,omitempty"`
	Phones     []string  `json:"phones"`
	PhonesTLS  []string  `json:"phones_tls,omitempty"` // of Phones, those signed in over TLS (calls with SRTP)
	Restarts   int       `json:"restarts"`
	// CrashRestarts: how many processes in a row before this one ended
	// without a stop (crashes.go); 0 again after 30 min of running.
	CrashRestarts int        `json:"crash_restarts"`
	LastError     string     `json:"last_error,omitempty"`
	LastErrorAt   *time.Time `json:"last_error_at,omitempty"`
	PID           int        `json:"pid"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

type stateWriter struct {
	mu     sync.Mutex
	path   string
	s      serviceState
	phones func() []string
	secure func() []string // phones on TLS
	log    *slog.Logger

	// After a boot the router's clock is behind until NTP steps it, so Since
	// and LastErrorAt are not stamped once: every write sets them to the wall
	// time of the write minus the time since the phase change or the error
	// on the monotonic clock. The first write after the step puts them
	// right, and UpdatedAt minus Since, which the web pages show, never
	// counts the step. now is the wall clock and mono the monotonic one
	// (both time.Now: Sub uses its monotonic reading); tests step one and
	// not the other.
	now, mono        func() time.Time
	phaseAt, errorAt time.Time // on mono
}

func newStateWriter(path string, log *slog.Logger) *stateWriter {
	w := &stateWriter{path: path, log: log, now: time.Now, mono: time.Now}
	w.update(func(s *serviceState) { s.Phase = "starting" })
	return w
}

// update changes the state and writes the file at once.
func (w *stateWriter) update(fn func(s *serviceState)) {
	w.mu.Lock()
	defer w.mu.Unlock()
	prev := w.s.Phase
	if fn != nil {
		fn(&w.s)
	}
	if w.s.Phase != prev || w.phaseAt.IsZero() {
		w.phaseAt = w.mono()
	}
	w.writeLocked()
}

func (w *stateWriter) fail(err error) {
	if err == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.s.LastError, w.errorAt = err.Error(), w.mono()
	w.writeLocked()
}

// writeLocked puts Since and LastErrorAt on the clock of this write and
// writes the file; w.mu is held.
func (w *stateWriter) writeLocked() {
	now, mono := w.now(), w.mono()
	w.s.Since = now.Add(-mono.Sub(w.phaseAt))
	if !w.errorAt.IsZero() {
		t := now.Add(-mono.Sub(w.errorAt))
		w.s.LastErrorAt = &t
	}
	w.s.PID, w.s.UpdatedAt = os.Getpid(), now
	w.s.Phones = []string{}
	w.s.PhonesTLS = nil
	if w.secure != nil {
		w.s.PhonesTLS = w.secure()
	}
	if w.phones != nil {
		w.s.Phones = w.phones()
	}
	if err := writeJSONAtomic(w.path, w.s); err != nil && w.log != nil {
		w.log.Warn("state file", "path", w.path, "err", err)
	}
}

func (w *stateWriter) snapshot() serviceState {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.s
}

func writeJSONAtomic(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	// The state and the bindings hold the number and the phones' addresses:
	// owner only (rpcd reads as root).
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
