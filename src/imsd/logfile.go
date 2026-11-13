package main

// Service log in a file. logread on the Mudi holds only a few minutes (the
// modem's kernel fills the 256 KB buffer with long lines), while looking into
// "calls did not get through this evening" needs hours. The file lives in
// /var/log (tmpfs: it survives a service restart but not a router reboot);
// when it grows to the limit, the current file moves to .1 and the previous
// .1 is deleted. Log times are local: the init script passes the zone from
// the system settings in TZ, and the zone database is built into the binary
// (OpenWrt has no /usr/share/zoneinfo).

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	_ "time/tzdata"
)

const defaultLogFileKB = 1024

type rotatingFile struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func openRotatingFile(path string, maxBytes int64) (*rotatingFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	r := &rotatingFile{path: path, max: maxBytes}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	if r.size > 0 && r.size+int64(len(p)) > r.max {
		r.f.Close()
		r.f = nil
		_ = os.Rename(r.path, r.path+".1")
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}

func (r *rotatingFile) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.f == nil {
		return nil
	}
	err := r.f.Close()
	r.f = nil
	return err
}

// newLogger returns a text logger to stderr (procd → logread) and, when
// log_file is set, to the file; times are local, without a zone offset.
func newLogger(cfg *Config) (*slog.Logger, io.Closer) {
	var out io.Writer = os.Stderr
	var closer io.Closer = nopCloser{}
	if cfg.LogFile != "" {
		kb := cfg.LogFileMaxKB
		if kb <= 0 {
			kb = defaultLogFileKB
		}
		if rf, err := openRotatingFile(cfg.LogFile, int64(kb)*1024); err == nil {
			out, closer = io.MultiWriter(os.Stderr, rf), rf
		} else {
			slog.New(slog.NewTextHandler(os.Stderr, nil)).Warn("log file", "path", cfg.LogFile, "err", err)
		}
	}
	opts := &slog.HandlerOptions{ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey && len(groups) == 0 {
			return slog.String(slog.TimeKey, a.Value.Time().Format("2006-01-02T15:04:05.000"))
		}
		return a
	}}
	if lvl, ok := parseLogLevel(cfg.LogLevel); ok {
		opts.Level = lvl
	}
	return slog.New(slog.NewTextHandler(out, opts)), closer
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }
