package main

// Modem state for the service mode (S5): the external IMS mode, network
// registration, the radio access type and the radio restart (CFUN 4→1). All
// commands go through ATLink, that is, in the confirmed SUB1 context (§69).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

type modem struct {
	link *ATLink
	log  *slog.Logger
	// sleep is replaced in tests.
	sleep func(ctx context.Context, d time.Duration) error
}

func newModem(link *ATLink, log *slog.Logger) *modem {
	return &modem{link: link, log: log, sleep: sleepCtx}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// externalMode reports whether "External VoLTE Stack" is on (QCFG ims = 2,
// §71). A "no" costs the service minutes of downtime, so it is believed only
// after three identical answers in a row.
func (m *modem) externalMode(ctx context.Context) (bool, error) {
	var last string
	for i := 0; i < 3; i++ {
		if i > 0 {
			if err := m.sleep(ctx, 2*time.Second); err != nil {
				return false, err
			}
		}
		out, err := m.link.query(ctx, `AT+QCFG="ims"`)
		if err != nil {
			return false, err
		}
		v, ok := parseQCFGIMS(out)
		if !ok {
			return false, fmt.Errorf("QCFG ims: cannot read the reply %.80q", out)
		}
		if v == 2 {
			return true, nil
		}
		last = strings.Join(strings.Fields(out), " ")
	}
	m.log.Warn("modem: not in External VoLTE mode", "answer", last)
	return false, nil
}

// radio returns the packet-domain registration and the access type: "LTE",
// "NR", "3G", "2G" or "" (no network).
func (m *modem) radio(ctx context.Context) (attached bool, rat string, err error) {
	out, err := m.link.query(ctx, "AT+CEREG?")
	if err != nil {
		return false, "", err
	}
	if stat, ok := parseCEREG(out); ok && (stat == 1 || stat == 5) {
		attached = true
	}
	out, err = m.link.query(ctx, "AT+COPS?")
	if err != nil {
		return attached, "", err
	}
	if act, ok := parseCOPSAct(out); ok {
		rat = ratFromAct(act)
	}
	return attached, rat, nil
}

// waitService waits for registration on LTE/NR for at most timeout.
func (m *modem) waitService(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last string
	for {
		attached, rat, err := m.radio(ctx)
		switch {
		case err != nil:
			last = err.Error()
		case attached && (rat == "LTE" || rat == "NR"):
			return nil
		default:
			last = fmt.Sprintf("attached=%v rat=%q", attached, rat)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no LTE within %s (%s)", timeout, last)
		}
		if err := m.sleep(ctx, 5*time.Second); err != nil {
			return err
		}
	}
}

// radioCycle does CFUN 4→1: after a visit to 3G, bringing the PDN up again is
// not enough, the network keeps routing calls past IMS (§87). The router
// loses the Internet for some 10–30 seconds.
func (m *modem) radioCycle(ctx context.Context) error {
	m.log.Warn("modem: radio restart (CFUN 4 -> 1)")
	if _, err := m.link.command(ctx, "AT+CFUN=4"); err != nil {
		return fmt.Errorf("CFUN=4: %w", err)
	}
	stopped := m.sleep(ctx, 6*time.Second)
	// The radio is off now. It has to come back even when the service is being
	// stopped: nothing else would turn it on, and the router would stay off
	// the network (§118).
	on := context.WithoutCancel(ctx)
	var err error
	for i := 0; i < 3; i++ {
		if _, err = m.link.command(on, "AT+CFUN=1"); err == nil {
			break
		}
		if serr := m.sleep(on, 3*time.Second); serr != nil {
			return serr
		}
	}
	if err != nil {
		return fmt.Errorf("CFUN=1: %w", err)
	}
	if stopped != nil {
		return stopped
	}
	return m.waitService(ctx, 3*time.Minute)
}

var errNoField = errors.New("field not found")

// atFields returns the fields of a reply after the prefix (e.g. "+CEREG:"), without quotes.
func atFields(out, prefix string) ([]string, error) {
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		var f []string
		for _, v := range strings.Split(line[len(prefix):], ",") {
			f = append(f, strings.Trim(strings.TrimSpace(v), "\""))
		}
		return f, nil
	}
	return nil, errNoField
}

// parseQCFGIMS — +QCFG: "ims",<mode>[,<state>] → mode (0 per MBN, 1 on, 2 external stack).
func parseQCFGIMS(out string) (int, bool) {
	f, err := atFields(out, "+QCFG:")
	if err != nil || len(f) < 2 || !strings.EqualFold(f[0], "ims") {
		return 0, false
	}
	v, err := strconv.Atoi(f[1])
	return v, err == nil
}

// parseCEREG — +CEREG: <n>,<stat>[,…] → stat (1 home, 5 roaming).
func parseCEREG(out string) (int, bool) {
	f, err := atFields(out, "+CEREG:")
	if err != nil || len(f) < 2 {
		return 0, false
	}
	v, err := strconv.Atoi(f[1])
	return v, err == nil
}

// parseCOPSAct — +COPS: <mode>,<format>,<oper>,<AcT> → AcT.
func parseCOPSAct(out string) (int, bool) {
	f, err := atFields(out, "+COPS:")
	if err != nil || len(f) < 4 {
		return 0, false
	}
	v, err := strconv.Atoi(f[3])
	return v, err == nil
}

// ratFromAct maps an AcT of TS 27.007 (+COPS) to a coarse access type.
func ratFromAct(act int) string {
	switch act {
	case 7, 9, 10, 13: // E-UTRAN, NB-S1, E-UTRA on 5GCN, EN-DC
		return "LTE"
	case 11, 12: // NR on 5GCN, NG-RAN
		return "NR"
	case 2, 4, 5, 6:
		return "3G"
	case 0, 1, 3, 8:
		return "2G"
	}
	return ""
}
