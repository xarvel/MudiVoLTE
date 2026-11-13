package main

import (
	"context"
	"time"

	"github.com/emiago/sipgo/sip"
)

type phoneDialog interface {
	Do(context.Context, *sip.Request) (*sip.Response, error)
}

func phoneTarget(m interface {
	Contact() *sip.ContactHeader
	From() *sip.FromHeader
}) sip.Uri {
	if h := m.Contact(); h != nil {
		return h.Address
	}
	// Malformed peers may omit Contact. Do still sets the established
	// dialog's destination and headers; do not panic on their input.
	if h := m.From(); h != nil {
		return h.Address
	}
	return sip.Uri{Scheme: "sip", Host: "localhost"}
}

// watchPhone recovers a line when a phone disappears without BYE. Silence
// alone is not a hangup: hold, DTX and a muted microphone can all stop RTP.
// After idle RTP, an in-dialog OPTIONS checks whether the phone is alive.
// Its returned stop function also waits for the probe to leave the dialog,
// so a following BYE cannot race its CSeq update.
func (m *callManager) watchPhone(lc *lineCall, leg *rtpLeg, dlg phoneDialog, target sip.Uri) func() {
	ctx, cancel := context.WithCancel(lc.ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		lastCheck := time.Now()
		ticker := time.NewTicker(min(m.phoneIdle, time.Second))
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				last := leg.lastReceived()
				if now.Sub(last) < m.phoneIdle || now.Sub(lastCheck) < m.phoneIdle {
					continue
				}
				probe, stop := context.WithTimeout(ctx, m.phoneProbe)
				res, err := dlg.Do(probe, sip.NewRequest(sip.OPTIONS, target))
				stop()
				lastCheck = time.Now()
				if ctx.Err() != nil {
					return
				}
				if err == nil && res != nil && res.StatusCode != 481 && res.StatusCode != 408 {
					continue // even 405/501 proves the phone is present
				}
				if leg.lastReceived().After(last) {
					continue // media resumed while waiting for the probe
				}
				m.logger.Info("call: phone disappeared (no RTP or SIP response)", "err", err)
				lc.cancel()
				return
			}
		}
	}()
	return func() { cancel(); <-done }
}
