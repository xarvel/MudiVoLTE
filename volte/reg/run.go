package reg

import (
	"context"
	"errors"
	"time"

	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// Status is reported by Run on every state change.
type Status int

const (
	StatusRegistering Status = iota
	StatusRegistered
	StatusFailed
	StatusClosed
)

func (s Status) String() string {
	return [...]string{"registering", "registered", "failed", "closed"}[s]
}

// refreshDelay follows TS 24.229 §5.1.1.4.1: 600 s before expiry when the
// binding is longer than 1200 s, otherwise at half time.
func refreshDelay(exp time.Duration) time.Duration {
	if exp > 1200*time.Second {
		return exp - 600*time.Second
	}
	return exp / 2
}

func backoff(n int) time.Duration {
	d := 5 * time.Second << min(n, 6)
	return min(d, 5*time.Minute)
}

// ErrAccessLost is the cause to cancel the context of Run with
// (context.WithCancelCause) when the access network is gone: the address the
// registration is bound to no longer exists, so nothing reaches the P-CSCF,
// and its answer to a de-REGISTER could not come. Run then leaves without
// one. User-initiated de-registration is optional (TS 24.229 §5.1.1.6.1),
// and once the bearer for SIP signalling is back the UE registers anew
// (annex L.2.2.1B for EPS). That registration replaces the one left behind
// (§5.4.1.2.1, §5.4.1.2.2, §5.4.2.1.2 NOTE 2), which would otherwise expire.
var ErrAccessLost = errors.New("the access network is gone")

// Run keeps the registration alive until ctx ends, then de-registers; when
// ctx ends with the cause ErrAccessLost it only gives up what it holds.
// onStatus may be nil.
func (c *Client) Run(ctx context.Context, onStatus func(Status, error)) {
	report := func(s Status, err error) {
		if onStatus != nil {
			onStatus(s, err)
		}
	}
	// All exit paths need this, including cancellation during replacement
	// registration or its backoff: an older session may still own SAs/sockets.
	defer func() {
		if errors.Is(context.Cause(ctx), ErrAccessLost) {
			c.abandon()
		} else {
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			if err := c.Deregister(dctx); err != nil {
				c.cfg.Log.Warn("de-REGISTER", "err", err)
			}
		}
		report(StatusClosed, nil)
	}()
	failures := 0
	for {
		report(StatusRegistering, nil)
		if _, err := c.Register(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			report(StatusFailed, err)
			c.cfg.Log.Warn("registration failed", "err", err, "retry_in", backoff(failures))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff(failures)):
			}
			failures++
			continue
		}
		failures = 0
		report(StatusRegistered, nil)
		if _, err := c.Subscribe(ctx); err != nil && ctx.Err() == nil {
			c.cfg.Log.Warn("reg-event subscription failed, will try again", "err", err)
		}
		done, lost := c.hold(ctx)
		if done {
			return
		}
		if errors.Is(lost, errNoBinding) {
			// Like a failed registration, so a registrar that keeps dropping
			// the binding in its 200 gets REGISTER after a pause.
			report(StatusFailed, lost)
			c.cfg.Log.Warn("registration dropped by the network", "err", lost, "retry_in", backoff(failures))
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff(failures)):
			}
			failures++
		}
	}
}

// refreshDue is the protected connection and when the binding is due for
// refresh (session.due); ok is false without a registration.
func (c *Client) refreshDue() (conn *sipnet.Conn, due time.Time, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.s == nil || c.s.conn == nil {
		return nil, time.Time{}, false
	}
	return c.s.conn, c.s.due(), true
}

// hold refreshes the binding and the reg-event subscription until the
// registration is lost (done is false; lost is the error of a failed
// refresh, nil for other losses) or ctx ends (done is true).
func (c *Client) hold(ctx context.Context) (done bool, lost error) {
	for {
		conn, refreshAt, ok := c.refreshDue()
		if !ok {
			return false, nil
		}
		refresh := time.NewTimer(time.Until(refreshAt))
		resubscribe := time.NewTimer(time.Hour)
		due, subscribed := c.subscriptionDue()
		if subscribed {
			resubscribe.Reset(time.Until(due))
		} else {
			resubscribe.Stop()
		}
		gone := false
		select {
		case <-ctx.Done():
		case <-conn.Done():
			c.cfg.Log.Warn("protected connection lost", "err", conn.Err())
			gone = true
		case reason := <-c.regEvent:
			c.cfg.Log.Info("re-registering", "reason", reason)
			gone = true
		case <-c.rescheduled:
			// A NOTIFY moved when the subscription or the binding is due:
			// start the timers anew.
		case <-resubscribe.C:
			if _, err := c.Resubscribe(ctx); err != nil && ctx.Err() == nil {
				c.cfg.Log.Warn("reg-event subscription not renewed, will try again", "err", err)
			}
		case <-refresh.C:
			if _, err := c.Refresh(ctx); err != nil {
				gone, lost = true, err
			}
		}
		refresh.Stop()
		resubscribe.Stop()
		if ctx.Err() != nil {
			return true, nil
		}
		if gone {
			return false, lost
		}
	}
}
