package call

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// Session timers (RFC 4028). A session interval agreed in the INVITE
// transaction (Session-Expires) has to be refreshed by one of the two sides
// before it runs out, or the other side hangs up. We take the role the peer
// gives us; when it leaves the choice open, the peer refreshes. Our refreshes
// are UPDATE requests without SDP (§7.4).
//
// When the peer should have refreshed and three quarters of the interval
// have passed without it, we refresh the session ourselves before giving it
// up. A dialog that is gone (481, 408, no answer) ends the call at once; a
// session that nobody managed to refresh ends with its interval (§10).

const (
	sessionExpiresDefault = 1800  // seconds, asked for in our INVITE
	sessionExpiresMin     = 90    // RFC 4028 §4
	sessionExpiresMax     = 86400 // a longer interval from the network counts as this
)

// Test hooks.
var (
	sessionSecond  = time.Second   // one second of a session interval
	refreshTimeout = sipnet.TimerF // how long a refresh may stay unanswered
	// glareDelay is the pause before repeating a refresh that met 491
	// (RFC 3261 §14.1): 2.1–4 s for the owner of the Call-ID, up to 2 s for
	// the other side.
	glareDelay = func(ours bool) time.Duration {
		if ours {
			return 2100*time.Millisecond + rand.N(1900*time.Millisecond)
		}
		return rand.N(2000 * time.Millisecond)
	}
)

// sessionTimer is the session timer state of a call, guarded by Call.mu.
type sessionTimer struct {
	interval int       // seconds; 0 = no session timer
	local    bool      // we are the refresher
	peer     bool      // the peer supports the extension
	minSE    int       // largest Min-SE of this call: from a 422 or a request of the peer
	expires  time.Time // when the interval runs out
	gen      uint64    // changes with every (re)arm; timers of an older one do nothing
	timer    *time.Timer
}

// refreshTries counts the repeats of one refresh by their cause.
type refreshTries struct{ glare, small, failed int }

// sessionExpires parses Session-Expires (compact form x): the interval in
// seconds and the refresher parameter, "" when absent.
func sessionExpires(m sip.Message) (secs int, refresher string, ok bool) {
	v := headerValue(m, "Session-Expires")
	if v == "" {
		v = headerValue(m, "x")
	}
	delta, params, _ := strings.Cut(v, ";")
	n, err := strconv.Atoi(strings.TrimSpace(delta))
	if err != nil || n <= 0 {
		return 0, "", false
	}
	for _, p := range strings.Split(params, ";") {
		if k, val, found := strings.Cut(p, "="); found && strings.EqualFold(strings.TrimSpace(k), "refresher") {
			refresher = strings.ToLower(strings.TrimSpace(val))
		}
	}
	return n, refresher, true
}

// minSE returns the Min-SE of a message, 0 when absent.
func minSE(m sip.Message) int {
	delta, _, _ := strings.Cut(headerValue(m, "Min-SE"), ";")
	n, _ := strconv.Atoi(strings.TrimSpace(delta))
	return min(max(n, 0), sessionExpiresMax)
}

// sessionFor reads the session timer a request (INVITE, UPDATE) asks for and
// picks the refresher (RFC 4028 §9, table 2): the peer's choice when it made
// one; otherwise we refresh when the peer cannot, and else the roles stay as
// they are, which at the start of a call means the peer refreshes. interval
// is 0 when the request asks for no timer; ok is false for an interval below
// the minimum, which the caller answers with 422. Callers hold c.mu.
func (c *Call) sessionFor(req *sip.Request) (interval int, local, ok bool) {
	c.se.peer = hasTag(optionTags(req, "Supported"), "timer") || hasTag(optionTags(req, "Require"), "timer")
	c.se.minSE = max(c.se.minSE, minSE(req)) // goes into our own refreshes (§7.4)
	secs, refresher, has := sessionExpires(req)
	if !has {
		return 0, false, true
	}
	if secs < sessionExpiresMin {
		return 0, false, false
	}
	switch {
	case refresher == "uas":
		local = true
	case refresher == "uac":
		local = false
	case !c.se.peer:
		local = true
	default:
		local = c.se.interval > 0 && c.se.local
	}
	return min(secs, sessionExpiresMax), local, true
}

// sessionHeaders confirm the timer in our 2xx to the peer's INVITE or UPDATE
// (RFC 4028 §9); the peer is the UAC of that transaction.
func sessionHeaders(interval int, local, peer bool) []sip.Header {
	if interval == 0 {
		return nil
	}
	who := "uac"
	if local {
		who = "uas"
	}
	hs := []sip.Header{sip.NewHeader("Session-Expires", strconv.Itoa(interval)+";refresher="+who)}
	if !local || peer {
		hs = append(hs, sip.NewHeader("Require", "timer"))
	}
	return hs
}

func tooSmall(conn *sipnet.Conn, req *sip.Request) {
	_ = conn.Respond(req, 422, "Session Interval Too Small", sip.NewHeader("Min-SE", strconv.Itoa(sessionExpiresMin)))
}

// armSession (re)starts the timer for an interval that begins now. We refresh
// at half of it when the role is ours and at three quarters when the peer
// should have done so by then. interval 0 switches the timer off.
func (c *Call) armSession(interval int, local bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.armSessionLocked(interval, local)
}

func (c *Call) armSessionLocked(interval int, local bool) {
	if interval != 0 {
		// What an answer of the network says is not checked anywhere else.
		interval = min(max(interval, sessionExpiresMin), sessionExpiresMax)
	}
	c.se.interval, c.se.local = interval, local
	c.se.gen++
	if c.se.timer != nil {
		c.se.timer.Stop()
		c.se.timer = nil
	}
	if interval == 0 || c.state == StateEnded {
		return
	}
	d := time.Duration(interval) * sessionSecond
	c.se.expires = time.Now().Add(d)
	after := d / 2
	if !local {
		after = d * 3 / 4
	}
	gen := c.se.gen
	c.se.timer = time.AfterFunc(after, func() { c.refreshSession(gen, refreshTries{}) })
}

// refresherName says in the log who refreshes the session.
func refresherName(local bool) string {
	if local {
		return "us"
	}
	return "peer"
}

// sessionFromAnswer arms the timer that the 2xx to our INVITE settled on
// (RFC 4028 §7.2). Without Session-Expires in it there is none.
func (c *Call) sessionFromAnswer(res *sip.Response) {
	if secs, refresher, ok := sessionExpires(res); ok {
		c.armSession(secs, refresher != "uas")
		c.m.cfg.Log.Info("session timer", "call", c.callID, "interval", secs, "refresher", refresherName(refresher != "uas"))
	}
}

// refreshSession sends the refresh UPDATE and acts on the answer (RFC 4028
// §7.4 and §10). gen is the arming it belongs to: once the peer has refreshed
// the session or the call is over, it does nothing.
func (c *Call) refreshSession(gen uint64, tries refreshTries) {
	c.mu.Lock()
	if c.se.gen != gen || c.state == StateEnded || c.se.interval == 0 {
		c.mu.Unlock()
		return
	}
	interval, floor, local := c.se.interval, c.se.minSE, c.se.local
	c.mu.Unlock()
	log := c.m.cfg.Log.With("call", c.callID)
	if !local && tries == (refreshTries{}) {
		log.Info("the peer has not refreshed the session, refreshing it")
	}

	conn := c.m.reg.Conn()
	if conn == nil {
		c.retryRefresh(gen, tries, "not registered")
		return
	}
	r := c.inDialog("UPDATE").
		Add("Contact", c.m.contact()).
		Add("Allow", allow).
		Add("Supported", "timer").
		Add("Session-Expires", strconv.Itoa(max(interval, floor))+";refresher=uac")
	if floor > 0 {
		r.Add("Min-SE", strconv.Itoa(floor))
	}
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	res, err := conn.Do(ctx, r, nil)
	cancel()
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		c.sessionLost(gen, "session refresh: no answer")
	case err != nil:
		// The connection went away under the request; the registration is
		// getting a new one.
		c.retryRefresh(gen, tries, err.Error())
	case res.StatusCode < 300:
		secs, refresher, ok := sessionExpires(res)
		if !ok {
			secs = 0 // the peer switched the timer off (§7.2)
		}
		c.mu.Lock()
		if c.se.gen == gen {
			if v := headerValue(res, "Contact"); v != "" {
				c.target = uriOf(v) // UPDATE is a target refresh request
			}
			c.armSessionLocked(secs, refresher != "uas")
			log.Info("session refreshed", "interval", secs)
		}
		c.mu.Unlock()
	case res.StatusCode == 422 && tries.small < 2 && minSE(res) > max(interval, floor):
		c.mu.Lock()
		if c.se.gen == gen {
			c.se.minSE = minSE(res)
		}
		c.mu.Unlock()
		tries.small++
		c.refreshSession(gen, tries)
	case res.StatusCode == 491 && tries.glare < 3:
		tries.glare++
		time.AfterFunc(glareDelay(c.Dir == Outbound), func() { c.refreshSession(gen, tries) })
	case res.StatusCode == 481 || res.StatusCode == 408:
		c.sessionLost(gen, fmt.Sprintf("session refresh: %d %s", res.StatusCode, res.Reason))
	default:
		c.retryRefresh(gen, tries, fmt.Sprintf("%d %s", res.StatusCode, res.Reason))
	}
}

// retryRefresh tries again halfway to the point where an unrefreshed session
// ends: 32 s before the interval is over, or a third of it for short ones
// (RFC 4028 §10). When the tries or the time run out, the call ends there.
func (c *Call) retryRefresh(gen uint64, tries refreshTries, why string) {
	c.mu.Lock()
	margin := min(32*sessionSecond, time.Duration(c.se.interval)*sessionSecond/3)
	left := time.Until(c.se.expires) - margin
	stale := c.se.gen != gen
	c.mu.Unlock()
	if stale {
		return
	}
	if tries.failed >= 3 || left < 2*sessionSecond {
		c.m.cfg.Log.Warn("session not refreshed, the call ends with its interval", "call", c.callID, "reason", why)
		time.AfterFunc(max(left, 0), func() { c.sessionLost(gen, "session expired: "+why) })
		return
	}
	c.m.cfg.Log.Warn("session refresh failed, will retry", "call", c.callID, "reason", why)
	tries.failed++
	time.AfterFunc(left/2, func() { c.refreshSession(gen, tries) })
}

// sessionLost hangs up a call whose session is over, unless the session was
// refreshed or the call ended while we were waiting.
func (c *Call) sessionLost(gen uint64, cause string) {
	c.mu.Lock()
	stale := c.se.gen != gen || c.state == StateEnded
	c.mu.Unlock()
	if stale {
		return
	}
	c.m.cfg.Log.Warn("session is over, hanging up", "call", c.callID, "cause", cause)
	_ = c.bye(cause)
}
