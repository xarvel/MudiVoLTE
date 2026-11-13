package reg

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// subscription is the reg-event dialog (RFC 3680, TS 24.229 §5.1.1.3).
type subscription struct {
	callID, localTag, remoteTag string
	routes                      []string // route set from Record-Route, else Service-Route
	target                      string   // remote target (Contact of the 2xx)
	cseq                        uint32
	expires                     time.Duration
	at                          time.Time // when expires was granted
}

// subBackoff is the pause before another SUBSCRIBE after n failed ones.
var subBackoff = func(n int) time.Duration { return min(time.Minute<<min(n, 5), 30*time.Minute) }

// Subscribe subscribes to our own registration state and returns the
// granted expiry. Terminated or deactivated contacts trigger re-registration.
// A subscription the session already has is replaced; after a failure the
// next attempt is due after a growing pause (see subscriptionDue).
func (c *Client) Subscribe(ctx context.Context) (time.Duration, error) {
	c.mu.Lock()
	s := c.s
	if s == nil {
		c.mu.Unlock()
		return 0, fmt.Errorf("not registered")
	}
	sub := &subscription{callID: sipnet.Token(12) + "@" + c.cfg.UEAddr.String(), localTag: sipnet.Token(6),
		target: c.cfg.IMPU, routes: s.binding.Routes, cseq: 1}
	// A NOTIFY of the new dialog can overtake the 2xx, so it is ours already.
	prev := s.sub
	s.sub = sub
	c.mu.Unlock()

	exp, err := c.subscribe(ctx, s, sub)
	c.mu.Lock()
	if err != nil {
		if s.sub == sub {
			s.sub = prev
		}
		s.subRetry = time.Now().Add(subBackoff(s.subFails))
		s.subFails++
	} else {
		s.subFails, s.subRetry = 0, time.Time{}
	}
	c.mu.Unlock()
	return exp, err
}

// Resubscribe refreshes the reg-event subscription inside its dialog
// (RFC 6665 §4.1.2.2, TS 24.229 §5.1.1.3). A subscription the network no
// longer knows is replaced by a new one.
func (c *Client) Resubscribe(ctx context.Context) (time.Duration, error) {
	c.mu.Lock()
	s := c.s
	var sub *subscription
	if s != nil && s.sub != nil {
		sub = s.sub
		sub.cseq++
	}
	c.mu.Unlock()
	if s == nil {
		return 0, fmt.Errorf("not registered")
	}
	if sub == nil {
		return c.Subscribe(ctx)
	}
	exp, err := c.subscribe(ctx, s, sub)
	if err == nil {
		c.mu.Lock()
		s.subFails, s.subRetry = 0, time.Time{}
		c.mu.Unlock()
		return exp, nil
	}
	if s.conn.Err() != nil || ctx.Err() != nil {
		return 0, err // the registration is going away, with or without us
	}
	c.cfg.Log.Info("reg-event subscription not refreshed, subscribing anew", "err", err)
	return c.Subscribe(ctx)
}

// subscribe runs one SUBSCRIBE transaction of sub, the first or a refresh,
// and records what the 2xx grants.
func (c *Client) subscribe(ctx context.Context, s *session, sub *subscription) (time.Duration, error) {
	c.mu.Lock()
	req := c.subscribeRequest(s, sub, c.cfg.Expires, sub.cseq)
	c.mu.Unlock()
	res, err := s.conn.Do(ctx, req, nil)
	if err != nil {
		return 0, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return 0, fmt.Errorf("SUBSCRIBE reg: %d %s", res.StatusCode, res.Reason)
	}
	expires := c.cfg.Expires
	if v := headerValues(res, "Expires"); len(v) > 0 {
		if n, err := strconv.Atoi(strings.TrimSpace(v[0])); err == nil {
			expires = time.Duration(min(n, 1<<31)) * time.Second
		}
	}
	if expires <= 0 {
		return 0, fmt.Errorf("SUBSCRIBE reg: granted for %v", expires)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if sub.remoteTag == "" { // the 2xx to the first SUBSCRIBE makes the dialog
		if to := res.To(); to != nil {
			sub.remoteTag, _ = to.Params.Get("tag")
		}
		if rr := sipnet.ListValues(res, "Record-Route"); len(rr) > 0 {
			// UAC route set is the Record-Route list reversed (RFC 3261 §12.1.2).
			sub.routes = make([]string, len(rr))
			for i, r := range rr {
				sub.routes[len(rr)-1-i] = r
			}
		}
	}
	if v := headerValues(res, "Contact"); len(v) > 0 {
		if _, uri, ok := strings.Cut(v[0], "<"); ok {
			if uri, _, ok = strings.Cut(uri, ">"); ok && uri != "" {
				sub.target = uri
			}
		}
	}
	sub.expires, sub.at = expires, time.Now()
	return expires, nil
}

// subscriptionDue tells when the subscription needs attention: ahead of its
// expiry like the binding (TS 24.229 §5.1.1.3), after the pause that follows
// a failure, or at once in a session without one (a re-registration inside
// Refresh, a subscription the network ended).
func (c *Client) subscriptionDue() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.s
	switch {
	case s == nil:
		return time.Time{}, false
	case !s.subRetry.IsZero():
		return s.subRetry, true
	case s.sub == nil:
		return time.Now(), true
	}
	return s.sub.at.Add(refreshDelay(s.sub.expires)), true
}

func (c *Client) subscribeRequest(s *session, sub *subscription, expires time.Duration, cseq uint32) *sipnet.Request {
	from := "<" + c.cfg.IMPU + ">;tag=" + sub.localTag
	to := "<" + c.cfg.IMPU + ">"
	if sub.remoteTag != "" {
		to += ";tag=" + sub.remoteTag
	}
	r := sipnet.NewRequest("SUBSCRIBE", strings.Trim(sub.target, "<>")).
		Add("Via", "SIP/2.0/TCP "+s.sa.UE.Addr.String()+":"+strconv.Itoa(int(s.sa.UE.PortS))+";branch="+sipnet.NewBranch()).
		Add("Max-Forwards", "70")
	for _, rt := range sub.routes {
		r.Add("Route", rt)
	}
	r.Add("From", from).
		Add("To", to).
		Add("Call-ID", sub.callID).
		Add("CSeq", strconv.FormatUint(uint64(cseq), 10)+" SUBSCRIBE").
		Add("Contact", "<"+c.contactURI(s)+">").
		Add("Event", "reg").
		Add("Accept", "application/reginfo+xml").
		Add("Expires", strconv.Itoa(int(expires/time.Second))).
		Add("P-Preferred-Identity", "<"+s.binding.Preferred+">")
	if c.cfg.PANI != "" {
		r.Add("P-Access-Network-Info", c.cfg.PANI)
	}
	if c.cfg.UserAgent != "" {
		r.Add("User-Agent", c.cfg.UserAgent)
	}
	return r
}

// reginfo is the subset of RFC 3680 §5.4 we act on.
type reginfo struct {
	Registrations []struct {
		AOR      string `xml:"aor,attr"`
		State    string `xml:"state,attr"`
		Contacts []struct {
			State   string `xml:"state,attr"`
			Event   string `xml:"event,attr"`
			Expires string `xml:"expires,attr"`
			URI     string `xml:"uri"`
		} `xml:"contact"`
	} `xml:"registration"`
}

// regNews is what a reginfo document says about the binding of our contact.
type regNews struct {
	ended     string        // why the binding is gone; "" while it stands
	shortened bool          // the registrar shortened it to have us re-authenticate
	expires   time.Duration // what is left of the shortened binding
}

// readReginfo reads what body says about the binding of contactHostPort.
// When it is gone nothing else matters; otherwise TS 24.229 §5.1.1.5A
// (S-CSCF side §5.4.1.6) names a network-initiated re-authentication: an
// active registration whose contact of ours has the event "shortened", with
// the time left in its expires attribute, which RFC 3680 §5.4 then requires.
func readReginfo(body []byte, contactHostPort string) (regNews, error) {
	var ri reginfo
	if err := xml.Unmarshal(body, &ri); err != nil {
		return regNews{}, err
	}
	if reason := ri.ended(contactHostPort); reason != "" {
		return regNews{ended: reason}, nil
	}
	for _, r := range ri.Registrations {
		if r.State != "active" {
			continue
		}
		for _, ct := range r.Contacts {
			if ct.Event != "shortened" || !strings.Contains(ct.URI, contactHostPort) {
				continue
			}
			n, err := strconv.ParseUint(strings.TrimSpace(ct.Expires), 10, 64)
			if err != nil && !errors.Is(err, strconv.ErrRange) {
				return regNews{}, fmt.Errorf("shortened contact with expires %q", ct.Expires)
			}
			return regNews{shortened: true, expires: time.Duration(min(n, 1<<31)) * time.Second}, nil
		}
	}
	return regNews{}, nil
}

// ended returns why our contact lost its binding, or "".
func (ri *reginfo) ended(contactHostPort string) string {
	for _, r := range ri.Registrations {
		for _, ct := range r.Contacts {
			if strings.Contains(ct.URI, contactHostPort) && ct.State == "terminated" {
				return "contact " + ct.Event
			}
		}
	}
	for _, r := range ri.Registrations {
		if r.State == "terminated" {
			mine := false
			for _, ct := range r.Contacts {
				mine = mine || strings.Contains(ct.URI, contactHostPort)
			}
			if mine || len(r.Contacts) == 0 {
				return "registration terminated"
			}
		}
	}
	return ""
}

// reauthSpacing keeps apart the refreshes that shortenings make, should the
// network shorten the binding again right after each one.
const reauthSpacing = time.Minute

// shorten takes a binding the network has shortened to have us
// re-authenticate (TS 24.229 §5.1.1.5A): with expires left, it is refreshed
// when one granted for expires now would be (§5.1.1.4.1), and the S-CSCF
// challenges that REGISTER (§5.4.1.6). It reports whether the refresh moved
// earlier. A shortening that would move it later is let be: a full-state
// NOTIFY repeats the last event of a contact that has not changed since
// (§5.4.2.1.2), with less time left.
func (c *Client) shorten(expires time.Duration) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.s
	if s == nil {
		return false
	}
	by := time.Now().Add(refreshDelay(expires))
	if next := c.reauthAt.Add(reauthSpacing); !c.reauthAt.IsZero() && by.Before(next) {
		by = next
	}
	if !by.Before(s.due()) {
		return false
	}
	s.reauthBy = by
	s.reauthGen++
	c.cfg.Log.Info("network asks for re-authentication: registration shortened",
		"expires", expires, "refresh_in", time.Until(by).Round(time.Second))
	return true
}

func (c *Client) onRegNotify(conn *sipnet.Conn, req *sip.Request) {
	_ = conn.Respond(req, 200, "OK")
	state, params, _ := strings.Cut(strings.ToLower(firstValueRaw(req, "Subscription-State")), ";")
	state = strings.TrimSpace(state)
	c.mu.Lock()
	s := c.s
	if s == nil {
		c.mu.Unlock()
		return
	}
	hostport := s.sa.UE.Addr.String() + ":" + strconv.Itoa(int(s.sa.UE.PortS))
	// The end of a subscription we have replaced says nothing about the
	// registration, and its expiry is not ours any more.
	current := s.sub != nil && req.CallID() != nil && req.CallID().Value() == s.sub.callID
	moved, ended := false, false
	if current {
		switch state {
		case "active":
			// The notifier has the last word on the expiry (RFC 6665 §4.1.3).
			if n, err := strconv.Atoi(stateParam(params, "expires")); err == nil && n > 0 {
				s.sub.expires, s.sub.at = time.Duration(min(n, 1<<31))*time.Second, time.Now()
				moved = true
			}
		case "terminated":
			ended = true
			switch stateParam(params, "reason") {
			case "timeout", "deactivated":
				// The subscription is over, the registration is not: a new one at once.
				s.sub, s.subRetry, moved = nil, time.Time{}, true
			case "probation", "giveup":
				s.sub, s.subRetry, moved = nil, time.Now().Add(subBackoff(0)), true
			}
		}
	}
	c.mu.Unlock()

	var news regNews
	if body := req.Body(); len(body) > 0 {
		var err error
		if news, err = readReginfo(body, hostport); err != nil {
			c.cfg.Log.Warn("unparsable reginfo", "err", err)
		}
	}
	reason := news.ended
	if reason == "" && ended && !moved {
		reason = "reg-event subscription terminated"
	}
	if reason != "" {
		c.cfg.Log.Info("network ended our registration", "reason", reason)
		select {
		case c.regEvent <- reason:
		default:
		}
		return
	}
	if news.shortened && c.shorten(news.expires) {
		moved = true
	}
	if moved {
		select {
		case c.rescheduled <- struct{}{}:
		default:
		}
	}
}

// stateParam returns a parameter of Subscription-State (already lower case).
func stateParam(params, name string) string {
	for _, p := range strings.Split(params, ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.TrimSpace(k) == name {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstValueRaw(m sip.Message, name string) string {
	if v := headerValues(m, name); len(v) > 0 {
		return v[0]
	}
	return ""
}
