package call

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// Dial places an MMTel call to target (tel:+44… or a SIP URI) with media at
// local. It returns at once; progress arrives through OnState.
func (m *Manager) Dial(target string, local netip.AddrPort) (*Call, error) {
	return m.DialWith(target, local, nil)
}

// DialWith is Dial with attach called before the first OnState, so the
// application can bind its own state to the call.
func (m *Manager) DialWith(target string, local netip.AddrPort, attach func(*Call)) (*Call, error) {
	conn := m.reg.Conn()
	b, ok := m.reg.Binding()
	if conn == nil || !ok {
		return nil, errors.New("not registered")
	}
	if !strings.Contains(target, ":") {
		target = "tel:" + target
	}
	impu := m.reg.IMPU()
	if b.Preferred != "" {
		impu = b.Preferred
	}
	c := newCall(m, Outbound)
	c.callID = sipnet.Token(12) + "@" + strings.Split(m.reg.SentBy(), ":")[0]
	c.localTag = sipnet.Token(6)
	c.localURI = "<" + impu + ">"
	c.remoteURI = "<" + target + ">"
	c.remoteID = c.remoteURI
	c.target = target
	c.routes = append([]string(nil), b.Routes...) // TS 24.229 §5.1.2A.1.1
	c.routes0 = c.routes
	c.local = local
	c.state = StateCalling
	c.inviteSeq = 1
	c.out = c.newInviteLocked()

	if !m.remember(c) {
		return nil, errors.New("Call-ID collision")
	}
	if attach != nil {
		attach(c)
	}
	m.notify(c, StateCalling)
	go c.runInvite(conn)
	return c, nil
}

// newInviteLocked builds our INVITE with the CSeq in c.inviteSeq. It asks for
// a session timer and leaves the choice of the refresher to the far side
// (RFC 4028 §7.1). Callers hold c.mu, or own the call alone.
func (c *Call) newInviteLocked() *sipnet.Request {
	floor := c.se.minSE
	r := c.inDialogSeqLocked("INVITE", c.inviteSeq, sipnet.NewBranch())
	r.Add("Contact", c.m.contact()).
		Add("Accept-Contact", `*;+g.3gpp.icsi-ref="`+mmtelICSI+`"`).
		Add("P-Preferred-Service", "urn:urn-7:3gpp-service.ims.icsi.mmtel").
		Add("P-Preferred-Identity", c.localURI).
		Add("Supported", "100rel, timer").
		Add("Session-Expires", strconv.Itoa(max(sessionExpiresDefault, floor)))
	if floor > 0 {
		r.Add("Min-SE", strconv.Itoa(floor))
	}
	r.Add("Allow", allow).
		Add("Accept", "application/sdp").
		Add("Content-Type", "application/sdp")
	r.Body = SessionDescription{ID: c.sdpID, Version: c.sdpVer, Local: c.local, Formats: OfferFormats(c.m.cfg.Codecs)}.Bytes()
	return r
}

// ourInvite is the INVITE we sent last, with its CSeq.
func (c *Call) ourInvite() (*sipnet.Request, uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out, c.inviteSeq
}

// retryWithMinSE answers a 422 to our INVITE by preparing the same INVITE
// with the session interval the refusing side asks for (RFC 4028 §7.4,
// TS 24.229 §5.1.2A.1.1). It reports whether there is one to send. The
// check for a CANCEL and the switch to the new INVITE are one step, so a
// hangup cancels either the old INVITE or the new one, never one that is
// already answered.
func (c *Call) retryWithMinSE(conn *sipnet.Conn, res *sip.Response) bool {
	floor := minSE(res)
	c.mu.Lock()
	if res.StatusCode != 422 || floor <= c.se.minSE || c.cancelled || c.inviteSeq >= 3 {
		c.mu.Unlock()
		return false
	}
	ack := c.ackNon2xxLocked(res)
	c.se.minSE = floor
	c.localSeq++
	c.inviteSeq = c.localSeq
	c.remoteTag = ""
	c.target = strings.Trim(c.remoteURI, "<>")
	c.routes = c.routes0
	c.out = c.newInviteLocked()
	c.mu.Unlock()
	_ = conn.SendRequest(ack)
	return true
}

func (c *Call) runInvite(conn *sipnet.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	go func() {
		select {
		case <-c.done:
			cancel()
		case <-ctx.Done():
		}
	}()
	var res *sip.Response
	for {
		c.mu.Lock()
		out, cancelled := c.out, c.cancelled
		c.mu.Unlock()
		if cancelled && out.Get("Min-SE") != "" {
			// Hung up between the 422 and this second INVITE: it stays unsent.
			c.setState(StateEnded, "cancelled")
			return
		}
		var err error
		res, err = conn.Do(ctx, out, func(p *sip.Response) { c.onProvisional(conn, p) })
		if err != nil {
			c.setState(StateEnded, "INVITE: "+err.Error())
			return
		}
		if !c.retryWithMinSE(conn, res) {
			break
		}
	}
	c.updateDialog(res)
	if res.StatusCode >= 300 {
		_ = conn.SendRequest(c.ackNon2xx(res))
		cause := fmt.Sprintf("%d %s", res.StatusCode, res.Reason)
		c.mu.Lock()
		if c.cancelled {
			cause = "cancelled"
		}
		c.mu.Unlock()
		c.setState(StateEnded, cause)
		return
	}
	c.takeAnswer(res)
	_, seq := c.ourInvite()
	_ = conn.SendRequest(c.inDialogSeq("ACK", seq, sipnet.NewBranch()))
	c.mu.Lock()
	cancelled := c.cancelled
	c.answered = !cancelled // decided together with cancel(): one of the two wins
	c.mu.Unlock()
	if cancelled {
		// The answer crossed our CANCEL: the call exists and has to be ended
		// as one (RFC 3261 §9.1).
		_ = c.bye("cancelled")
		return
	}
	c.setState(StateActive, "")
	c.sessionFromAnswer(res)
}

// updateDialog records the remote tag, target and route set from a response
// that establishes the (early) dialog (RFC 3261 §12.1.2).
func (c *Call) updateDialog(res *sip.Response) {
	tag := toTag(res)
	if tag == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.remoteTag = tag
	if v := headerValue(res, "Contact"); v != "" && res.StatusCode < 300 {
		c.target = uriOf(v)
	}
	if rr := sipnet.ListValues(res, "Record-Route"); len(rr) > 0 && res.StatusCode < 300 {
		c.routes = make([]string, len(rr))
		for i, r := range rr {
			c.routes[len(rr)-1-i] = r
		}
	}
	if pai := headerValue(res, "P-Asserted-Identity"); pai != "" {
		c.remoteID = pai
	}
}

// takeAnswer negotiates media from an SDP answer, once.
func (c *Call) takeAnswer(res *sip.Response) bool {
	body := res.Body()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(body) == 0 || c.hasMedia {
		return c.hasMedia
	}
	ans, err := ParseSDP(body)
	if err != nil {
		return false
	}
	n, err := Negotiate(ans, c.m.cfg.Codecs)
	if err != nil {
		return false
	}
	c.neg, c.offerDir, c.hasMedia = n, ans.Direction, true
	return true
}

func (c *Call) onProvisional(conn *sipnet.Conn, res *sip.Response) {
	if res.StatusCode == 100 {
		return
	}
	c.updateDialog(res)
	media := c.takeAnswer(res)
	if rseq := strings.TrimSpace(headerValue(res, "RSeq")); rseq != "" && hasTag(optionTags(res, "Require"), "100rel") {
		// RFC 3262 §7.2: RAck = RSeq SP CSeq-num SP Method, taken from the
		// reliable provisional itself (its CSeq header is already "num METHOD").
		cseq := strings.TrimSpace(headerValue(res, "CSeq"))
		if cseq == "" {
			_, seq := c.ourInvite()
			cseq = itoa(seq) + " INVITE"
		}
		prack := c.inDialog("PRACK").Add("RAck", rseq+" "+cseq)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := conn.Do(ctx, prack, nil); err != nil {
				c.m.cfg.Log.Warn("PRACK", "call", c.callID, "err", err)
			}
		}()
	}
	switch {
	case res.StatusCode == 183 && media:
		c.setState(StateEarly, "")
	case res.StatusCode == 180:
		c.setState(StateRinging, "")
	}
}

// ackNon2xx is the ACK for a failed INVITE: same branch, sent hop by hop
// (RFC 3261 §17.1.1.3).
func (c *Call) ackNon2xx(res *sip.Response) *sipnet.Request {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ackNon2xxLocked(res)
}

func (c *Call) ackNon2xxLocked(res *sip.Response) *sipnet.Request {
	to := c.remoteURI
	if t := toTag(res); t != "" {
		to += ";tag=" + t
	}
	out, seq := c.out, c.inviteSeq
	r := sipnet.NewRequest("ACK", out.URI).
		Add("Via", out.Get("Via")).
		Add("Max-Forwards", "70")
	for _, rt := range initialRoutes(out) {
		r.Add("Route", rt)
	}
	return r.Add("From", c.localURI+";tag="+c.localTag).
		Add("To", to).
		Add("Call-ID", c.callID).
		Add("CSeq", itoa(seq)+" ACK")
}

func initialRoutes(invite *sipnet.Request) []string {
	var out []string
	for _, line := range strings.Split(string(invite.Bytes()), "\r\n") {
		if v, ok := strings.CutPrefix(line, "Route: "); ok {
			out = append(out, v)
		}
	}
	return out
}

// cancel abandons our pending INVITE (RFC 3261 §9.1).
func (c *Call) cancel() error {
	conn := c.m.reg.Conn()
	c.mu.Lock()
	out, seq := c.out, c.inviteSeq
	if c.answered {
		c.mu.Unlock()
		return c.bye("local hangup") // the answer came first
	}
	if conn == nil || out == nil {
		c.mu.Unlock()
		return errors.New("nothing to cancel")
	}
	c.cancelled = true
	c.mu.Unlock()
	r := sipnet.NewRequest("CANCEL", out.URI).
		Add("Via", out.Get("Via")).
		Add("Max-Forwards", "70")
	for _, rt := range initialRoutes(out) {
		r.Add("Route", rt)
	}
	r.Add("From", c.localURI+";tag="+c.localTag).
		Add("To", c.remoteURI).
		Add("Call-ID", c.callID).
		Add("CSeq", itoa(seq)+" CANCEL")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := conn.Do(ctx, r, nil)
	return err
}
