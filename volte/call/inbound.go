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

// Option tags we can honour when the peer requires them.
var supportedRequire = []string{"100rel", "timer"}

// incoming takes a new INVITE. sipnet refuses requests without the header
// fields every request carries; callID still comes from Handle, which never
// dereferences a missing one.
func (m *Manager) incoming(conn *sipnet.Conn, req *sip.Request, callID string) {
	if callID == "" {
		_ = conn.Respond(req, 400, "Missing Call-ID header field")
		return
	}
	var unsupported []string
	for _, t := range optionTags(req, "Require") {
		if !hasTag(supportedRequire, t) {
			unsupported = append(unsupported, t)
		}
	}
	if len(unsupported) > 0 {
		_ = conn.Respond(req, 420, "Bad Extension", sip.NewHeader("Unsupported", strings.Join(unsupported, ", ")))
		return
	}

	c := newCall(m, Inbound)
	c.callID = callID
	c.remoteTag = fromTag(req)
	c.localTag = sipnet.Token(6)
	c.localURI = nameAddr(headerValue(req, "To"))
	c.remoteURI = nameAddr(headerValue(req, "From"))
	c.remoteID = headerValue(req, "P-Asserted-Identity")
	if c.remoteID == "" {
		c.remoteID = c.remoteURI
	}
	c.target = uriOf(headerValue(req, "Contact"))
	c.routes = sipnet.ListValues(req, "Record-Route") // UAS keeps the order (RFC 3261 §12.1.1)
	c.invite, c.inviteConn = req, conn
	c.reliable = hasTag(optionTags(req, "Require"), "100rel")
	c.state = StateIncoming
	if cs := req.CSeq(); cs != nil {
		c.remoteInviteSeq = cs.SeqNo
	}

	if body := req.Body(); len(body) > 0 {
		offer, err := ParseSDP(body)
		if err == nil {
			c.neg, err = Negotiate(offer, m.cfg.Codecs)
		}
		if err != nil {
			_ = conn.Respond(req, 488, "Not Acceptable Here", sip.NewHeader("Warning", `399 - "`+err.Error()+`"`))
			return
		}
		c.offerDir = offer.Direction
	} else {
		c.offerless = true
	}
	var ok bool
	if c.se.interval, c.se.local, ok = c.sessionFor(req); !ok {
		tooSmall(conn, req)
		return
	}
	if !m.remember(c) {
		return
	}
	_ = conn.Respond(req, 100, "Trying")
	m.notify(c, StateIncoming)
	if m.OnIncoming != nil {
		go m.OnIncoming(c)
	} else {
		go c.Reject(480, "Temporarily Unavailable")
	}
}

// response builds a response to the initial INVITE.
func (c *Call) response(code int, reason string, sdp []byte, extra ...sip.Header) *sip.Response {
	res := sip.NewResponseFromRequest(c.invite, code, reason, nil)
	if code > 100 {
		if to := res.To(); to != nil {
			to.Params.Add("tag", c.localTag)
		}
	}
	if code > 100 && code < 300 {
		res.AppendHeader(sip.NewHeader("Contact", c.m.contact()))
		res.AppendHeader(sip.NewHeader("Allow", allow))
		res.AppendHeader(sip.NewHeader("Supported", "100rel, timer"))
	}
	if c.m.cfg.PANI != "" {
		res.AppendHeader(sip.NewHeader("P-Access-Network-Info", c.m.cfg.PANI))
	}
	for _, h := range extra {
		res.AppendHeader(h)
	}
	if sdp != nil {
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.SetBody(sdp)
	} else {
		res.SetBody(nil)
	}
	return res
}

// Ring sends 180 Ringing; reliably (RFC 3262) when the caller requires 100rel.
func (c *Call) Ring() error {
	c.mu.Lock()
	if c.state != StateIncoming {
		c.mu.Unlock()
		return fmt.Errorf("call is %s", c.state)
	}
	var extra []sip.Header
	reliable := c.reliable
	rseq := uint32(0)
	if reliable {
		c.rseq++
		rseq = c.rseq
		extra = append(extra, sip.NewHeader("Require", "100rel"), sip.NewHeader("RSeq", itoa(rseq)))
	}
	res := c.response(180, "Ringing", nil, extra...)
	c.mu.Unlock()
	if err := c.inviteConn.Send(res); err != nil {
		return err
	}
	if reliable {
		go c.retransmitUntil(res, func() bool {
			select {
			case got := <-c.pracked:
				return got == rseq
			default:
				return false
			}
		}, nil)
	}
	return nil
}

// Answer accepts the call with media at local (our RTP address).
func (c *Call) Answer(local netip.AddrPort) error {
	c.mu.Lock()
	if c.state != StateIncoming {
		c.mu.Unlock()
		return fmt.Errorf("call is %s", c.state)
	}
	c.local = local
	var sdp []byte
	if c.offerless {
		sdp = SessionDescription{ID: c.sdpID, Version: c.sdpVer, Local: local, Formats: OfferFormats(c.m.cfg.Codecs)}.Bytes()
	} else {
		sdp = c.neg.Answer(local, c.sdpID, c.sdpVer, c.offerDir).Bytes()
		c.hasMedia = true
	}
	interval, refresh := c.se.interval, c.se.local
	res := c.response(200, "OK", sdp, sessionHeaders(interval, refresh, c.se.peer)...)
	c.mu.Unlock()
	if err := c.inviteConn.Send(res); err != nil {
		c.setState(StateEnded, "sending 200: "+err.Error())
		return err
	}
	c.setState(StateAnswered, "")
	c.armSession(interval, refresh)
	if interval > 0 {
		c.m.cfg.Log.Info("session timer", "call", c.callID, "interval", interval, "refresher", refresherName(refresh))
	}
	// 2xx is retransmitted end to end until ACK (RFC 3261 §13.3.1.4).
	go c.retransmitUntil(res, func() bool {
		select {
		case <-c.acked:
			return true
		default:
			return false
		}
	}, func() {
		c.m.cfg.Log.Warn("no ACK for 200, hanging up", "call", c.callID)
		c.bye("no ACK")
	})
	return nil
}

// retransmitUntil resends res with T1 doubling up to T2 until stop reports
// true, the call ends, or 64·T1 passes (then onTimeout runs).
func (c *Call) retransmitUntil(res *sip.Response, stop func() bool, onTimeout func()) {
	interval, deadline := T1, time.Now().Add(64*T1)
	for {
		select {
		case <-c.done:
			return
		case <-time.After(interval):
		}
		if stop() {
			return
		}
		if time.Now().After(deadline) {
			if onTimeout != nil {
				onTimeout()
			}
			return
		}
		_ = c.inviteConn.Send(res)
		interval = min(interval*2, T2)
	}
}

// Reject refuses an unanswered inbound call.
func (c *Call) Reject(code int, reason string) error {
	c.mu.Lock()
	if c.state != StateIncoming {
		c.mu.Unlock()
		return fmt.Errorf("call is %s", c.state)
	}
	res := c.response(code, reason, nil)
	c.mu.Unlock()
	err := c.inviteConn.Send(res)
	c.setState(StateEnded, fmt.Sprintf("rejected %d", code))
	return err
}

// Hangup ends the call in whatever way its state allows.
func (c *Call) Hangup() error {
	st, _ := c.State()
	switch st {
	case StateIncoming:
		return c.Reject(603, "Decline")
	case StateCalling, StateRinging, StateEarly:
		if c.Dir == Outbound {
			return c.cancel()
		}
	case StateAnswered, StateActive:
		return c.bye("local hangup")
	}
	return nil
}

func (c *Call) bye(cause string) error {
	conn := c.m.reg.Conn()
	defer c.setState(StateEnded, cause)
	if conn == nil {
		return errors.New("not registered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := conn.Do(ctx, c.inDialog("BYE"), nil)
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("BYE: %d %s", res.StatusCode, res.Reason)
	}
	return nil
}

// handleInDialog processes requests from the peer within this call.
func (c *Call) handleInDialog(conn *sipnet.Conn, req *sip.Request) {
	switch req.Method {
	case sip.ACK:
		c.onAck(req)
	case sip.CANCEL:
		_ = conn.Respond(req, 200, "OK")
		c.mu.Lock()
		pending := c.state == StateIncoming && c.Dir == Inbound
		var res *sip.Response
		if pending {
			res = c.response(487, "Request Terminated", nil)
		}
		c.mu.Unlock()
		if pending {
			_ = c.inviteConn.Send(res)
			c.setState(StateEnded, "cancelled by caller")
		}
	case sip.BYE:
		_ = conn.Respond(req, 200, "OK")
		cause := "remote bye"
		if r := headerValue(req, "Reason"); r != "" {
			cause += " (" + r + ")"
		}
		c.setState(StateEnded, cause)
	case sip.INVITE:
		if toTag(req) == "" {
			return // retransmitted initial INVITE
		}
		c.onModify(conn, req)
	case sip.UPDATE:
		c.onModify(conn, req)
	case sip.PRACK:
		_ = conn.Respond(req, 200, "OK")
		if f := strings.Fields(headerValue(req, "RAck")); len(f) > 0 {
			if n, err := strconv.ParseUint(f[0], 10, 32); err == nil {
				select {
				case c.pracked <- uint32(n):
				default:
				}
			}
		}
	default:
		_ = conn.Respond(req, 200, "OK")
	}
}

func (c *Call) onAck(req *sip.Request) {
	cs := req.CSeq()
	if c.Dir != Inbound || cs == nil || cs.SeqNo != c.remoteInviteSeq {
		return // ACK for a re-INVITE answer
	}
	c.ackOnce.Do(func() { close(c.acked) })
	c.mu.Lock()
	if c.offerless && len(req.Body()) > 0 {
		if ans, err := ParseSDP(req.Body()); err == nil {
			if n, err := Negotiate(ans, c.m.cfg.Codecs); err == nil {
				c.neg, c.hasMedia = n, true
			}
		}
	}
	answered := c.state == StateAnswered
	c.mu.Unlock()
	if answered {
		c.setState(StateActive, "")
	}
}

// onModify answers a re-INVITE or UPDATE (RFC 3311) without changing our
// address: session refreshes, hold/resume and codec changes from the network.
func (c *Call) onModify(conn *sipnet.Conn, req *sip.Request) {
	c.mu.Lock()
	// Before the call is answered the session timer belongs to the INVITE
	// transaction; an UPDATE of the early dialog does not touch it.
	established := c.state == StateAnswered || c.state == StateActive
	interval, refresh := 0, false
	if established {
		var ok bool
		if interval, refresh, ok = c.sessionFor(req); !ok {
			c.mu.Unlock()
			tooSmall(conn, req)
			return
		}
	}
	if body := req.Body(); len(body) > 0 {
		offer, err := ParseSDP(body)
		var n Negotiated
		if err == nil {
			n, err = Negotiate(offer, c.m.cfg.Codecs)
		}
		if err != nil {
			c.mu.Unlock()
			_ = conn.Respond(req, 488, "Not Acceptable Here")
			return
		}
		if n.Remote != c.neg.Remote || n.Codec.PT != c.neg.Codec.PT || offer.Direction != c.offerDir {
			c.sdpVer++
		}
		c.neg, c.offerDir, c.hasMedia = n, offer.Direction, true
	}
	// A request without an offer gets ours only when it is an INVITE
	// (RFC 3261 §14.2); the 2xx to an UPDATE without SDP carries none
	// (RFC 3311 §5.2).
	var sdp []byte
	if c.local.IsValid() && (len(req.Body()) > 0 || req.Method == sip.INVITE) {
		if c.hasMedia {
			sdp = c.neg.Answer(c.local, c.sdpID, c.sdpVer, c.offerDir).Bytes()
		} else {
			sdp = SessionDescription{ID: c.sdpID, Version: c.sdpVer, Local: c.local, Formats: OfferFormats(c.m.cfg.Codecs)}.Bytes()
		}
	}
	// Both re-INVITE and UPDATE are target refresh requests, and both
	// refresh the session (RFC 4028 §9); without Session-Expires in them the
	// timer is off from here on.
	c.target = targetFrom(req, c.target)
	var timer []sip.Header
	if established {
		timer = sessionHeaders(interval, refresh, c.se.peer)
		switch {
		case interval > 0:
			c.m.cfg.Log.Info("session refreshed by the peer", "call", c.callID, "with", string(req.Method), "interval", interval, "refresher", refresherName(refresh))
		case c.se.interval > 0:
			c.m.cfg.Log.Info("session timer switched off by the peer", "call", c.callID, "with", string(req.Method))
		}
		c.armSessionLocked(interval, refresh)
	}
	c.mu.Unlock()

	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	res.AppendHeader(sip.NewHeader("Contact", c.m.contact()))
	res.AppendHeader(sip.NewHeader("Allow", allow))
	for _, h := range timer {
		res.AppendHeader(h)
	}
	if c.m.cfg.PANI != "" {
		res.AppendHeader(sip.NewHeader("P-Access-Network-Info", c.m.cfg.PANI))
	}
	if sdp != nil {
		res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
		res.SetBody(sdp)
	} else {
		res.SetBody(nil)
	}
	_ = conn.Send(res)
}

// targetFrom updates the remote target from a target-refresh request.
func targetFrom(req *sip.Request, old string) string {
	if v := headerValue(req, "Contact"); v != "" {
		return uriOf(v)
	}
	return old
}
