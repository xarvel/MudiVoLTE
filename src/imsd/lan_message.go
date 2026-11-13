package main

// Text messages of the phones (SIP MESSAGE, RFC 3428). Linphone keeps one
// conversation per address: a message from sip:+447700…@<router> shows up as
// a chat with that number, and the reply goes back to the same address. So a
// message from a phone goes
//   - to a number: out as an SMS through smsd (smsbridge.go);
//   - to another phone, by login or short number: straight to it;
//   - to the echo number: back to the sender, a test without the network.
// An incoming SMS comes to the phones the same way, from the sender's number
// (smsbridge.go). Typing notifications and IMDN receipts are accepted and
// dropped: the network has no use for them.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// msgUDPText is the most text one MESSAGE carries over UDP: sipgo refuses
// to send a UDP datagram over 1300 bytes (RFC 3261 §18.1.1). Long Contacts
// with push parameters reduce this further; textPieces measures the headers.
const msgUDPText = 700

// msgTimeout is how long a phone has to answer one MESSAGE.
const msgTimeout = 10 * time.Second

// A message from one phone to another waits for the answer of the addressee
// inside the sender's own transaction (textToPhone).
const (
	// msgRelayWait is how long the addressee has to answer. A phone asleep
	// answers when it next wakes up: after 12 and 16 s in the measurements of
	// §119, at worst after its keep-alive period of about 31 s. The sender
	// gives up at Timer F, 64*T1 = 32 s in belle-sip as in sipgo, and an
	// answer later than that is lost, so the wait ends before it with time for
	// the answer to get there.
	msgRelayWait = 30 * time.Second
	// msgRelayTrying is when a sender still waiting hears 100 Trying: RFC 4320
	// §4.1 asks for it once its Timer E has reached T2 (0.5+1+2 s) and forbids
	// it earlier over UDP. It does not move Timer F. A message to a number
	// holds to it as well (textToNumber).
	msgRelayTrying = 3500 * time.Millisecond
	msgIDPrefix    = "msg-" // the MESSAGEs of one phone-to-phone message: this, then relayID
)

var (
	errNoPhone = errors.New("the phone is not connected")
	// errNoAnswer: the text went out and the phone has said nothing. It may
	// well have the text, and its 200 may still come.
	errNoAnswer = errors.New("the phone has not answered")
)

type msgKind int

const (
	msgText        msgKind = iota // a text for the addressee
	msgIgnore                     // typing notification or receipt: accept, drop
	msgUnsupported                // a file or anything else: 415
)

// messageBody returns the text of a MESSAGE body. Linphone sends text/plain,
// or the same wrapped in message/cpim (RFC 3862) when it asks for receipts.
func messageBody(contentType string, body []byte) (string, msgKind) {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	switch mt {
	case "text/plain":
		return strings.ToValidUTF8(string(body), "�"), msgText
	case "message/cpim":
		ct, inner, ok := splitCPIM(body)
		if !ok {
			return "", msgUnsupported
		}
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "message/cpim") {
			return "", msgUnsupported // no nesting
		}
		return messageBody(ct, inner)
	case "application/im-iscomposing+xml", "message/imdn+xml":
		return "", msgIgnore
	}
	return "", msgUnsupported
}

// splitCPIM returns the content type and the body inside a message/cpim
// wrapper: message headers, an empty line, MIME headers, an empty line, the
// content (Content-Length bytes of it, when given).
func splitCPIM(b []byte) (string, []byte, bool) {
	_, rest, ok := cutBlankLine(b)
	if !ok {
		return "", nil, false
	}
	head, content, ok := cutBlankLine(rest)
	if !ok {
		return "", nil, false
	}
	ct, length := "", -1
	for _, line := range strings.Split(string(head), "\n") {
		k, v, ok := strings.Cut(strings.TrimRight(line, "\r"), ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "content-type":
			ct = strings.TrimSpace(v)
		case "content-length":
			if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
				length = n
			}
		}
	}
	if ct == "" {
		return "", nil, false
	}
	if length >= 0 && length <= len(content) {
		content = content[:length]
	}
	return ct, content, true
}

// cutBlankLine splits b at the first empty line (CRLF CRLF or LF LF).
func cutBlankLine(b []byte) ([]byte, []byte, bool) {
	i, n := bytes.Index(b, []byte("\r\n\r\n")), 4
	if j := bytes.Index(b, []byte("\n\n")); j >= 0 && (i < 0 || j < i) {
		i, n = j, 2
	}
	if i < 0 {
		return nil, nil, false
	}
	return b[:i], b[i+n:], true
}

// --- MESSAGE from a phone ---

func (l *lanSIP) onMessage(req *sip.Request, tx sip.ServerTransaction) {
	user, ok := l.authorize(req, tx, true)
	if !ok {
		return
	}
	ct := ""
	if h := req.ContentType(); h != nil {
		ct = h.Value()
	}
	text, kind := messageBody(ct, req.Body())
	switch {
	case kind == msgIgnore || (kind == msgText && strings.TrimSpace(text) == ""):
		l.respond(req, tx, 200, "OK")
		return
	case kind == msgUnsupported:
		res := sip.NewResponseFromRequest(req, 415, "Unsupported Media Type", nil)
		res.AppendHeader(sip.NewHeader("Accept", "text/plain, message/cpim"))
		_ = tx.Respond(res)
		return
	}
	target := req.Recipient.User
	if l.cfg.EchoExt != "" && target == l.cfg.EchoExt {
		l.respond(req, tx, 200, "OK")
		go func() {
			time.Sleep(300 * time.Millisecond) // the phone files its own message first
			ctx, cancel := context.WithTimeout(context.Background(), 2*msgTimeout)
			defer cancel()
			if _, err := l.sendText(ctx, user, l.cfg.EchoExt, "Echo test", text, ""); err != nil {
				l.logger.Warn("message: echo not delivered", "user", user, "err", err)
			}
		}()
		return
	}
	if peer, ok := l.cfg.phoneFor(target); ok {
		l.textToPhone(req, tx, user, peer, text)
		return
	}
	l.textToNumber(req, tx, user, target, text)
}

// textToPhone passes a message from one phone to another, from the sender's
// login so that the reply finds its way back. The sender hears 200 as soon as
// a device of the addressee has taken the text. A device that stays silent
// may simply be asleep with the text in its socket: a 480 would say "not
// delivered" (RFC 3428 §7) and Linphone would offer to send it again, a copy
// for the addressee. So silence gets 202, accepted without a guarantee of
// delivery, which Linphone shows like 200, and 480 is left for a text that
// cannot have arrived: no device connected, or all of them refused it.
func (l *lanSIP) textToPhone(req *sip.Request, tx sip.ServerTransaction, user, peer, text string) {
	done := make(chan error, 1)
	go func() { done <- l.relayText(peer, user, text, relayID(user, peer, req, text)) }()
	var err error
	select {
	case err = <-done:
	case <-time.After(l.relayTrying):
		_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
		err = <-done
	}
	switch {
	case err == nil:
		l.logger.Info("message: passed to a phone", "from", user, "to", peer)
		l.respond(req, tx, 200, "OK")
	case errors.Is(err, errNoAnswer):
		l.logger.Info("message: a phone has not answered, it may have the text", "from", user, "to", peer)
		l.respond(req, tx, 202, "Accepted")
	default:
		l.logger.Info("message: not delivered to a phone", "from", user, "to", peer, "err", err)
		l.respond(req, tx, 480, "Temporarily Unavailable")
	}
}

// relayID names a message on its way from one phone to another. It comes
// from the Call-ID of the sender's request, so the same request heard twice
// (the sender repeating it to a restarted daemon) is one message for the
// addressee. A text Linphone sends again by itself or at the user's tap has a
// new Call-ID (ChatMessagePrivate::send makes a new SalOp) and a new relayID.
func relayID(user, peer string, req *sip.Request, text string) string {
	callID := ""
	if h := req.CallID(); h != nil {
		callID = h.Value()
	}
	h := sha256.Sum256([]byte(user + "\x00" + peer + "\x00" + callID + "\x00" + text))
	return msgIDPrefix + hex.EncodeToString(h[:10])
}

// textToNumber sends a message to a number as an SMS. The answer waits for
// smsd's verdict for a while: 200 when sent, 500 when smsd gave up, 202 when
// it is still at it (the outcome then reaches the log, and a failure comes
// back to the phone as a message). A sender still waiting hears 100 Trying
// from here and not from the wait: a 1xx after the final answer would become
// what sipgo repeats to a retransmitted request.
func (l *lanSIP) textToNumber(req *sip.Request, tx sip.ServerTransaction, user, target, text string) {
	sender, _ := l.hooks()
	if sender == nil {
		l.respond(req, tx, 403, "SMS Off")
		return
	}
	num, err := normalizeDialed(target, l.cfg.DefaultCountry)
	if err != nil {
		l.respond(req, tx, 484, "Address Incomplete")
		return
	}
	if !dialAllowed(l.cfg.DialAllow, num) {
		l.logger.Warn("SMS: destination not allowed", "user", user, "to", maskNumber(num))
		l.respond(req, tx, 403, "Destination Not Allowed")
		return
	}
	if parts := smsParts(text); parts > maxSMSParts {
		l.logger.Warn("SMS: too long", "user", user, "parts", parts)
		l.respond(req, tx, 513, "Message Too Large")
		return
	}
	var code int
	var reason string
	done := make(chan struct{})
	go func() {
		code, reason = sender.send(user, num, text)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(l.relayTrying):
		_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))
		<-done
	}
	l.respond(req, tx, code, reason)
}

// --- MESSAGE to a phone ---

// sendText sends text to every live device of user as a MESSAGE from sender
// (a number, a login or the echo number); display is the name the phone
// shows. ok when at least one device took it. id names the text across
// attempts, "" for a one-off: see textRequest.
func (l *lanSIP) sendText(ctx context.Context, user, sender, display, text, id string) (bool, error) {
	bs := l.reg.forUser(user)
	if len(bs) == 0 {
		return false, errNoPhone
	}
	errs := make(chan error, len(bs))
	for _, b := range bs {
		go func(b binding) { errs <- l.sendTextTo(ctx, b, sender, display, text, id) }(b)
	}
	ok := false
	var last error
	for range bs {
		if err := <-errs; err == nil {
			ok = true
		} else {
			last = err
		}
	}
	return ok, last
}

// sendTextTo sends text to one device, in pieces over UDP, stopping at the
// first piece not taken: the attempts at an SMS start over later, under the
// same id.
func (l *lanSIP) sendTextTo(ctx context.Context, b binding, sender, display, text, id string) error {
	pieces, err := l.textPieces(b, sender, display, text, id)
	if err != nil {
		return err
	}
	if !l.reachable(b) {
		return errors.New("no connection to the phone")
	}
	for i, p := range pieces {
		c, cancel := context.WithTimeout(ctx, msgTimeout)
		res, err := l.cli.Do(c, l.textRequest(b, sender, display, p, id, i, len(pieces)))
		cancel()
		if err != nil {
			return err
		}
		if res.StatusCode < 200 || res.StatusCode > 299 {
			return fmt.Errorf("%d %s", res.StatusCode, res.Reason)
		}
	}
	return nil
}

// relayText sends a message of a phone to every live device of user, and
// returns as soon as one of them has it: the other devices keep their time
// in the background, the sender does not wait for them. errNoAnswer when no
// device took it and at least one may have it; any other error when the text
// cannot have arrived.
func (l *lanSIP) relayText(user, sender, text, id string) error {
	bs := l.reg.forUser(user)
	if len(bs) == 0 {
		return errNoPhone
	}
	ctx, cancel := context.WithTimeout(context.Background(), l.relayWait)
	errs := make(chan error, len(bs))
	for _, b := range bs {
		go func(b binding) { errs <- l.relayTextTo(ctx, b, sender, text, id) }(b)
	}
	var last error
	for left := len(bs); left > 0; left-- {
		err := <-errs
		if err == nil {
			go func(n int) {
				for ; n > 0; n-- {
					<-errs
				}
				cancel()
			}(left - 1)
			return nil
		}
		if last == nil || errors.Is(err, errNoAnswer) {
			last = err
		}
	}
	cancel()
	return last
}

// relayTextTo sends a phone's text to one device. The pieces of a long text
// over UDP share the wait evenly, and a piece without an answer does not hold
// back the next: a phone asleep finds them all in its socket when it wakes
// up. A refusal ends the text there.
func (l *lanSIP) relayTextTo(ctx context.Context, b binding, sender, text, id string) error {
	if !l.reachable(b) {
		return errNoPhone
	}
	pieces, err := l.textPieces(b, sender, sender, text, id)
	if err != nil {
		return err
	}
	wait := l.relayWait / time.Duration(len(pieces))
	silent := false
	for i, p := range pieces {
		c, cancel := context.WithTimeout(ctx, wait)
		res, err := l.cli.Do(c, l.textRequest(b, sender, sender, p, id, i, len(pieces)))
		cancel()
		switch {
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, sip.ErrTransactionTimeout):
			silent = true
		case err != nil:
			return err
		case res.StatusCode < 200 || res.StatusCode > 299:
			return fmt.Errorf("%d %s", res.StatusCode, res.Reason)
		}
	}
	if silent {
		return errNoAnswer
	}
	return nil
}

// textPieces cuts a text for one device: over UDP it goes in pieces.
func (l *lanSIP) textPieces(b binding, sender, display, text, id string) ([]string, error) {
	if b.transport == "udp" {
		// Include every generated header and the longest possible piece index.
		// Reserve space for the transport's Via port and Content-Length digits.
		probe := l.textRequest(b, sender, display, "", id, len(text), 2)
		if err := sipgo.ClientRequestBuild(l.cli, probe); err != nil {
			return nil, err
		}
		budget := min(msgUDPText, sip.UDPMTUSize-200-len(probe.String())-32)
		if budget < utf8.UTFMax {
			return nil, errors.New("MESSAGE headers leave no room for text over UDP")
		}
		return splitText(text, budget), nil
	}
	return []string{text}, nil
}

// textRequest builds the MESSAGE with piece i of the n pieces of a text. With
// an id, every attempt at the same text carries the same Call-ID: Linphone
// files a MESSAGE under its Call-ID, answers 200 to one it already has and
// does not show it again, and a phone that did not answer in time may have
// the text after all (§119).
func (l *lanSIP) textRequest(b binding, sender, display, piece, id string, i, n int) *sip.Request {
	req := sip.NewRequest(sip.MESSAGE, b.contact)
	req.SetDestination(b.source)
	req.SetTransport(strings.ToUpper(b.transport))
	from := &sip.FromHeader{DisplayName: quotedName(display), Address: sip.Uri{Scheme: "sip", User: sipUser(sender), Host: l.ip.String()}, Params: sip.NewParams()}
	from.Params.Add("tag", sip.GenerateTagN(16))
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: b.user, Host: l.ip.String()}, Params: sip.NewParams()})
	req.AppendHeader(sip.NewHeader("Content-Type", "text/plain;charset=UTF-8"))
	if id != "" {
		callID := sip.CallIDHeader(id + "@" + l.ip.String())
		if n > 1 { // each piece is a message of its own
			callID = sip.CallIDHeader(fmt.Sprintf("%s.%d@%s", id, i, l.ip))
		}
		req.AppendHeader(&callID)
	}
	req.SetBody([]byte(piece))
	return req
}

// lateResponse takes an answer no transaction waits for any more. A phone
// asleep takes a MESSAGE off its socket when it next wakes up, and its 200
// comes after the daemon has stopped waiting; it still means the phone has
// the text (§119).
func (l *lanSIP) lateResponse(res *sip.Response) {
	cseq, to, id := res.CSeq(), res.To(), res.CallID()
	if !res.IsSuccess() || cseq == nil || to == nil || id == nil || cseq.MethodName != sip.MESSAGE {
		return
	}
	callID := strings.TrimSuffix(id.Value(), "@"+l.ip.String())
	if strings.HasPrefix(callID, msgIDPrefix) {
		l.logger.Info("message: passed to a phone, its answer came late", "to", to.Address.User)
		return
	}
	if sender, _ := l.hooks(); sender != nil {
		sender.lateAnswer(callID, to.Address.User)
	}
}

// splitText cuts text into pieces of at most max bytes, on a space or line
// break when there is one in the second half of the piece, never inside a
// character.
func splitText(text string, max int) []string {
	var out []string
	for len(text) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		if i := strings.LastIndexAny(text[:cut], " \n"); i >= max/2 {
			cut = i + 1
		}
		out = append(out, text[:cut])
		text = text[cut:]
	}
	return append(out, text)
}

// sipUser makes the user part of a SIP URI out of a sender: a number stays
// as it is, anything else in an alphanumeric sender ("My Bank") is
// %-escaped (RFC 3261 §25.1).
func sipUser(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("+-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// quotedName returns a display name safe inside quotes.
func quotedName(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < ' ' {
			return -1
		}
		return r
	}, s)
}
