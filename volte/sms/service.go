package sms

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/reg"
	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// ContentType of SMS over IP bodies (TS 24.341 §7.1).
const ContentType = "application/vnd.3gpp.sms"

// Registrar is what the SMS service needs from the registration.
type Registrar interface {
	Conn() *sipnet.Conn
	SentBy() string
	IMPU() string
	Binding() (reg.Binding, bool)
}

// Config of the SMS service.
type Config struct {
	Domain    string // home domain, for the default SMSC PSI
	SMSC      string // service centre E.164 (+44…); learned from MT messages if empty
	SMSCURI   string // PSI override; default sip:<SMSC>@<Domain>;user=phone
	PANI      string
	UserAgent string
	Log       *slog.Logger
}

// Message is one complete received SMS (concatenated parts joined).
type Message struct {
	From string
	Text string
	Data []byte // 8-bit messages
	Time time.Time
	SMSC string
}

// Service sends and receives SMS over IP.
type Service struct {
	reg Registrar
	cfg Config

	// OnMessage stores a received message. Returning an error (or leaving it
	// nil) makes us answer RP-ERROR "memory capacity exceeded", so the
	// network keeps the message and retries instead of losing it.
	OnMessage func(Message) error
	// Next receives requests that are not SMS (chain to another handler).
	Next sipnet.Handler

	mu      sync.Mutex
	rpMR    byte
	tpMR    byte
	ref     byte
	smsc    string
	pending map[byte]chan RP
	parts   map[string]*partial
}

type partial struct {
	texts   map[int]string
	total   int
	first   *Deliver
	updated time.Time
}

func New(r Registrar, cfg Config) *Service {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Service{reg: r, cfg: cfg, smsc: cfg.SMSC, pending: map[byte]chan RP{}, parts: map[string]*partial{},
		rpMR: byte(time.Now().UnixNano()), ref: byte(time.Now().UnixNano() >> 8)}
}

// Handle is a sipnet.Handler; chain it after the call manager (call.Manager.Other).
func (s *Service) Handle(conn *sipnet.Conn, req *sip.Request) {
	if req.Method != sip.MESSAGE {
		if s.Next != nil {
			s.Next(conn, req)
		} else {
			_ = conn.Respond(req, 405, "Method Not Allowed")
		}
		return
	}
	ct := ""
	if h := req.ContentType(); h != nil {
		ct = h.Value()
	}
	if !strings.EqualFold(strings.TrimSpace(strings.Split(ct, ";")[0]), ContentType) {
		_ = conn.Respond(req, 415, "Unsupported Media Type", sip.NewHeader("Accept", ContentType))
		return
	}
	_ = conn.Respond(req, 200, "OK")
	rp, err := ParseRP(req.Body())
	if err != nil {
		s.cfg.Log.Warn("unparsable RP message", "err", err)
		return
	}
	switch rp.MTI {
	case RPDataNToMS:
		go s.deliver(req, rp)
	case RPAckNToMS, RPErrorNToMS:
		s.mu.Lock()
		ch := s.pending[rp.MR]
		s.mu.Unlock()
		if ch != nil {
			select {
			case ch <- rp:
			default:
			}
		}
	}
}

func (s *Service) deliver(req *sip.Request, rp RP) {
	reply := RP{MTI: RPAckMSToN, MR: rp.MR}
	if rp.OA != nil {
		s.mu.Lock()
		if s.smsc == "" {
			s.smsc = rp.OA.Number
		}
		s.mu.Unlock()
	}
	if d, err := ParseDeliver(rp.TPDU); err != nil {
		s.cfg.Log.Warn("bad SMS-DELIVER", "err", err)
		reply = RP{MTI: RPErrorMSToN, MR: rp.MR, Cause: CauseInvalidMessage}
	} else if err := s.store(d, rp.OA); err != nil {
		s.cfg.Log.Warn("SMS not stored, asking the network to retry", "err", err)
		reply = RP{MTI: RPErrorMSToN, MR: rp.MR, Cause: CauseMemoryExceeded}
	}
	// The report goes to the SMSC that sent the message (TS 24.341 §5.3.2.4).
	target := uriOfHeader(req, "P-Asserted-Identity")
	if target == "" {
		target = uriOfHeader(req, "From")
	}
	body, _ := reply.Marshal()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	callID := ""
	if h := req.CallID(); h != nil {
		callID = h.Value()
	}
	if _, err := s.message(ctx, target, body, callID); err != nil {
		s.cfg.Log.Warn("sending SMS delivery report", "err", err)
	}
}

// store hands complete messages to OnMessage, collecting concatenated parts.
func (s *Service) store(d *Deliver, oa *Address) error {
	if s.OnMessage == nil {
		return errors.New("no message store")
	}
	smsc := ""
	if oa != nil {
		smsc = oa.Number
	}
	if d.Part == nil || d.Part.Total <= 1 {
		return s.OnMessage(Message{From: d.From.Number, Text: d.Text, Data: d.Data, Time: d.Timestamp, SMSC: smsc})
	}
	key := fmt.Sprintf("%s|%d|%d", d.From.Number, d.Part.Ref, d.Part.Total)
	s.mu.Lock()
	for k, p := range s.parts {
		if time.Since(p.updated) > 24*time.Hour {
			delete(s.parts, k)
		}
	}
	p := s.parts[key]
	if p == nil {
		p = &partial{texts: map[int]string{}, total: d.Part.Total}
		s.parts[key] = p
	}
	p.texts[d.Part.Index] = d.Text
	p.updated = time.Now()
	if d.Part.Index == 1 || p.first == nil {
		p.first = d
	}
	complete := len(p.texts) == p.total
	var text strings.Builder
	if complete {
		for i := 1; i <= p.total; i++ {
			text.WriteString(p.texts[i])
		}
		delete(s.parts, key)
	}
	s.mu.Unlock()
	if !complete {
		return nil
	}
	return s.OnMessage(Message{From: d.From.Number, Text: text.String(), Time: p.first.Timestamp, SMSC: smsc})
}

func (s *Service) smscURI() (string, Address, error) {
	s.mu.Lock()
	smsc := s.smsc
	s.mu.Unlock()
	if smsc == "" {
		return "", Address{}, errors.New("SMSC address unknown: set Config.SMSC")
	}
	uri := s.cfg.SMSCURI
	if uri == "" {
		uri = "sip:" + smsc + "@" + s.cfg.Domain + ";user=phone"
	}
	return uri, ParseNumber(smsc), nil
}

// Send submits text to number (+44… or national), splitting long texts.
// It returns when the SMSC has accepted every part (RP-ACK).
func (s *Service) Send(ctx context.Context, to, text string) error {
	uri, sc, err := s.smscURI()
	if err != nil {
		return err
	}
	s.mu.Lock()
	tpMR, ref := s.tpMR, s.ref
	s.ref++
	s.mu.Unlock()
	tpdus, err := Submit(ParseNumber(to), text, tpMR, ref)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.tpMR += byte(len(tpdus))
	s.mu.Unlock()
	for i, t := range tpdus {
		s.mu.Lock()
		mr := s.rpMR
		s.rpMR++
		ch := make(chan RP, 1)
		s.pending[mr] = ch
		s.mu.Unlock()
		err := s.sendPart(ctx, uri, sc, mr, t, ch)
		s.mu.Lock()
		delete(s.pending, mr)
		s.mu.Unlock()
		if err != nil {
			return fmt.Errorf("part %d/%d: %w", i+1, len(tpdus), err)
		}
	}
	return nil
}

func (s *Service) sendPart(ctx context.Context, uri string, sc Address, mr byte, tpdu []byte, ch chan RP) error {
	body, err := RP{MTI: RPDataMSToN, MR: mr, DA: &sc, TPDU: tpdu}.Marshal()
	if err != nil {
		return err
	}
	res, err := s.message(ctx, uri, body, "")
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		return fmt.Errorf("MESSAGE: %d %s", res.StatusCode, res.Reason)
	}
	select {
	case rp := <-ch:
		if rp.MTI == RPErrorNToMS {
			return fmt.Errorf("SMSC rejected the message: RP-Cause %d", rp.Cause)
		}
		return nil
	case <-ctx.Done():
		return fmt.Errorf("no RP-ACK from SMSC: %w", ctx.Err())
	case <-time.After(60 * time.Second):
		return errors.New("no RP-ACK from SMSC within 60 s")
	}
}

// message sends one MESSAGE carrying an RP body (TS 24.341 §5.3.1.2, §5.3.2.4).
func (s *Service) message(ctx context.Context, target string, body []byte, inReplyTo string) (*sip.Response, error) {
	conn := s.reg.Conn()
	b, ok := s.reg.Binding()
	if conn == nil || !ok {
		return nil, errors.New("not registered")
	}
	impu := s.reg.IMPU()
	if b.Preferred != "" {
		impu = b.Preferred
	}
	r := sipnet.NewRequest("MESSAGE", target).
		Add("Via", "SIP/2.0/TCP "+s.reg.SentBy()+";branch="+sipnet.NewBranch()).
		Add("Max-Forwards", "70")
	for _, rt := range b.Routes {
		r.Add("Route", rt)
	}
	r.Add("From", "<"+impu+">;tag="+sipnet.Token(6)).
		Add("To", "<"+target+">").
		Add("Call-ID", sipnet.Token(12)+"@"+strings.Split(s.reg.SentBy(), ":")[0]).
		Add("CSeq", "1 MESSAGE").
		Add("P-Preferred-Identity", "<"+impu+">").
		Add("Request-Disposition", "no-fork").
		Add("Accept-Contact", "*;+g.3gpp.smsip").
		Add("Content-Type", ContentType)
	if inReplyTo != "" {
		r.Add("In-Reply-To", inReplyTo)
	}
	if s.cfg.PANI != "" {
		r.Add("P-Access-Network-Info", s.cfg.PANI)
	}
	if s.cfg.UserAgent != "" {
		r.Add("User-Agent", s.cfg.UserAgent)
	}
	r.Body = body
	return conn.Do(ctx, r, nil)
}

func uriOfHeader(m sip.Message, name string) string {
	hs := m.GetHeaders(name)
	if len(hs) == 0 {
		return ""
	}
	v := hs[0].Value()
	if i := strings.Index(v, "<"); i >= 0 {
		v = v[i+1:]
		if j := strings.Index(v, ">"); j >= 0 {
			return v[:j]
		}
	}
	v, _, _ = strings.Cut(v, ";")
	return strings.TrimSpace(v)
}
