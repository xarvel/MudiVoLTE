package call

import (
	"log/slog"
	"strings"
	"sync"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/reg"
	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// Registrar is what calls need from the registration (reg.Client).
type Registrar interface {
	Conn() *sipnet.Conn // protected UE port-c → P-CSCF port-s
	ContactURI() string
	SentBy() string
	IMPU() string
	Binding() (reg.Binding, bool)
}

// Config tunes the call layer.
type Config struct {
	PANI      string // P-Access-Network-Info
	UserAgent string
	Codecs    []string // answer preference; nil → DefaultCodecs
	Log       *slog.Logger
}

const mmtelICSI = `urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel`

// Manager owns all calls of one registration.
type Manager struct {
	reg Registrar
	cfg Config

	// OnIncoming is called (in its own goroutine) for every new inbound call.
	OnIncoming func(*Call)
	// OnState reports every state change; it must not block.
	OnState func(*Call, State)
	// Other receives requests outside calls (MESSAGE, out-of-dialog NOTIFY…).
	// When nil they are refused so the network can retry or fall back.
	Other sipnet.Handler

	mu    sync.Mutex
	calls map[string]*Call
}

func NewManager(r Registrar, cfg Config) *Manager {
	if cfg.Codecs == nil {
		cfg.Codecs = DefaultCodecs
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Manager{reg: r, cfg: cfg, calls: map[string]*Call{}}
}

// Calls returns the live calls.
func (m *Manager) Calls() []*Call {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Call, 0, len(m.calls))
	for _, c := range m.calls {
		out = append(out, c)
	}
	return out
}

func (m *Manager) lookup(callID string) *Call {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[callID]
}

func (m *Manager) remember(c *Call) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.calls[c.callID]; dup {
		return false
	}
	m.calls[c.callID] = c
	return true
}

func (m *Manager) forget(c *Call) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.calls[c.callID] == c {
		delete(m.calls, c.callID)
	}
}

func (m *Manager) notify(c *Call, s State) {
	m.cfg.Log.Info("call state", "call", c.callID, "state", s, "cause", c.cause)
	if m.OnState != nil {
		m.OnState(c, s)
	}
}

func (m *Manager) contact() string {
	return "<" + m.reg.ContactURI() + `>;+g.3gpp.icsi-ref="` + mmtelICSI + `";audio`
}

func (m *Manager) commonHeaders(r *sipnet.Request) {
	if m.cfg.PANI != "" {
		r.Add("P-Access-Network-Info", m.cfg.PANI)
	}
	if m.cfg.UserAgent != "" {
		r.Add("User-Agent", m.cfg.UserAgent)
	}
}

const allow = "INVITE, ACK, CANCEL, BYE, UPDATE, PRACK, MESSAGE, NOTIFY, OPTIONS, INFO"

// Handle is the sipnet.Handler for every request that is not reg-event.
func (m *Manager) Handle(conn *sipnet.Conn, req *sip.Request) {
	callID := ""
	if h := req.CallID(); h != nil {
		callID = h.Value()
	}
	c := m.lookup(callID)
	switch {
	case req.Method == sip.INVITE && c == nil && toTag(req) == "":
		m.incoming(conn, req, callID)
	case c != nil:
		c.handleInDialog(conn, req)
	case req.Method == sip.ACK:
		// ACK for a call we already forgot (e.g. to a non-2xx): nothing to do.
	case toTag(req) != "" && req.Method != sip.MESSAGE:
		_ = conn.Respond(req, 481, "Call/Transaction Does Not Exist")
	case req.Method == sip.OPTIONS:
		_ = conn.Respond(req, 200, "OK", sip.NewHeader("Allow", allow), sip.NewHeader("Accept", "application/sdp"))
	case m.Other != nil:
		m.Other(conn, req)
	case toTag(req) != "":
		_ = conn.Respond(req, 481, "Call/Transaction Does Not Exist")
	default:
		_ = conn.Respond(req, 480, "Temporarily Unavailable")
	}
}

func toTag(m sip.Message) string {
	if to := m.To(); to != nil {
		t, _ := to.Params.Get("tag")
		return t
	}
	return ""
}

func fromTag(m sip.Message) string {
	if f := m.From(); f != nil {
		t, _ := f.Params.Get("tag")
		return t
	}
	return ""
}

func headerValue(m sip.Message, name string) string {
	if hs := m.GetHeaders(name); len(hs) > 0 {
		return hs[0].Value()
	}
	return ""
}

// optionTags lists the tags of Require/Supported (RFC 3261 §20.32).
func optionTags(m sip.Message, name string) []string {
	var out []string
	for _, h := range m.GetHeaders(name) {
		for _, t := range strings.Split(h.Value(), ",") {
			if t = strings.TrimSpace(strings.ToLower(t)); t != "" {
				out = append(out, t)
			}
		}
	}
	return out
}

func hasTag(tags []string, t string) bool {
	for _, x := range tags {
		if x == t {
			return true
		}
	}
	return false
}

// nameAddr strips header parameters (tag) from a From/To value.
func nameAddr(v string) string {
	if i := strings.Index(v, ">"); i >= 0 {
		return v[:i+1]
	}
	v, _, _ = strings.Cut(v, ";")
	return "<" + strings.TrimSpace(v) + ">"
}

// uriOf returns the URI inside a name-addr.
func uriOf(v string) string {
	if i := strings.Index(v, "<"); i >= 0 {
		v = v[i+1:]
		if j := strings.Index(v, ">"); j >= 0 {
			return v[:j]
		}
	}
	v, _, _ = strings.Cut(v, ";")
	return strings.TrimSpace(v)
}
