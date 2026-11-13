package reg

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/auth"
	"github.com/xarvel/MudiVoLTE/volte/sim"
	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

const (
	domain = "ims.mnc001.mcc001.3gppnetwork.org"
	impi   = "001010000000001@" + domain
	impu   = "sip:001010000000001@" + domain
)

// Toy AKA shared by the fake SIM and the fake network.
func akaVectors(r [16]byte) (res, ck, ik []byte) {
	res, ck, ik = make([]byte, 8), make([]byte, 16), make([]byte, 16)
	for i := range r {
		if i < 8 {
			res[i] = r[i] ^ 0x5a
		}
		ck[i], ik[i] = r[i]^0x11, r[i]^0x22
	}
	return
}

type fakeSIM struct {
	mu        sync.Mutex
	syncFails int
	calls     int
}

func (f *fakeSIM) Authenticate(_ context.Context, r, _ [16]byte) (sim.AuthResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.syncFails > 0 {
		f.syncFails--
		return sim.AuthResult{AUTS: []byte("fourteen-bytes")}, nil
	}
	res, ck, ik := akaVectors(r)
	return sim.AuthResult{RES: res, CK: ck, IK: ik}, nil
}

type fakeRunner struct {
	mu   sync.Mutex
	cmds []string
}

func (f *fakeRunner) Run(_ context.Context, args ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cmds = append(f.cmds, strings.Join(args, " "))
	return nil
}

func (f *fakeRunner) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// fakePCSCF plays the network side of TS 24.229 registration on loopback.
// Like the P-CSCF of TS 33.203 §7.1 it keeps the UE client ports of the SAs
// it holds and refuses a REGISTER that offers one of them again.
type fakePCSCF struct {
	t          *testing.T
	plain, prt *sipnet.Listener

	mu          sync.Mutex
	rand        [16]byte       // of the last challenge
	secServer   string         // of the last challenge
	secClient   auth.Mechanism // the offer the last challenge answered
	registers   int            // REGISTER requests on the protected port
	lastExpires string
	lastSrc     netip.AddrPort
	lastConn    *sipnet.Conn
	mirror      func(ipsecPorts)
	digestOK    bool
	verifyOK    bool
	subExpires  string    // granted to SUBSCRIBE; "" = 600000
	subRefuse   int       // status for a SUBSCRIBE inside the dialog; 0 = accept
	subFail     int       // so many first SUBSCRIBEs of a dialog get 503
	subMute     bool      // a first SUBSCRIBE of a dialog gets no answer
	subs        []seenSub // every SUBSCRIBE received

	reauth       bool                             // challenge the REGISTER requests that come over SAs
	movePortC    bool                             // every challenge names another P-CSCF client port
	refuse       int                              // status for a REGISTER over SAs that answers no challenge; 0 = accept
	refuseAnswer int                              // status for the answer to a challenge sent over SAs; 0 = accept
	refusePortS  bool                             // refuse an unprotected REGISTER for the server port of SAs held
	minExpires   int                              // 423 below this many seconds
	grant        string                           // expires of the binding; "" = 3600
	stall        chan struct{}                    // when set, answers to REGISTER wait until it is closed
	other        func(*sipnet.Conn, *sip.Request) // requests that are neither REGISTER nor SUBSCRIBE
	lost         bool                             // the UE's access network is gone: nothing it sends over SAs gets an answer
	afterLoss    []string                         // the methods of what it sent all the same

	challenges int
	held       *challenge      // the SAs in use
	pending    *challenge      // a challenge that waits for its answer
	sas        map[uint16]bool // UE client ports of SAs held or being set up
	regs       []seenReg       // every REGISTER received
}

type seenSub struct {
	callID, toTag, uri string
	cseq               uint32
}

// challenge is a 401 of the fake network and the SAs that come of it.
type challenge struct {
	rand      [16]byte
	secServer string
	client    auth.Mechanism // the UE half: the Security-Client of the challenged REGISTER
	clientRaw string
	protected bool // the challenged REGISTER came over SAs
}

// seenReg is a REGISTER as the fake network saw it.
type seenReg struct {
	plain   bool           // on the unprotected port
	src     uint16         // source port
	client  auth.Mechanism // Security-Client
	verify  string         // Security-Verify
	expires string
	auts    bool // reports a SIM out of sync
	answer  bool // answers a challenge
	status  int  // what it got
}

// ipsecPorts is what the fake network learns from Security-Client.
type ipsecPorts struct {
	portC, portS uint16
	spiC, spiS   uint32
}

func newFakePCSCF(t *testing.T) *fakePCSCF {
	f := &fakePCSCF{t: t, sas: map[uint16]bool{}}
	var err error
	if f.plain, err = sipnet.Listen(netip.MustParseAddrPort("127.0.0.1:0"), f.onPlain, nil); err != nil {
		t.Fatal(err)
	}
	if f.prt, err = sipnet.Listen(netip.MustParseAddrPort("127.0.0.1:0"), f.onProtected, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.plain.Close(); f.prt.Close() })
	return f
}

func header(m sip.Message, name string) string {
	if hs := m.GetHeaders(name); len(hs) > 0 {
		return hs[0].Value()
	}
	return ""
}

// seen returns the REGISTER requests received so far.
func (f *fakePCSCF) seen() []seenReg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]seenReg(nil), f.regs...)
}

func (f *fakePCSCF) set(change func()) {
	f.mu.Lock()
	defer f.mu.Unlock()
	change()
}

// challengeLocked makes the 401 for a REGISTER with the offer client and
// sets the SAs of an earlier, unanswered challenge aside.
func (f *fakePCSCF) challengeLocked(client auth.Mechanism, raw string, protected bool) []sip.Header {
	if f.pending != nil {
		delete(f.sas, f.pending.client.PortC)
	}
	f.challenges++
	ch := &challenge{client: client, clientRaw: raw, protected: protected}
	_, _ = rand.Read(ch.rand[:])
	portC := 9950
	if f.movePortC {
		portC += f.challenges - 1
	}
	ch.secServer = fmt.Sprintf("ipsec-3gpp;alg=hmac-md5-96;prot=esp;mod=trans;ealg=null;spi-c=%d;spi-s=%d;port-c=%d;port-s=%d",
		6999+2*f.challenges, 7000+2*f.challenges, portC, f.prt.Addr().Port())
	f.pending, f.sas[client.PortC] = ch, true
	f.rand, f.secServer, f.secClient = ch.rand, ch.secServer, client
	if f.mirror != nil {
		f.mirror(ipsecPorts{client.PortC, client.PortS, client.SPIc, client.SPIs})
	}
	nonce := base64.StdEncoding.EncodeToString(append(ch.rand[:], make([]byte, 16)...))
	return []sip.Header{
		sip.NewHeader("WWW-Authenticate", `Digest realm="`+domain+`", nonce="`+nonce+`", algorithm=AKAv1-MD5, qop="auth"`),
		sip.NewHeader("Security-Server", ch.secServer),
	}
}

var conflict = sip.NewHeader("Warning", `399 fake.pcscf "AKA IP+Port conflict"`)

func (f *fakePCSCF) onPlain(c *sipnet.Conn, req *sip.Request) {
	if req.Method != sip.REGISTER {
		_ = c.Respond(req, 405, "Method Not Allowed")
		return
	}
	raw := header(req, "Security-Client")
	ms, err := auth.ParseMechanisms(raw)
	if err != nil || len(ms) == 0 {
		f.t.Errorf("bad Security-Client: %v", err)
		return
	}
	seen := seenReg{plain: true, src: c.RemoteAddr().Port(), client: ms[0], expires: header(req, "Expires"),
		auts: strings.Contains(header(req, "Authorization"), "auts=")}
	f.mu.Lock()
	var extra []sip.Header
	switch {
	case f.sas[ms[0].PortC]:
		seen.status, extra = 500, []sip.Header{conflict}
	case f.refusePortS && f.held != nil && f.held.client.PortS == ms[0].PortS:
		seen.status = 500
	default:
		seen.status, extra = 401, f.challengeLocked(ms[0], raw, false)
	}
	f.regs = append(f.regs, seen)
	f.mu.Unlock()
	_ = c.Respond(req, seen.status, map[int]string{401: "Unauthorized", 500: "Server Internal Error"}[seen.status], extra...)
}

func digestParams(h string) map[string]string {
	out := map[string]string{}
	for _, p := range strings.Split(strings.TrimPrefix(h, "Digest "), ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		out[k] = strings.Trim(v, `"`)
	}
	return out
}

func md5hex(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }

// digestOf is the response the REGISTER should carry for the challenge ch.
func digestOf(req *sip.Request, ch *challenge) (got, want string) {
	res, _, _ := akaVectors(ch.rand)
	p := digestParams(header(req, "Authorization"))
	ha1 := md5hex(p["username"] + ":" + p["realm"] + ":" + string(res))
	ha2 := md5hex("REGISTER:" + p["uri"])
	return p["response"], md5hex(ha1 + ":" + p["nonce"] + ":" + p["nc"] + ":" + p["cnonce"] + ":auth:" + ha2)
}

// onRegister handles a REGISTER that came over SAs: the answer to a
// challenge, which sets the SAs of that challenge up, or a request over the
// SAs in use, which is accepted, challenged or refused.
func (f *fakePCSCF) onRegister(c *sipnet.Conn, req *sip.Request) {
	raw := header(req, "Security-Client")
	ms, err := auth.ParseMechanisms(raw)
	if err != nil || len(ms) == 0 {
		f.t.Errorf("bad Security-Client: %v", err)
		return
	}
	seen := seenReg{src: c.RemoteAddr().Port(), client: ms[0], verify: header(req, "Security-Verify"),
		expires: header(req, "Expires"), auts: strings.Contains(header(req, "Authorization"), "auts=")}
	expires, _ := strconv.Atoi(seen.expires)
	f.mu.Lock()
	f.registers++
	f.lastExpires, f.lastSrc, f.lastConn = seen.expires, c.RemoteAddr(), c
	reason, grant, stall := "OK", f.grant, f.stall
	var extra []sip.Header
	p := f.pending
	seen.answer = p != nil && seen.src == p.client.PortC && raw == p.clientRaw && !seen.auts
	switch {
	case seen.answer:
		got, want := digestOf(req, p)
		f.digestOK, f.verifyOK = got == want, seen.verify == p.secServer
		f.pending = nil
		switch {
		case !f.digestOK || !f.verifyOK:
			seen.status, reason = 403, "Forbidden"
		case p.protected && f.refuseAnswer != 0:
			seen.status, reason = f.refuseAnswer, "Refused"
		case expires > 0 && expires < f.minExpires:
			seen.status, reason = 423, "Interval Too Brief"
			extra = []sip.Header{sip.NewHeader("Min-Expires", strconv.Itoa(f.minExpires))}
		default:
			seen.status = 200
		}
		if seen.status != 200 {
			delete(f.sas, p.client.PortC)
			break
		}
		if !p.protected || f.held == nil {
			// SAs of before go when the registration started unprotected.
			f.sas = map[uint16]bool{p.client.PortC: true}
		}
		f.held = p
	case f.held == nil:
		seen.status, reason = 403, "Forbidden"
	default:
		got, want := digestOf(req, f.held)
		f.digestOK, f.verifyOK = got == want || seen.auts, seen.verify == f.held.secServer
		switch {
		case f.sas[ms[0].PortC]:
			seen.status, reason, extra = 500, "Server Internal Error", []sip.Header{conflict}
		case !f.digestOK || !f.verifyOK || seen.src != f.held.client.PortC:
			seen.status, reason = 403, "Forbidden"
		case f.refuse != 0:
			seen.status, reason = f.refuse, "Refused"
		case expires > 0 && expires < f.minExpires:
			seen.status, reason = 423, "Interval Too Brief"
			extra = []sip.Header{sip.NewHeader("Min-Expires", strconv.Itoa(f.minExpires))}
		case f.reauth || seen.auts:
			seen.status, reason, extra = 401, "Unauthorized", f.challengeLocked(ms[0], raw, true)
		default:
			seen.status = 200
		}
	}
	f.regs = append(f.regs, seen)
	f.mu.Unlock()
	if stall != nil {
		<-stall
	}
	if seen.status != 200 {
		_ = c.Respond(req, seen.status, reason, extra...)
		return
	}
	if seen.expires == "0" {
		_ = c.Respond(req, 200, "OK", sip.NewHeader("Expires", "0"))
		return
	}
	if grant == "" {
		grant = "3600"
	}
	contact := header(req, "Contact")
	contact = contact[:strings.Index(contact, ">")+1] + ";expires=" + grant
	_ = c.Respond(req, 200, "OK",
		sip.NewHeader("Contact", contact),
		sip.NewHeader("Service-Route", "<sip:orig@scscf.test:6060;lr>"),
		sip.NewHeader("P-Associated-URI", "<"+impu+">, <tel:+447700900001>"))
}

func (f *fakePCSCF) onProtected(c *sipnet.Conn, req *sip.Request) {
	f.mu.Lock()
	lost := f.lost
	if lost {
		f.afterLoss = append(f.afterLoss, string(req.Method))
	}
	f.mu.Unlock()
	if lost {
		return
	}
	switch req.Method {
	case sip.REGISTER:
		f.onRegister(c, req)
	case sip.SUBSCRIBE:
		seen := seenSub{callID: req.CallID().Value(), uri: req.Recipient.String(), cseq: req.CSeq().SeqNo}
		seen.toTag, _ = req.To().Params.Get("tag")
		f.mu.Lock()
		f.subs = append(f.subs, seen)
		expires, refuse := f.subExpires, f.subRefuse
		fail := seen.toTag == "" && f.subFail > 0
		if fail {
			f.subFail--
		}
		mute := seen.toTag == "" && f.subMute
		f.mu.Unlock()
		if mute {
			return
		}
		if fail {
			_ = c.Respond(req, 503, "Service Unavailable")
			return
		}
		if seen.toTag != "" && refuse != 0 {
			_ = c.Respond(req, refuse, "Call/Transaction Does Not Exist")
			return
		}
		if expires == "" {
			expires = "600000"
		}
		res := sip.NewResponseFromRequest(req, 200, "OK", nil)
		if seen.toTag == "" {
			res.To().Params.Add("tag", "net1")
		}
		res.AppendHeader(sip.NewHeader("Expires", expires))
		res.AppendHeader(sip.NewHeader("Contact", "<sip:notifier@127.0.0.1:9900;transport=tcp>"))
		_ = c.Send(res)
	default:
		f.mu.Lock()
		other := f.other
		f.mu.Unlock()
		if other != nil {
			other(c, req)
			return
		}
		_ = c.Respond(req, 405, "Method Not Allowed")
	}
}

func newClient(t *testing.T, f *fakePCSCF, s sim.Authenticator, r *fakeRunner) *Client {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	c, err := New(Config{
		IMPI: impi, IMPU: impu, Domain: domain, IMEI: "350000000000001",
		UEAddr: netip.MustParseAddr("127.0.0.1"), PCSCF: f.plain.Addr(),
		PANI: "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=0010100010000001", UserAgent: "volte-test",
		IPsec: r, Log: log,
	}, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRegisterLifecycle(t *testing.T) {
	f, r := newFakePCSCF(t), &fakeRunner{}
	c := newClient(t, f, &fakeSIM{}, r)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	b, err := c.Register(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if b.Expires != time.Hour || len(b.ServiceRoutes) != 1 || len(b.AssociatedURIs) != 2 {
		t.Fatalf("binding %+v", b)
	}
	if b.Preferred != "tel:+447700900001" || len(b.Routes) != 2 || !strings.HasPrefix(b.Routes[0], "<sip:127.0.0.1:") {
		t.Fatalf("preferred %q routes %v", b.Preferred, b.Routes)
	}
	f.mu.Lock()
	if !f.digestOK || !f.verifyOK {
		t.Errorf("digest ok=%v, Security-Verify ok=%v", f.digestOK, f.verifyOK)
	}
	if f.lastSrc.Port() != f.secClient.PortC {
		t.Errorf("protected REGISTER from port %d, Security-Client port-c %d", f.lastSrc.Port(), f.secClient.PortC)
	}
	f.mu.Unlock()
	if r.count("xfrm state add") != 4 || r.count("xfrm policy add") != 8 {
		t.Fatalf("ipsec commands: %v", r.cmds)
	}
	_, _, ik := akaVectors(f.rand)
	if r.count("xfrm state add") > 0 && !strings.Contains(r.cmds[0], hex.EncodeToString(ik)) {
		t.Errorf("SA not keyed with IK: %s", r.cmds[0])
	}

	if exp, err := c.Subscribe(ctx); err != nil || exp != 600000*time.Second {
		t.Fatalf("subscribe: %v %v", exp, err)
	}

	// The network opens its own connection to our protected server port.
	contact := strings.TrimPrefix(strings.Split(c.ContactURI(), ";")[0], "sip:")
	hp := contact[strings.Index(contact, "@")+1:]
	nc, err := sipnet.Dial(ctx, netip.AddrPort{}, netip.MustParseAddrPort(hp), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	body := `<?xml version="1.0"?><reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="partial">` +
		`<registration aor="` + impu + `" id="r1" state="active"><contact id="c1" state="terminated" event="deactivated">` +
		`<uri>sip:x@` + hp + `;transport=tcp</uri></contact></registration></reginfo>`
	notify := sipnet.NewRequest("NOTIFY", "sip:x@"+hp).
		Add("Via", "SIP/2.0/TCP 127.0.0.1:9950;branch="+sipnet.NewBranch()).
		Add("From", "<"+impu+">;tag=net1").Add("To", "<"+impu+">;tag=ue").
		Add("Call-ID", "n1").Add("CSeq", "1 NOTIFY").Add("Event", "reg").
		Add("Subscription-State", "active;expires=600000").Add("Content-Type", "application/reginfo+xml")
	notify.Body = []byte(body)
	if res, err := nc.Do(ctx, notify, nil); err != nil || res.StatusCode != 200 {
		t.Fatalf("NOTIFY: %v %v", res, err)
	}
	select {
	case reason := <-c.regEvent:
		if reason != "contact deactivated" {
			t.Errorf("reason %q", reason)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no re-registration trigger from NOTIFY")
	}

	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Deregister(ctx); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	if f.registers != 3 || f.lastExpires != "0" {
		t.Errorf("registers=%d last Expires=%q", f.registers, f.lastExpires)
	}
	f.mu.Unlock()
	if r.count("xfrm state delete") != 4 || r.count("xfrm policy delete") != 8 {
		t.Errorf("teardown commands: %d states, %d policies", r.count("xfrm state delete"), r.count("xfrm policy delete"))
	}
	if c.Conn() != nil {
		t.Error("connection kept after de-registration")
	}
}

func TestRegisterResync(t *testing.T) {
	f, r := newFakePCSCF(t), &fakeRunner{}
	s := &fakeSIM{syncFails: 1}
	c := newClient(t, f, s, r)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if s.calls != 2 {
		t.Fatalf("SIM calls %d, want 2", s.calls)
	}
	// The REGISTER with AUTS offers new SPIs and a new client port
	// (TS 24.229 §5.1.1.5.3); the answer repeats that offer.
	regs := f.seen()
	if len(regs) != 3 || !regs[1].plain || !regs[1].auts || regs[1].status != 401 || regs[2].status != 200 || regs[2].src != regs[1].client.PortC {
		t.Fatalf("REGISTER requests: %+v", regs)
	}
	newOffer(t, regs[1], regs[0])
	c.teardown()
}

func TestRefreshDelay(t *testing.T) {
	if refreshDelay(3600*time.Second) != 3000*time.Second || refreshDelay(600*time.Second) != 300*time.Second {
		t.Fatal("refresh delay")
	}
}

func TestIMEIURN(t *testing.T) {
	if got := imeiURN("350000000000001"); got != "urn:gsma:imei:35000000-000000-1" {
		t.Fatal(got)
	}
}

func TestTerminationReason(t *testing.T) {
	body := []byte(`<reginfo xmlns="urn:ietf:params:xml:ns:reginfo"><registration aor="x" state="terminated"><contact state="terminated" event="expired"><uri>sip:u@10.0.0.1:5101</uri></contact></registration></reginfo>`)
	if n, _ := readReginfo(body, "10.0.0.1:5101"); n.ended != "contact expired" {
		t.Fatal(n.ended)
	}
	if n, _ := readReginfo(body, "10.0.0.9:5101"); n.ended != "" {
		t.Fatal(n.ended)
	}
}

// Run must re-register when the network drops the protected connection and
// de-register when stopped.
func TestRunReconnectsAndDeregisters(t *testing.T) {
	f, r := newFakePCSCF(t), &fakeRunner{}
	c := newClient(t, f, &fakeSIM{}, r)
	ctx, cancel := context.WithCancel(context.Background())
	statuses := make(chan Status, 16)
	done := make(chan struct{})
	go func() { c.Run(ctx, func(s Status, _ error) { statuses <- s }); close(done) }()

	wait := func(want Status) {
		t.Helper()
		for {
			select {
			case s := <-statuses:
				if s == want {
					return
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("timeout waiting for %v", want)
			}
		}
	}
	wait(StatusRegistered)
	f.mu.Lock()
	conn := f.lastConn
	f.mu.Unlock()
	conn.Close()
	wait(StatusRegistering)
	wait(StatusRegistered)
	cancel()
	wait(StatusClosed)
	<-done
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.lastExpires != "0" {
		t.Errorf("no de-REGISTER on stop, last Expires=%q", f.lastExpires)
	}
	if adds, dels := r.count("xfrm state add"), r.count("xfrm state delete"); adds != 8 || dels != 8 {
		t.Errorf("SA adds=%d deletes=%d, want 8/8", adds, dels)
	}
}

// A dead first P-CSCF is skipped and the working one is preferred afterwards.
func TestRegisterFallsBackToNextPCSCF(t *testing.T) {
	f, r := newFakePCSCF(t), &fakeRunner{}
	c := newClient(t, f, &fakeSIM{}, r)
	dead := netip.MustParseAddrPort("127.0.0.1:1") // nothing listens on port 1
	c.pcscfs = []netip.AddrPort{dead, f.plain.Addr()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	if got := c.candidates()[0]; got != f.plain.Addr() {
		t.Fatalf("preferred P-CSCF %s", got)
	}
	c.teardown()
}

// The reg-event subscription is refreshed inside its dialog ahead of its
// expiry, and the expiry a NOTIFY names counts. A subscription the network
// has forgotten or let run out is replaced without a new registration; the
// late end of a replaced one changes nothing; one the network rejects means
// the registration is gone.
func TestSubscriptionRefresh(t *testing.T) {
	f, r := newFakePCSCF(t), &fakeRunner{}
	f.subExpires = "2" // refreshed at half time
	c := newClient(t, f, &fakeSIM{}, r)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx, nil); close(done) }()
	defer func() { cancel(); <-done }()

	subs := func(n int) []seenSub {
		t.Helper()
		for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
			f.mu.Lock()
			got := append([]seenSub(nil), f.subs...)
			f.mu.Unlock()
			if len(got) >= n {
				return got
			}
		}
		t.Fatalf("fewer than %d SUBSCRIBE requests", n)
		return nil
	}
	registers := func() int {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.registers
	}
	set := func(expires string, refuse int) {
		f.mu.Lock()
		f.subExpires, f.subRefuse = expires, refuse
		f.mu.Unlock()
	}

	s := subs(2)
	if s[0].toTag != "" || s[0].cseq != 1 || s[0].uri != impu {
		t.Errorf("first SUBSCRIBE %+v", s[0])
	}
	if s[1].callID != s[0].callID || s[1].toTag != "net1" || s[1].cseq != 2 || s[1].uri != "sip:notifier@127.0.0.1:9900;transport=tcp" {
		t.Errorf("refresh SUBSCRIBE %+v", s[1])
	}

	// The network has forgotten the dialog: a new subscription.
	set("2", 481)
	s = subs(4)
	if s[2].callID != s[0].callID || s[2].toTag != "net1" || s[3].callID == s[0].callID || s[3].toTag != "" || s[3].cseq != 1 {
		t.Errorf("after 481: %+v then %+v", s[2], s[3])
	}
	set("600000", 0)
	s = subs(5) // the refresh of the new one, now granted for long
	if s[4].callID != s[3].callID || s[4].toTag != "net1" || s[4].cseq != 2 {
		t.Errorf("refresh of the new subscription %+v", s[4])
	}

	contact := strings.TrimPrefix(strings.Split(c.ContactURI(), ";")[0], "sip:")
	hp := contact[strings.Index(contact, "@")+1:]
	nc, err := sipnet.Dial(ctx, netip.AddrPort{}, netip.MustParseAddrPort(hp), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	seq := 0
	notify := func(callID, state string) {
		t.Helper()
		seq++
		req := sipnet.NewRequest("NOTIFY", "sip:x@"+hp).
			Add("Via", "SIP/2.0/TCP 127.0.0.1:9950;branch="+sipnet.NewBranch()).
			Add("From", "<"+impu+">;tag=net1").Add("To", "<"+impu+">;tag=ue").
			Add("Call-ID", callID).Add("CSeq", strconv.Itoa(seq)+" NOTIFY").Add("Event", "reg").
			Add("Subscription-State", state)
		if res, err := nc.Do(ctx, req, nil); err != nil || res.StatusCode != 200 {
			t.Fatalf("NOTIFY: %v %v", res, err)
		}
	}

	// The notifier cuts the expiry down: the refresh follows that.
	start := time.Now()
	notify(s[3].callID, "active;expires=2")
	s = subs(6)
	if d := time.Since(start); s[5].callID != s[3].callID || s[5].cseq != 3 || d < 800*time.Millisecond {
		t.Errorf("refresh after a shorter expiry: %+v after %v", s[5], d)
	}

	before := registers()
	notify(s[0].callID, "terminated;reason=timeout") // the replaced one
	time.Sleep(300 * time.Millisecond)
	if got := subs(6); len(got) != 6 || registers() != before {
		t.Fatalf("the end of the replaced subscription caused %d SUBSCRIBE and %d REGISTER", len(got)-6, registers()-before)
	}
	notify(s[3].callID, "terminated;reason=timeout") // the current one
	s = subs(7)
	if s[6].toTag != "" || s[6].callID == s[3].callID || registers() != before {
		t.Fatalf("after the current subscription ran out: %+v, %d new REGISTER", s[6], registers()-before)
	}
	notify(s[6].callID, "terminated;reason=noresource")
	for deadline := time.Now().Add(5 * time.Second); registers() == before; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("a rejected subscription did not lead to a new registration")
		}
	}
}

// A SUBSCRIBE that fails is repeated after a pause; the registration stays.
func TestSubscriptionRetriesAfterFailure(t *testing.T) {
	pause := subBackoff
	subBackoff = func(int) time.Duration { return 150 * time.Millisecond }
	defer func() { subBackoff = pause }()
	f, r := newFakePCSCF(t), &fakeRunner{}
	f.subFail = 2
	c := newClient(t, f, &fakeSIM{}, r)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	start := time.Now()
	go func() { c.Run(ctx, nil); close(done) }()
	defer func() { cancel(); <-done }()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		f.mu.Lock()
		n, regs := len(f.subs), f.registers
		f.mu.Unlock()
		if n >= 3 {
			if d := time.Since(start); d < 280*time.Millisecond || regs != 1 {
				t.Errorf("third SUBSCRIBE after %v with %d REGISTER; want two pauses and one registration", d, regs)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d SUBSCRIBE requests, want 3", n)
		}
	}
	time.Sleep(400 * time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.subs) != 3 {
		t.Errorf("%d SUBSCRIBE requests after the one that succeeded", len(f.subs)-3)
	}
}

// since returns the ipsec commands issued after the first n.
func (f *fakeRunner) since(n int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cmds[n:]...)
}

func (f *fakeRunner) len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.cmds)
}

func countPrefix(cmds []string, prefix string) int {
	n := 0
	for _, c := range cmds {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

// serverPort is the host:port of our Contact.
func serverPort(c *Client) string {
	contact := strings.TrimPrefix(strings.Split(c.ContactURI(), ";")[0], "sip:")
	return contact[strings.Index(contact, "@")+1:]
}

// network is a connection of the fake network to our protected server port.
func network(t *testing.T, c *Client) *sipnet.Conn {
	t.Helper()
	nc, err := sipnet.Dial(context.Background(), netip.AddrPort{}, netip.MustParseAddrPort(serverPort(c)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	return nc
}

// reach sends a request of the network to the server port over nc and wants
// it answered.
func reach(t *testing.T, nc *sipnet.Conn, c *Client) {
	t.Helper()
	req := sipnet.NewRequest("NOTIFY", "sip:x@"+serverPort(c)).
		Add("Via", "SIP/2.0/TCP 127.0.0.1:9950;branch="+sipnet.NewBranch()).
		Add("From", "<"+impu+">;tag=net1").Add("To", "<"+impu+">;tag=ue").
		Add("Call-ID", "probe").Add("CSeq", "1 NOTIFY").Add("Event", "reg").
		Add("Subscription-State", "active;expires=600000")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if res, err := nc.Do(ctx, req, nil); err != nil || res.StatusCode != 200 {
		t.Fatalf("request of the network to %s: %v %v", serverPort(c), res, err)
	}
}

func registered(t *testing.T) (*fakePCSCF, *fakeRunner, *fakeSIM, *Client, context.Context) {
	t.Helper()
	f, r, s := newFakePCSCF(t), &fakeRunner{}, &fakeSIM{}
	c := newClient(t, f, s, r)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	t.Cleanup(c.teardown)
	if _, err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	return f, r, s, c, ctx
}

func (f *fakeSIM) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// newOffer checks that a REGISTER offers SPIs and a client port unlike those
// of the earlier ones, and the server port they have (TS 33.203 §7.4.0).
func newOffer(t *testing.T, got seenReg, earlier ...seenReg) {
	t.Helper()
	for _, e := range earlier {
		if got.client.PortS != e.client.PortS {
			t.Errorf("port-s %d, was %d", got.client.PortS, e.client.PortS)
		}
		if got.client.PortC == e.client.PortC || got.client.PortC == got.client.PortS {
			t.Errorf("port-c %d is not new (port-s %d)", got.client.PortC, got.client.PortS)
		}
		for _, spi := range []uint32{e.client.SPIc, e.client.SPIs} {
			if got.client.SPIc == spi || got.client.SPIs == spi || got.client.SPIc == got.client.SPIs {
				t.Errorf("SPIs %d/%d are not new", got.client.SPIc, got.client.SPIs)
			}
		}
	}
}

// The network of TS 33.203 §7.1 refuses a REGISTER that offers the client
// port of the SAs in use, the way the SBC of the tested network does.
func TestOfferOfTheSAsInUseIsRefused(t *testing.T) {
	_, _, _, c, ctx := registered(t)
	s := c.current()
	res, err := c.protectedRegister(ctx, s, s.client, c.expires())
	if err != nil {
		t.Fatal(err)
	}
	if got := status(res); got != "500 Server Internal Error (AKA IP+Port conflict)" {
		t.Fatalf("got %q", got)
	}
}

// A re-REGISTER offers new SPIs and a new client port over the SAs in use.
// A network that takes it without a challenge leaves everything as it is.
func TestRefreshOffersNewSAs(t *testing.T) {
	f, r, sim, c, ctx := registered(t)
	conn, contact, cmds := c.Conn(), c.ContactURI(), r.len()
	first := f.seen()[1]
	server := f.secServer

	b, err := c.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	regs := f.seen()
	if len(regs) != 3 {
		t.Fatalf("%d REGISTER requests, want 3: %+v", len(regs), regs)
	}
	re := regs[2]
	if re.plain || re.status != 200 || re.src != first.client.PortC || re.verify != server || re.expires != "600000" {
		t.Errorf("re-REGISTER %+v", re)
	}
	newOffer(t, re, first)
	if b.Expires != time.Hour || c.Conn() != conn || c.ContactURI() != contact {
		t.Errorf("binding %v, connection or contact changed", b.Expires)
	}
	if n := r.len() - cmds; n != 0 || sim.count() != 1 {
		t.Errorf("%d ipsec commands and %d SIM runs for a refresh without a challenge", n, sim.count())
	}

	// Every one of them offers something new.
	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	newOffer(t, f.seen()[3], first, re)

	if err := c.Deregister(ctx); err != nil {
		t.Fatal(err)
	}
	de := f.seen()[4]
	if de.plain || de.status != 200 || de.expires != "0" || de.src != first.client.PortC {
		t.Errorf("de-REGISTER %+v", de)
	}
	newOffer(t, de, first, re, f.seen()[3])
	if r.count("xfrm state add") != 4 || r.count("xfrm state delete") != 4 {
		t.Errorf("SAs: %d added, %d deleted", r.count("xfrm state add"), r.count("xfrm state delete"))
	}
}

// A network that answers the re-REGISTER with a challenge gets new SAs
// beside the old ones: the answer leaves from the new client port, the
// server port and what listens there stay, and the old SAs go when their
// lifetime ends (TS 33.203 §7.4.1a).
func TestRefreshWithChallenge(t *testing.T) {
	f, r, sim, c, ctx := registered(t)
	if _, err := c.Subscribe(ctx); err != nil {
		t.Fatal(err)
	}
	before := network(t, c)
	reach(t, before, c)
	oldConn, contact, cmds, first := c.Conn(), c.ContactURI(), r.len(), f.seen()[1]
	old := c.current()
	f.set(func() { f.reauth = true })

	b, err := c.Refresh(ctx)
	if err != nil {
		t.Fatal(err)
	}
	regs := f.seen()
	if len(regs) != 4 {
		t.Fatalf("%d REGISTER requests, want 4: %+v", len(regs), regs)
	}
	re, answer := regs[2], regs[3]
	if re.plain || re.status != 401 || re.src != first.client.PortC {
		t.Errorf("re-REGISTER %+v", re)
	}
	newOffer(t, re, first)
	if answer.plain || !answer.answer || answer.status != 200 || answer.src != re.client.PortC || answer.verify != f.secServer {
		t.Errorf("answer to the challenge %+v", answer)
	}
	if !f.digestOK || !f.verifyOK || sim.count() != 2 {
		t.Errorf("digest ok=%v, Security-Verify ok=%v, %d SIM runs", f.digestOK, f.verifyOK, sim.count())
	}
	if b.Expires != time.Hour || c.ContactURI() != contact {
		t.Errorf("binding %v, contact %s (was %s)", b.Expires, c.ContactURI(), contact)
	}
	if c.Conn() == oldConn || c.Conn().LocalAddr().Port() != re.client.PortC {
		t.Errorf("requests still leave from the old client port")
	}
	if oldConn.Err() != nil {
		t.Errorf("the old connection is closed before its SAs end: %v", oldConn.Err())
	}

	// The new SAs stand beside the old ones: nothing is deleted, the inbound
	// policy of the server port takes either SA, and the outbound one moved to
	// the new SA once the registration stood.
	got := r.since(cmds)
	if countPrefix(got, "xfrm state add") != 4 || countPrefix(got, "xfrm policy add") != 4 ||
		countPrefix(got, "xfrm state delete")+countPrefix(got, "xfrm policy delete") != 0 {
		t.Errorf("ipsec commands: %q", got)
	}
	portS := strconv.Itoa(int(first.client.PortS))
	var either, moved int
	for _, cmd := range got {
		switch {
		case strings.HasPrefix(cmd, "xfrm policy update dir in") && strings.Contains(cmd, "dport "+portS+" tmpl") && !strings.Contains(cmd, " spi "):
			either++
		case strings.HasPrefix(cmd, "xfrm policy update dir out") && strings.Contains(cmd, "sport "+portS+" dport 9950") && strings.Contains(cmd, "spi 0x00001b5b"):
			moved++ // 7003, the SPI of the new challenge for the P-CSCF client port
		}
	}
	if either != 2 || moved != 2 || countPrefix(got, "xfrm policy update") != 4 {
		t.Errorf("policies of the server port: %d take either SA, %d moved to the new one: %q", either, moved, got)
	}
	if last := got[len(got)-1]; !strings.HasPrefix(last, "xfrm policy update dir out") {
		t.Errorf("the outbound policy moved before the registration stood: %q", got)
	}

	// The subscription lives on, and so does everything at the server port.
	if due, ok := c.subscriptionDue(); !ok || time.Until(due) < time.Hour {
		t.Errorf("subscription due %v %v after the re-authentication", due, ok)
	}
	f.mu.Lock()
	if len(f.subs) != 1 {
		t.Errorf("%d SUBSCRIBE requests, want the one from before", len(f.subs))
	}
	f.mu.Unlock()
	reach(t, before, c)
	reach(t, network(t, c), c)

	// The lifetime of the old SAs ends.
	cmds = r.len()
	c.expire(old)
	got = r.since(cmds)
	if countPrefix(got, "xfrm state delete") != 4 || countPrefix(got, "xfrm policy delete") != 4 || countPrefix(got, "xfrm policy update") != 4 {
		t.Errorf("removing the old SAs: %q", got)
	}
	for _, cmd := range got {
		if strings.HasPrefix(cmd, "xfrm policy update") && !strings.Contains(cmd, " spi ") {
			t.Errorf("a policy still takes any SA: %s", cmd)
		}
		if strings.HasPrefix(cmd, "xfrm policy delete") && strings.Contains(cmd, "port "+portS) {
			t.Errorf("a policy of the server port is deleted: %s", cmd)
		}
	}
	if oldConn.Err() == nil || c.Conn().Err() != nil {
		t.Errorf("connections after the old SAs ended: old %v, new %v", oldConn.Err(), c.Conn().Err())
	}
	reach(t, before, c)

	// The next refresh goes over the new SAs.
	f.set(func() { f.reauth = false })
	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if next := f.seen()[4]; next.status != 200 || next.src != re.client.PortC {
		t.Errorf("refresh after the re-authentication %+v", next)
	}
	newOffer(t, f.seen()[4], first, re)
}

// The old SAs end by themselves when their registration has run out.
func TestReplacedSAsExpire(t *testing.T) {
	grace := saGrace
	saGrace = 200 * time.Millisecond
	defer func() { saGrace = grace }()
	f, r, s := newFakePCSCF(t), &fakeRunner{}, &fakeSIM{}
	f.grant, f.reauth = "1", true
	c := newClient(t, f, s, r)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer c.teardown()
	if _, err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	oldConn := c.Conn()
	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if r.count("xfrm state delete") != 0 {
		t.Fatal("old SAs deleted at once")
	}
	for deadline := time.Now().Add(5 * time.Second); r.count("xfrm state delete") != 4 || oldConn.Err() == nil; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("old SAs still there: %d states deleted, connection %v", r.count("xfrm state delete"), oldConn.Err())
		}
	}
	// A new re-authentication does not wait for the lifetime of the one before.
	conn := c.Conn()
	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	if conn.Err() == nil || r.count("xfrm state add")-r.count("xfrm state delete") != 8 {
		t.Errorf("after two more: connection of the first %v, %d SAs installed", conn.Err(),
			r.count("xfrm state add")-r.count("xfrm state delete"))
	}
}

// When the answer to the challenge is refused the new SAs go, the old ones
// stay in use (TS 24.229 §5.1.1.5.1), and the registration starts anew at
// the same server port.
func TestRefusedReauthentication(t *testing.T) {
	f, r, sim, c, ctx := registered(t)
	before := network(t, c)
	contact, cmds, first := c.ContactURI(), r.len(), f.seen()[1]
	f.set(func() { f.reauth, f.refuseAnswer = true, 403 })

	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	regs := f.seen()
	if len(regs) != 6 {
		t.Fatalf("%d REGISTER requests, want 6: %+v", len(regs), regs)
	}
	if regs[2].status != 401 || regs[3].status != 403 || !regs[3].answer {
		t.Errorf("re-authentication: %+v then %+v", regs[2], regs[3])
	}
	if !regs[4].plain || regs[4].status != 401 || regs[5].plain || regs[5].status != 200 || regs[5].src != regs[4].client.PortC {
		t.Errorf("registration after it: %+v then %+v", regs[4], regs[5])
	}
	newOffer(t, regs[4], first, regs[2])
	if c.ContactURI() != contact || sim.count() != 3 {
		t.Errorf("contact %s (was %s), %d SIM runs", c.ContactURI(), contact, sim.count())
	}
	got := r.since(cmds)
	if countPrefix(got, "xfrm state add") != 8 || countPrefix(got, "xfrm state delete") != 8 {
		t.Errorf("SAs: %d added, %d deleted: %q", countPrefix(got, "xfrm state add"), countPrefix(got, "xfrm state delete"), got)
	}
	// The SAs of the refused answer (ten commands to install) went first,
	// with the policies of the server port handed back to the SAs in use.
	var back int
	for _, cmd := range got[10:22] {
		if strings.HasPrefix(cmd, "xfrm policy update") && strings.Contains(cmd, " spi ") {
			back++
		}
	}
	if !strings.HasPrefix(got[21], "xfrm state delete") || countPrefix(got[:21], "xfrm state delete") != 3 || back != 4 {
		t.Errorf("removing the SAs of the refused answer: %q", got[10:22])
	}
	reach(t, before, c)
}

// A network that refuses the re-REGISTER gets a full registration, as
// TS 24.229 §5.1.1.4.1 asks. It keeps the server port and what listens
// there, and the SAs in use serve until the new ones stand.
func TestRefusedRefreshKeepsTheServerPort(t *testing.T) {
	f, r, _, c, ctx := registered(t)
	before := network(t, c)
	oldConn, contact, cmds, first := c.Conn(), c.ContactURI(), r.len(), f.seen()[1]
	f.set(func() { f.refuse = 500 })

	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	regs := f.seen()
	if len(regs) != 5 || regs[2].status != 500 || !regs[3].plain || regs[3].status != 401 || regs[4].status != 200 {
		t.Fatalf("REGISTER requests: %+v", regs)
	}
	newOffer(t, regs[3], first, regs[2])
	if c.ContactURI() != contact || c.Conn() == oldConn || oldConn.Err() == nil {
		t.Errorf("contact %s (was %s), old connection %v", c.ContactURI(), contact, oldConn.Err())
	}
	got := r.since(cmds)
	if countPrefix(got, "xfrm state add") != 4 || countPrefix(got, "xfrm state delete") != 4 {
		t.Fatalf("ipsec commands: %q", got)
	}
	for i, cmd := range got {
		if strings.HasPrefix(cmd, "xfrm state delete") && i < 12 {
			t.Errorf("an SA in use is deleted before the new ones stand: %q", got)
			break
		}
	}
	portS := strconv.Itoa(int(first.client.PortS))
	for _, cmd := range got {
		if strings.HasPrefix(cmd, "xfrm policy delete") && strings.Contains(cmd, "port "+portS) {
			t.Errorf("a policy of the server port is deleted: %s", cmd)
		}
	}
	// What the network had open to the server port is still served.
	reach(t, before, c)
	if before.Err() != nil {
		t.Errorf("the connection of the network is closed: %v", before.Err())
	}
}

// When the registration at the same server port is refused as well, the
// client starts from scratch with new ports.
func TestRegistrationFromScratch(t *testing.T) {
	f, r, _, c, ctx := registered(t)
	before := network(t, c)
	contact := c.ContactURI()
	f.set(func() { f.refuse, f.refusePortS = 500, true })

	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	regs := f.seen()
	if len(regs) != 6 || regs[2].status != 500 || !regs[3].plain || regs[3].status != 500 || !regs[4].plain || regs[4].status != 401 || regs[5].status != 200 {
		t.Fatalf("REGISTER requests: %+v", regs)
	}
	if regs[3].client.PortS != regs[1].client.PortS || regs[4].client.PortS == regs[1].client.PortS {
		t.Errorf("server ports: %d, then %d, then %d", regs[1].client.PortS, regs[3].client.PortS, regs[4].client.PortS)
	}
	if c.ContactURI() == contact {
		t.Errorf("contact did not change")
	}
	select {
	case <-before.Done():
	case <-time.After(2 * time.Second):
		t.Error("the old server port still listens")
	}
	if n := r.count("xfrm state add") - r.count("xfrm state delete"); n != 4 {
		t.Errorf("%d SAs installed", n)
	}
	reach(t, network(t, c), c)
}

// A challenge to the de-REGISTER is answered like any other; then all SAs go.
func TestDeregisterWithChallenge(t *testing.T) {
	f, r, sim, c, ctx := registered(t)
	f.set(func() { f.reauth = true })
	if err := c.Deregister(ctx); err != nil {
		t.Fatal(err)
	}
	regs := f.seen()
	if len(regs) != 4 || regs[2].status != 401 || regs[2].expires != "0" || !regs[3].answer || regs[3].status != 200 || regs[3].expires != "0" {
		t.Fatalf("REGISTER requests: %+v", regs)
	}
	newOffer(t, regs[2], regs[1])
	if sim.count() != 2 || c.Conn() != nil || r.count("xfrm state add") != 8 || r.count("xfrm state delete") != 8 {
		t.Errorf("%d SIM runs, connection %v, SAs %d added %d deleted", sim.count(), c.Conn(),
			r.count("xfrm state add"), r.count("xfrm state delete"))
	}
}

// A SIM out of sync on a re-authentication reports it over the SAs in use,
// with one more new offer, and makes no SAs for the challenge it could not
// take (TS 24.229 §5.1.1.5.3).
func TestReauthenticationResync(t *testing.T) {
	f, r, sim, c, ctx := registered(t)
	cmds, first := r.len(), f.seen()[1]
	f.set(func() { f.reauth = true })
	sim.mu.Lock()
	sim.syncFails = 1
	sim.mu.Unlock()

	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	regs := f.seen()
	if len(regs) != 5 {
		t.Fatalf("%d REGISTER requests, want 5: %+v", len(regs), regs)
	}
	re, auts, answer := regs[2], regs[3], regs[4]
	if re.status != 401 || !auts.auts || auts.status != 401 || auts.src != first.client.PortC || auts.verify != re.verify {
		t.Errorf("re-REGISTER %+v, then with AUTS %+v", re, auts)
	}
	newOffer(t, auts, first, re)
	if !answer.answer || answer.status != 200 || answer.src != auts.client.PortC {
		t.Errorf("answer %+v", answer)
	}
	if got := r.since(cmds); countPrefix(got, "xfrm state add") != 4 || sim.count() != 3 {
		t.Errorf("%d SAs added, %d SIM runs", countPrefix(got, "xfrm state add"), sim.count())
	}
}

// A registrar that finds the interval too brief names its minimum, and the
// next REGISTER asks for it (RFC 3261 §10.3).
func TestIntervalTooBrief(t *testing.T) {
	f, r := newFakePCSCF(t), &fakeRunner{}
	f.minExpires = 200
	c := newClient(t, f, &fakeSIM{}, r)
	c.cfg.Expires = 100 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	defer c.teardown()
	if _, err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	regs := f.seen()
	if len(regs) != 4 || regs[1].status != 423 || regs[1].expires != "100" || !regs[2].plain || regs[3].status != 200 || regs[3].expires != "200" {
		t.Fatalf("REGISTER requests: %+v", regs)
	}
	newOffer(t, regs[2], regs[0])
	if n := r.count("xfrm state add") - r.count("xfrm state delete"); n != 4 {
		t.Errorf("%d SAs installed", n)
	}
	f.set(func() { f.minExpires = 300 })
	if _, err := c.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	regs = f.seen()
	if len(regs) != 6 || regs[4].status != 423 || regs[5].status != 200 || regs[5].expires != "300" || regs[5].plain {
		t.Fatalf("REGISTER requests of the refresh: %+v", regs[4:])
	}
	newOffer(t, regs[5], regs[3], regs[4])
}
