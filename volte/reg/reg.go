// Package reg keeps the UE registered in IMS (3GPP TS 24.229 §5.1.1):
// initial REGISTER → 401 with IMS-AKA → SIM → sec-agree SAs (TS 33.203 §7)
// → protected REGISTER → 200, then refreshes, the reg-event subscription
// (RFC 3680) and de-registration.
package reg

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/auth"
	"github.com/xarvel/MudiVoLTE/volte/ipsec"
	"github.com/xarvel/MudiVoLTE/volte/sim"
	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// Offer is one ipsec-3gpp algorithm pair we propose in Security-Client.
type Offer struct{ Alg, Ealg string }

// Config describes the subscriber and the access network.
type Config struct {
	IMPI   string // private identity, e.g. 0010100...@ims.mnc001.mcc001.3gppnetwork.org
	IMPU   string // public identity, e.g. sip:0010100...@ims.mnc001.mcc001.3gppnetwork.org
	Domain string // home network domain: Request-URI host and Digest realm
	IMEI   string // 15 digits, for +sip.instance (RFC 7254); optional

	UEAddr netip.Addr     // our address on the IMS PDN
	PCSCF  netip.AddrPort // unprotected P-CSCF address, usually :5060
	// PCSCFFallback is tried in order when PCSCF fails; the last one that
	// worked is tried first next time.
	PCSCFFallback []netip.AddrPort

	// PortC and PortS are the protected UE ports; 0 picks random ones. Every
	// authentication needs a client port of its own (TS 33.203 §7.4.0), so a
	// configured PortC is the first of 64 that are used in turn.
	PortC, PortS uint16
	Expires      time.Duration // requested; 0 → 600000 s (TS 24.229 §5.1.1.2.1)
	UserAgent    string
	PANI         string // P-Access-Network-Info, mandatory for VoLTE access
	Offers       []Offer

	// LooseInboundSrcPort: see ipsec.Set.
	LooseInboundSrcPort bool

	IPsec ipsec.Runner // nil → ipsec.Default(): netlink on Linux, ip elsewhere
	Log   *slog.Logger
}

func (c *Config) defaults() {
	if c.Expires == 0 {
		c.Expires = 600000 * time.Second
	}
	if len(c.Offers) == 0 {
		c.Offers = []Offer{{"hmac-md5-96", "null"}}
	}
	if c.IPsec == nil {
		c.IPsec = ipsec.Default()
	}
	if c.Log == nil {
		c.Log = slog.Default()
	}
}

// Binding is what the network granted.
type Binding struct {
	Expires        time.Duration
	ServiceRoutes  []string // Service-Route from the 200 (§5.1.1.2)
	AssociatedURIs []string // P-Associated-URI: our public identities
	// Routes is the preloaded route set for new dialogs and standalone
	// requests: the P-CSCF at its protected server port, then the service
	// routes (TS 24.229 §5.1.2A.1.1).
	Routes []string
	// Preferred is the identity to assert in P-Preferred-Identity and From:
	// the first associated URI other than the registered IMPU, which is
	// barred when it is the IMSI-derived temporary identity (TS 23.003 §13.4B).
	Preferred string
	At        time.Time
}

// saGrace is how long SAs outlive the registration they belong to
// (TS 24.229 §5.1.1.4.2).
var saGrace = 30 * time.Second

// minBinding is the shortest binding a refresh is planned for: a grant
// below it is refreshed as if it were this long, so a registrar that grants
// next to nothing gets a REGISTER every 30 s, not one per round trip.
const minBinding = time.Minute

// errNoBinding is a 200 to a REGISTER that grants the binding no time: the
// registrar has dropped it (an expires of 0 removes a binding, RFC 3261
// §10.2.2).
var errNoBinding = errors.New("the registrar granted the binding no time")

// session is one set of SAs with the connection from its client port. The
// server port and its listener are the Client's: SA sets come and go, the
// server port stays (TS 33.203 §7.4.0).
type session struct {
	sa        ipsec.Set
	installed bool             // sa is in the kernel
	client    []auth.Mechanism // the Security-Client that offered sa
	server    []auth.Mechanism // network's Security-Server
	chal      *auth.Challenge
	res       []byte
	nc        uint32
	conn      *sipnet.Conn // UE port-c → P-CSCF port-s
	binding   Binding
	sub       *subscription // reg-event dialog; nil before the first SUBSCRIBE
	subFails  int           // failed SUBSCRIBE attempts in a row
	subRetry  time.Time     // when to try again after a failure; zero = no failure pending
	reauthBy  time.Time     // refresh by then: the network shortened the binding (see shorten); zero = no
	reauthGen int           // counts the shortenings, to tell one that crossed a refresh
}

// due is when the binding of s wants refreshing: ahead of its expiry
// (TS 24.229 §5.1.1.4.1), for a grant of minBinding at least, or by the
// time a network-initiated re-authentication asks for, if that is earlier.
func (s *session) due() time.Time {
	due := s.binding.At.Add(refreshDelay(max(s.binding.Expires, minBinding)))
	if !s.reauthBy.IsZero() && s.reauthBy.Before(due) {
		due = s.reauthBy
	}
	return due
}

// Client registers one subscriber.
type Client struct {
	cfg     Config
	sim     sim.Authenticator
	inbound sipnet.Handler

	// proc serialises the registration procedures and the removal of the SAs
	// they replace: the UE is in one procedure at a time (TS 33.203 §7.4.1a).
	proc sync.Mutex

	mu         sync.Mutex
	s          *session         // the SAs in use; nil when not registered
	old        *session         // SAs a re-authentication replaced, kept until their lifetime ends
	oldTimer   *time.Timer      // ends the lifetime of old
	ln         *sipnet.Listener // UE port-s
	portSeq    uint16           // client ports taken from a configured PortC
	minExpires time.Duration    // the registrar's minimum, from a 423
	callID     string
	tag        string
	cseq       uint32

	regEvent    chan string   // reasons from NOTIFY that need re-registration
	rescheduled chan struct{} // a NOTIFY moved when the subscription or the binding is due
	reauthAt    time.Time     // when a shortening last made us refresh (see shorten)
	pcscfs      []netip.AddrPort
}

// New creates a client. inbound receives every request other than reg-event
// NOTIFY (INVITE, MESSAGE, OPTIONS…) arriving on protected connections.
func New(cfg Config, s sim.Authenticator, inbound sipnet.Handler) (*Client, error) {
	cfg.defaults()
	if cfg.IMPI == "" || cfg.IMPU == "" || cfg.Domain == "" {
		return nil, errors.New("IMPI, IMPU and Domain are required")
	}
	if !cfg.UEAddr.IsValid() || !cfg.PCSCF.IsValid() {
		return nil, errors.New("UEAddr and PCSCF are required")
	}
	return &Client{
		cfg: cfg, sim: s, inbound: inbound,
		callID:      sipnet.Token(12) + "@" + cfg.UEAddr.String(),
		tag:         sipnet.Token(6),
		regEvent:    make(chan string, 4),
		rescheduled: make(chan struct{}, 1),
		pcscfs:      append([]netip.AddrPort{cfg.PCSCF}, cfg.PCSCFFallback...),
	}, nil
}

// Conn is the protected client connection for originating requests, or nil.
func (c *Client) Conn() *sipnet.Conn {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.s == nil {
		return nil
	}
	return c.s.conn
}

// Binding returns the current registration, if any.
func (c *Client) Binding() (Binding, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.s == nil {
		return Binding{}, false
	}
	return c.s.binding, true
}

// ContactURI is our protected contact, the target of terminating requests.
func (c *Client) ContactURI() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.s == nil {
		return ""
	}
	return c.contactURI(c.s)
}

// SentBy is the Via sent-by of our requests: UE address and protected server
// port (TS 24.229 §5.1.1.2.1, §5.1.2A.1.1).
func (c *Client) SentBy() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.s == nil {
		return ""
	}
	return netip.AddrPortFrom(c.cfg.UEAddr, c.s.sa.UE.PortS).String()
}

// IMPU is the registered public identity.
func (c *Client) IMPU() string { return c.cfg.IMPU }

func (c *Client) contactURI(s *session) string {
	return "sip:" + userPart(c.cfg.IMPU) + "@" + netip.AddrPortFrom(c.cfg.UEAddr, s.sa.UE.PortS).String() + ";transport=tcp"
}

func userPart(impu string) string {
	u := strings.TrimPrefix(strings.TrimPrefix(impu, "sip:"), "sips:")
	u, _, _ = strings.Cut(u, "@")
	return u
}

func (c *Client) nextCSeq() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cseq++
	return c.cseq
}

func randPort() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return 20000 + binary.BigEndian.Uint16(b[:])%40000
}

// errTooBrief is a 423 that named a longer interval: the next attempt asks
// for it.
var errTooBrief = errors.New("423 Interval Too Brief")

// Register performs a full initial registration. A registration we hold is
// replaced rather than dropped first: the server port and its listener stay,
// so the Contact of running dialogs keeps reaching us (TS 33.203 §7.1,
// NOTE 10), and the SAs we have serve until the new ones stand. Only when
// that fails does the client start from scratch, with new ports.
func (c *Client) Register(ctx context.Context) (Binding, error) {
	c.proc.Lock()
	defer c.proc.Unlock()
	return c.registerAnew(ctx)
}

func (c *Client) registerAnew(ctx context.Context) (Binding, error) {
	c.dropReplaced()
	if cur := c.current(); cur != nil {
		b, err := c.tryPCSCFs(ctx, cur)
		if err == nil || ctx.Err() != nil {
			return b, err
		}
		c.cfg.Log.Warn("registration at the same server port failed, starting from scratch", "err", err)
	}
	c.teardown()
	return c.tryPCSCFs(ctx, nil)
}

func (c *Client) current() *session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.s
}

// tryPCSCFs registers through the first P-CSCF that lets us. With cur, the
// registration we hold, the server port is kept and cur stays in service
// until the new SAs take over.
func (c *Client) tryPCSCFs(ctx context.Context, cur *session) (Binding, error) {
	portS := c.cfg.PortS
	switch {
	case cur != nil:
		portS = cur.sa.UE.PortS
	case portS == 0:
		portS = randPort()
	}
	var errs []error
	for _, pcscf := range c.candidates() {
		for again := false; ; again = true {
			s, err := c.newSession(portS) // fresh SPIs and client port per attempt
			if err != nil {
				return Binding{}, err
			}
			b, err := c.register(ctx, s, pcscf, cur)
			if err == nil {
				c.mu.Lock()
				c.s = s
				c.prefer(pcscf)
				c.mu.Unlock()
				if cur != nil {
					// A registration that started unprotected makes the P-CSCF
					// drop the SAs of before as soon as it stands
					// (TS 33.203 §7.4.2a), so they go here as well.
					c.remove(cur, s)
				}
				return b, nil
			}
			c.remove(s, cur)
			if errors.Is(err, errTooBrief) && !again {
				continue
			}
			errs = append(errs, fmt.Errorf("P-CSCF %s: %w", pcscf, err))
			break
		}
		if ctx.Err() != nil {
			break
		}
	}
	if cur == nil {
		c.closeListener() // nothing protects the server port any more
	}
	return Binding{}, errors.Join(errs...)
}

// newSession prepares our half of sec-agree for the server port portS.
func (c *Client) newSession(portS uint16) (*session, error) {
	s := &session{sa: ipsec.Set{UE: ipsec.Endpoint{Addr: c.cfg.UEAddr, PortS: portS},
		LooseInboundSrcPort: c.cfg.LooseInboundSrcPort}}
	return s, c.offer(s)
}

// offer gives s SPIs and a client port that no SA of ours uses, and the
// Security-Client that announces them. TS 33.203 §7.1 wants the SPIs to
// differ from those of every existing SA and lets the P-CSCF refuse a
// REGISTER whose client port its SA table already holds; the server port
// is not part of the choice.
func (c *Client) offer(s *session) error {
	ue := &s.sa.UE
	c.mu.Lock()
	spis := []uint32{ue.SPIc, ue.SPIs}
	ports := []uint16{0, ue.PortS, ue.PortC}
	for _, x := range []*session{c.s, c.old} {
		if x != nil {
			spis = append(spis, x.sa.UE.SPIc, x.sa.UE.SPIs, x.sa.PCSCF.SPIc, x.sa.PCSCF.SPIs)
			ports = append(ports, x.sa.UE.PortC)
		}
	}
	for taken := true; taken; {
		if c.cfg.PortC == 0 {
			ue.PortC = randPort()
		} else {
			ue.PortC = c.cfg.PortC + c.portSeq%64
			c.portSeq++
		}
		taken = slices.Contains(ports, ue.PortC)
	}
	c.mu.Unlock()
	var err error
	if ue.SPIc, err = ipsec.AllocSPI(spis...); err != nil {
		return err
	}
	if ue.SPIs, err = ipsec.AllocSPI(append(spis, ue.SPIc)...); err != nil {
		return err
	}
	s.client = s.client[:0]
	for _, o := range c.cfg.Offers {
		s.client = append(s.client, auth.Mechanism{Name: auth.MechIPsec3GPP, Alg: o.Alg, Ealg: o.Ealg,
			Prot: "esp", Mode: "trans", SPIc: ue.SPIc, SPIs: ue.SPIs, PortC: ue.PortC, PortS: ue.PortS, Q: -1})
	}
	return nil
}

func (c *Client) candidates() []netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]netip.AddrPort(nil), c.pcscfs...)
}

// prefer moves p to the front of the candidate list; c.mu must be held.
func (c *Client) prefer(p netip.AddrPort) {
	out := []netip.AddrPort{p}
	for _, x := range c.pcscfs {
		if x != p {
			out = append(out, x)
		}
	}
	c.pcscfs = out
}

// expires is the interval we ask for: the configured one, or the minimum a
// registrar insisted on.
func (c *Client) expires() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return max(c.cfg.Expires, c.minExpires)
}

// noteMinExpires takes the registrar's minimum from a 423 (RFC 3261 §10.3)
// and reports whether it asks for more than we did.
func (c *Client) noteMinExpires(res *sip.Response) bool {
	v := headerValues(res, "Min-Expires")
	if len(v) == 0 {
		return false
	}
	sec, err := strconv.Atoi(strings.TrimSpace(v[0]))
	if err != nil || sec <= 0 {
		return false
	}
	floor := time.Duration(sec) * time.Second
	c.mu.Lock()
	defer c.mu.Unlock()
	if floor <= max(c.cfg.Expires, c.minExpires) {
		return false
	}
	c.minExpires = floor
	c.cfg.Log.Info("423 Interval Too Brief, registering with the minimum", "min_expires", sec)
	return true
}

// register runs one initial registration through pcscf. beside is the
// registration it replaces, if any: its SAs stay installed next to the new.
func (c *Client) register(ctx context.Context, s *session, pcscf netip.AddrPort, beside *session) (Binding, error) {
	log := c.cfg.Log
	plain, err := sipnet.Dial(ctx, netip.AddrPortFrom(c.cfg.UEAddr, 0), pcscf, c.handle, log)
	if err != nil {
		return Binding{}, fmt.Errorf("connecting: %w", err)
	}
	defer plain.Close()

	expires := c.expires()
	unprotected := func(authz string) (*sip.Response, error) {
		return plain.Do(ctx, c.registerRequest(s, s.client, nil, authz, expires), nil)
	}
	res, err := unprotected(auth.InitialAuthorization(c.cfg.IMPI, c.cfg.Domain, "sip:"+c.cfg.Domain))
	if err != nil {
		return Binding{}, err
	}
	if res.StatusCode != 401 {
		return Binding{}, fmt.Errorf("initial REGISTER: want 401, got %s", status(res))
	}
	akaRes, res, err := c.runAKA(ctx, s, res, pcscf.Addr(), unprotected)
	if err != nil {
		return Binding{}, err
	}
	if err := c.secure(ctx, s, res, akaRes, pcscf.Addr(), beside); err != nil {
		return Binding{}, err
	}
	res, err = c.protectedRegister(ctx, s, s.client, expires)
	if err != nil {
		return Binding{}, err
	}
	if res.StatusCode == 423 && c.noteMinExpires(res) {
		return Binding{}, errTooBrief
	}
	if res.StatusCode != 200 {
		return Binding{}, fmt.Errorf("protected REGISTER: %s", status(res))
	}
	if s.binding, err = c.parseBinding(s, res, expires); err != nil {
		return Binding{}, fmt.Errorf("protected REGISTER: %w", err)
	}
	log.Info("IMS registered", "expires", s.binding.Expires, "service_routes", len(s.binding.ServiceRoutes))
	return s.binding, nil
}

// runAKA answers the challenge in res with the SIM and returns the 401 that
// the SIM accepted. A SIM out of sync puts AUTS into one more REGISTER,
// which offers new SPIs and a new client port again and gets a new challenge
// (TS 24.229 §5.1.1.5.3); resend sends it.
func (c *Client) runAKA(ctx context.Context, s *session, res *sip.Response, pcscf netip.Addr,
	resend func(authz string) (*sip.Response, error)) (sim.AuthResult, *sip.Response, error) {
	log := c.cfg.Log
	for attempt := 0; ; attempt++ {
		chal, err := digestChallenge(res)
		if err != nil {
			return sim.AuthResult{}, nil, err
		}
		s.chal, s.nc = chal, 0
		rnd, autn, err := chal.RandAutn()
		if err != nil {
			return sim.AuthResult{}, nil, err
		}
		akaRes, err := c.sim.Authenticate(ctx, rnd, autn)
		if errors.Is(err, sim.ErrMAC) {
			// The SIM could not verify AUTN: whoever answered the REGISTER does not
			// hold this subscriber's key. A rogue cell or a man in the middle, not
			// a transient fault, so it is logged on its own and never retried blindly.
			log.Error("AUTN rejected by the SIM: the network is not authentic (rogue cell or interception?)", "pcscf", pcscf)
			return sim.AuthResult{}, nil, fmt.Errorf("SIM AKA: %w", err)
		}
		if err != nil {
			return sim.AuthResult{}, nil, fmt.Errorf("SIM AKA: %w", err)
		}
		if !akaRes.SyncFailure() {
			return akaRes, res, nil
		}
		if attempt >= 1 {
			return sim.AuthResult{}, nil, errors.New("SIM still out of sync after resynchronisation")
		}
		log.Info("AKA sync failure, resynchronising")
		s.nc++
		authz := chal.SyncFailure(c.authRequest(), akaRes.AUTS, s.nc, sipnet.Token(8))
		if err := c.offer(s); err != nil {
			return sim.AuthResult{}, nil, err
		}
		if res, err = resend(authz); err != nil {
			return sim.AuthResult{}, nil, err
		}
		if res.StatusCode != 401 {
			return sim.AuthResult{}, nil, fmt.Errorf("REGISTER with AUTS: want 401, got %s", status(res))
		}
	}
}

// secure makes the SAs that the challenge res and its AKA run define and
// connects over them. beside is the session whose SAs stay in use meanwhile.
func (c *Client) secure(ctx context.Context, s *session, res *sip.Response, akaRes sim.AuthResult, pcscf netip.Addr, beside *session) error {
	var err error
	if s.server, err = securityServer(res); err != nil {
		return err
	}
	chosen, err := auth.Choose(s.server)
	if err != nil {
		return err
	}
	s.res = akaRes.RES
	s.sa.PCSCF = ipsec.Endpoint{Addr: pcscf, SPIc: chosen.SPIc, SPIs: chosen.SPIs, PortC: chosen.PortC, PortS: chosen.PortS}
	s.sa.Alg, s.sa.Ealg, s.sa.IK, s.sa.CK = chosen.Alg, chosen.Ealg, akaRes.IK, akaRes.CK

	if err := c.listen(s.sa.UE.PortS); err != nil {
		return fmt.Errorf("listening on protected server port: %w", err)
	}
	if beside != nil && beside.installed {
		err = s.sa.InstallBeside(ctx, c.cfg.IPsec, beside.sa)
	} else {
		err = s.sa.Install(ctx, c.cfg.IPsec)
	}
	if err != nil {
		return fmt.Errorf("installing SAs: %w", err)
	}
	s.installed = true
	s.conn, err = sipnet.Dial(ctx, netip.AddrPortFrom(c.cfg.UEAddr, s.sa.UE.PortC),
		netip.AddrPortFrom(s.sa.PCSCF.Addr, s.sa.PCSCF.PortS), c.handle, c.cfg.Log)
	if err != nil {
		return fmt.Errorf("protected connection: %w", err)
	}
	return nil
}

// listen opens the protected server port unless it is open already.
func (c *Client) listen(port uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ln != nil {
		return nil
	}
	ln, err := sipnet.Listen(netip.AddrPortFrom(c.cfg.UEAddr, port), c.handle, c.cfg.Log)
	if err != nil {
		return err
	}
	c.ln = ln
	return nil
}

func (c *Client) closeListener() {
	c.mu.Lock()
	ln := c.ln
	c.ln = nil
	c.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
}

// protectedRegister sends REGISTER over the SAs of s with its credentials.
// offer is the Security-Client: the one that made the SAs when the request
// answers their challenge, a new one otherwise.
func (c *Client) protectedRegister(ctx context.Context, s *session, offer []auth.Mechanism, expires time.Duration) (*sip.Response, error) {
	c.mu.Lock()
	s.nc++
	nc := s.nc
	c.mu.Unlock()
	authz, err := s.chal.Answer(c.authRequest(), s.res, nc, sipnet.Token(8))
	if err != nil {
		return nil, err
	}
	return s.conn.Do(ctx, c.registerRequest(s, offer, s.server, authz, expires), nil)
}

func (c *Client) authRequest() auth.Request {
	return auth.Request{Username: c.cfg.IMPI, Method: "REGISTER", URI: "sip:" + c.cfg.Domain}
}

// registerRequest builds a REGISTER for the contact of s. offer goes into
// Security-Client; verify, the Security-Server of the SAs that carry the
// request, into Security-Verify (nil for an unprotected request).
func (c *Client) registerRequest(s *session, offer, verify []auth.Mechanism, authz string, expires time.Duration) *sipnet.Request {
	secs := strconv.Itoa(int(expires / time.Second))
	contact := "<" + c.contactURI(s) + ">;expires=" + secs
	if inst := imeiURN(c.cfg.IMEI); inst != "" {
		contact += `;+sip.instance="<` + inst + `>"`
	}
	contact += `;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip`

	clientMechs := make([]string, len(offer))
	for i, m := range offer {
		clientMechs[i] = m.String()
	}
	r := sipnet.NewRequest("REGISTER", "sip:"+c.cfg.Domain).
		Add("Via", "SIP/2.0/TCP "+netip.AddrPortFrom(c.cfg.UEAddr, s.sa.UE.PortS).String()+";branch="+sipnet.NewBranch()).
		Add("Max-Forwards", "70").
		Add("From", "<"+c.cfg.IMPU+">;tag="+c.tag).
		Add("To", "<"+c.cfg.IMPU+">").
		Add("Call-ID", c.callID).
		Add("CSeq", strconv.FormatUint(uint64(c.nextCSeq()), 10)+" REGISTER").
		Add("Contact", contact).
		Add("Expires", secs).
		Add("Supported", "path, gruu, sec-agree").
		Add("Require", "sec-agree").
		Add("Proxy-Require", "sec-agree").
		Add("Allow", "INVITE, ACK, CANCEL, BYE, UPDATE, PRACK, MESSAGE, NOTIFY, OPTIONS, INFO").
		Add("Authorization", authz).
		Add("Security-Client", strings.Join(clientMechs, ", "))
	if verify != nil {
		r.Add("Security-Verify", auth.VerifyHeader(verify))
	}
	if c.cfg.PANI != "" {
		r.Add("P-Access-Network-Info", c.cfg.PANI)
	}
	if c.cfg.UserAgent != "" {
		r.Add("User-Agent", c.cfg.UserAgent)
	}
	return r
}

// status renders a response for errors and the journal: code, reason and
// the text of its Warning, where an SBC says what it disliked.
func status(res *sip.Response) string {
	out := fmt.Sprintf("%d %s", res.StatusCode, res.Reason)
	if w := headerValues(res, "Warning"); len(w) > 0 {
		if _, text, ok := strings.Cut(w[0], `"`); ok {
			if text = strings.TrimSuffix(strings.TrimSpace(text), `"`); text != "" {
				out += " (" + text + ")"
			}
		}
	}
	return out
}

// imeiURN renders urn:gsma:imei:TTTTTTTT-SSSSSS-C (RFC 7254 §3).
func imeiURN(imei string) string {
	if len(imei) != 15 {
		return ""
	}
	return "urn:gsma:imei:" + imei[:8] + "-" + imei[8:14] + "-" + imei[14:]
}

func headerValues(m sip.Message, name string) []string {
	var out []string
	for _, h := range m.GetHeaders(name) {
		out = append(out, h.Value())
	}
	return out
}

func digestChallenge(res *sip.Response) (*auth.Challenge, error) {
	var lastErr error
	for _, v := range headerValues(res, "WWW-Authenticate") {
		ch, err := auth.ParseChallenge(v)
		if err == nil && strings.EqualFold(ch.Algorithm, auth.AlgAKAv1MD5) {
			return ch, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("401 without an AKAv1-MD5 challenge: %v", lastErr)
}

func securityServer(res *sip.Response) ([]auth.Mechanism, error) {
	var all []auth.Mechanism
	for _, v := range headerValues(res, "Security-Server") {
		ms, err := auth.ParseMechanisms(v)
		if err != nil {
			return nil, err
		}
		all = append(all, ms...)
	}
	if len(all) == 0 {
		return nil, errors.New("401 without Security-Server")
	}
	return all, nil
}

// parseBinding reads the 200 to a REGISTER of s that asked for asked; a
// de-registration (asked 0) leaves no binding to time.
func (c *Client) parseBinding(s *session, res *sip.Response, asked time.Duration) (Binding, error) {
	b := Binding{At: time.Now()}
	if asked > 0 {
		var err error
		if b.Expires, err = granted(res, netip.AddrPortFrom(c.cfg.UEAddr, s.sa.UE.PortS).String(), asked); err != nil {
			return Binding{}, err
		}
		if b.Expires < minBinding {
			c.cfg.Log.Warn("registration granted for less than a minute, refreshing it as one of a minute", "expires", b.Expires)
		}
	}
	b.ServiceRoutes = sipnet.ListValues(res, "Service-Route")
	b.AssociatedURIs = sipnet.ListValues(res, "P-Associated-URI")
	b.Routes = append([]string{"<sip:" + netip.AddrPortFrom(s.sa.PCSCF.Addr, s.sa.PCSCF.PortS).String() + ";lr>"}, b.ServiceRoutes...)
	b.Preferred = c.cfg.IMPU
	for _, u := range b.AssociatedURIs {
		if v := strings.Trim(strings.Split(u, ">")[0], "< "); v != "" && v != c.cfg.IMPU {
			b.Preferred = v
			break
		}
	}
	return b, nil
}

// granted is how long the registrar keeps the binding of our contact at
// hostport, from its 200 to a REGISTER that asked for asked: the expires of
// that Contact, else the Expires header, else what we asked (RFC 3261
// §10.2.4). A registrar may shorten the interval asked for, not lengthen it
// (§10.3, step 7), so more counts as asked; none at all is errNoBinding.
func granted(res *sip.Response, hostport string, asked time.Duration) (time.Duration, error) {
	n := int64(asked / time.Second)
	if v := headerValues(res, "Expires"); len(v) > 0 {
		if x, ok := seconds(v[0]); ok {
			n = x
		}
	}
	// Our own Contact's expires wins.
	for _, v := range sipnet.ListValues(res, "Contact") {
		if !strings.Contains(v, hostport) {
			continue
		}
		for _, p := range strings.Split(v, ";") {
			if k, val, ok := strings.Cut(p, "="); ok && strings.EqualFold(strings.TrimSpace(k), "expires") {
				if x, ok := seconds(val); ok {
					n = x
				}
			}
		}
	}
	if n <= 0 {
		return 0, fmt.Errorf("%w (expires %d)", errNoBinding, n)
	}
	if n >= int64(asked/time.Second) {
		return asked, nil
	}
	return time.Duration(n) * time.Second, nil
}

// seconds reads delta-seconds (RFC 3261 §25.1) without overflow: a number
// past the int64 range comes back as its limit.
func seconds(v string) (int64, bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0, false
	}
	return n, true
}

// Refresh re-registers over the SAs we have (TS 24.229 §5.1.1.4). When that
// does not work a full registration follows (§5.1.1.4.1).
func (c *Client) Refresh(ctx context.Context) (Binding, error) {
	c.proc.Lock()
	defer c.proc.Unlock()
	s := c.current()
	if s == nil {
		return c.registerAnew(ctx)
	}
	b, err := c.reregister(ctx, s, false)
	if err == nil || ctx.Err() != nil {
		return b, err
	}
	if errors.Is(err, errNoBinding) {
		// Not at once: Run registers anew after a pause, so a registrar that
		// keeps dropping the binding this way is not flooded.
		return Binding{}, err
	}
	c.cfg.Log.Warn("re-REGISTER failed, registering afresh", "err", err)
	return c.registerAnew(ctx)
}

// Deregister removes the binding (expires=0) and tears the SAs down.
func (c *Client) Deregister(ctx context.Context) error {
	c.proc.Lock()
	defer c.proc.Unlock()
	s := c.current()
	if s == nil {
		return nil
	}
	defer c.teardown()
	_, err := c.reregister(ctx, s, true)
	return err
}

// abandon gives the registration up without a word to the network: the
// connections, the server port and the SAs go, the binding stays behind
// (see ErrAccessLost).
func (c *Client) abandon() {
	c.proc.Lock()
	defer c.proc.Unlock()
	if c.current() != nil {
		c.cfg.Log.Info("IMS registration given up without a de-REGISTER: the access network is gone")
	}
	c.teardown()
}

// reregister refreshes the binding over the SAs of s, or removes it
// (TS 24.229 §5.1.1.4, §5.1.1.6). The network either takes the request, and
// s stays as it is, or challenges it: then new SAs are made beside those of
// s and take over once the registration stands (TS 33.203 §7.4.1a).
func (c *Client) reregister(ctx context.Context, s *session, remove bool) (Binding, error) {
	what := "re-REGISTER"
	if remove {
		what = "de-REGISTER"
	}
	c.dropReplaced()
	for again := false; ; again = true {
		expires := c.expires()
		if remove {
			expires = 0
		}
		// A REGISTER that answers no challenge offers what new SAs would need:
		// new SPIs and a new client port, the server port as it is
		// (TS 24.229 §5.1.1.4.2 and §5.1.1.6.2, TS 33.203 §7.4.0). The P-CSCF
		// refuses an offer with the client port of SAs it holds (TS 33.203
		// §7.1; the tested network: 500 "AKA IP+Port conflict").
		next, err := c.newSession(s.sa.UE.PortS)
		if err != nil {
			return Binding{}, err
		}
		c.mu.Lock()
		gen := s.reauthGen
		if now := time.Now(); !remove && !s.reauthBy.IsZero() && !now.Before(s.reauthBy) {
			c.reauthAt = now // a refresh that a shortening asked for (see shorten)
		}
		c.mu.Unlock()
		res, err := c.protectedRegister(ctx, s, next.client, expires)
		if err != nil {
			return Binding{}, fmt.Errorf("%s: %w", what, err)
		}
		switch {
		case res.StatusCode == 200:
			b, err := c.parseBinding(s, res, expires)
			if err != nil {
				return Binding{}, fmt.Errorf("%s: %w", what, err)
			}
			c.mu.Lock()
			s.binding = b
			if s.reauthGen == gen {
				// The 200 times the binding anew, past any shortening that came
				// before the REGISTER left; one that came since may be newer
				// than the 200 and stays.
				s.reauthBy = time.Time{}
			}
			c.mu.Unlock()
			if !remove {
				c.cfg.Log.Info("IMS registration refreshed", "expires", b.Expires)
			}
			return b, nil
		case res.StatusCode == 401:
			b, err := c.reauthenticate(ctx, s, next, res, expires)
			if err != nil {
				return Binding{}, fmt.Errorf("%s: %w", what, err)
			}
			return b, nil
		case res.StatusCode == 423 && !again && c.noteMinExpires(res):
			continue
		}
		return Binding{}, fmt.Errorf("%s: %s", what, status(res))
	}
}

// reauthenticate answers the challenge res that a protected REGISTER of old
// drew. The challenge, and what follows a SIM out of sync, travel over the
// SAs of old; the answer goes over the new ones, from the new client port.
// With the 200 next becomes the session in use, and old only receives until
// its lifetime ends (TS 33.203 §7.4.1a). When anything fails the new SAs go
// and old stays in use (TS 24.229 §5.1.1.5.1).
func (c *Client) reauthenticate(ctx context.Context, old, next *session, res *sip.Response, expires time.Duration) (Binding, error) {
	pcscf := old.sa.PCSCF.Addr
	akaRes, res, err := c.runAKA(ctx, next, res, pcscf, func(authz string) (*sip.Response, error) {
		return old.conn.Do(ctx, c.registerRequest(old, next.client, old.server, authz, expires), nil)
	})
	if err == nil {
		err = c.secure(ctx, next, res, akaRes, pcscf, old)
	}
	if err == nil {
		if res, err = c.protectedRegister(ctx, next, next.client, expires); err == nil && res.StatusCode != 200 {
			if res.StatusCode == 423 {
				c.noteMinExpires(res) // for the registration that follows
			}
			err = fmt.Errorf("answer to the challenge: %s", status(res))
		}
	}
	var b Binding
	if err == nil {
		if b, err = c.parseBinding(next, res, expires); err != nil {
			err = fmt.Errorf("answer to the challenge: %w", err)
		}
	}
	if err != nil {
		c.remove(next, old)
		return Binding{}, err
	}

	c.mu.Lock()
	next.binding = b
	next.sub, next.subFails, next.subRetry = old.sub, old.subFails, old.subRetry
	c.s, c.old = next, old
	// The P-CSCF may keep sending over the old SAs until it has seen ours
	// arrive over the new ones, and we cannot tell which SA a request to the
	// server port came through. So the old ones stay for all of their
	// lifetime, that of their registration and saGrace on top, instead of
	// going with the first message over the new ones.
	until := old.binding.At.Add(old.binding.Expires + saGrace)
	c.oldTimer = time.AfterFunc(time.Until(until), func() { c.expire(old) })
	c.mu.Unlock()
	// From here on we send over the new SAs only.
	if err := next.sa.Supersede(context.WithoutCancel(ctx), c.cfg.IPsec, old.sa); err != nil {
		c.cfg.Log.Warn("moving to the new SAs", "err", err)
	}
	if expires > 0 {
		c.cfg.Log.Info("IMS registration refreshed with new security associations",
			"expires", b.Expires, "old_sas_for", time.Until(until).Round(time.Second))
	}
	return b, nil
}

// expire ends the lifetime of the SAs that a re-authentication replaced.
func (c *Client) expire(old *session) {
	c.proc.Lock()
	defer c.proc.Unlock()
	c.mu.Lock()
	still := c.old == old
	c.mu.Unlock()
	if still {
		c.dropReplaced()
	}
}

// dropReplaced removes the SAs that a re-authentication replaced: their
// lifetime is over, or another registration procedure begins, and the SAs
// of one earlier authentication are all the UE keeps (TS 33.203 §7.4.1a).
func (c *Client) dropReplaced() {
	c.mu.Lock()
	old, cur := c.old, c.s
	c.old = nil
	if c.oldTimer != nil {
		c.oldTimer.Stop()
		c.oldTimer = nil
	}
	c.mu.Unlock()
	if old != nil {
		c.remove(old, cur)
	}
}

// teardown drops everything: connections, the server port, every SA.
func (c *Client) teardown() {
	c.mu.Lock()
	sessions, ln := []*session{c.old, c.s}, c.ln
	c.s, c.old, c.ln = nil, nil, nil
	if c.oldTimer != nil {
		c.oldTimer.Stop()
		c.oldTimer = nil
	}
	c.mu.Unlock()
	for _, s := range sessions {
		if s != nil && s.conn != nil {
			s.conn.Close()
		}
	}
	if ln != nil {
		ln.Close()
	}
	for _, s := range sessions {
		if s != nil {
			c.remove(s, nil)
		}
	}
}

// remove closes the client connection of s and deletes its SAs. beside is a
// session that stays: the policies both have are left to it.
func (c *Client) remove(s, beside *session) {
	if s.conn != nil {
		s.conn.Close()
	}
	if !s.installed {
		return
	}
	s.installed = false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var err error
	if beside != nil && beside.installed {
		err = s.sa.RemoveBeside(ctx, c.cfg.IPsec, beside.sa)
	} else {
		err = s.sa.Remove(ctx, c.cfg.IPsec)
	}
	if err != nil {
		c.cfg.Log.Warn("removing SAs", "err", err)
	}
}

// handle routes inbound requests: reg-event NOTIFY here, the rest to inbound.
func (c *Client) handle(conn *sipnet.Conn, req *sip.Request) {
	if req.Method == sip.NOTIFY && strings.EqualFold(firstValue(req, "Event"), "reg") {
		c.onRegNotify(conn, req)
		return
	}
	if c.inbound != nil {
		c.inbound(conn, req)
		return
	}
	if req.Method != sip.ACK {
		_ = conn.Respond(req, 501, "Not Implemented")
	}
}

func firstValue(m sip.Message, name string) string {
	if v := headerValues(m, name); len(v) > 0 {
		v0, _, _ := strings.Cut(v[0], ";")
		return strings.TrimSpace(v0)
	}
	return ""
}
