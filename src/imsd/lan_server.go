package main

// SIP server for the phones in the LAN (sipgo): a registrar with digest
// passwords, calls from a phone (outgoing ones and the echo test), incoming
// calls forked to all registered phones, and text messages (lan_message.go).
// It listens only on the LAN address: UDP and TCP on sip.listen, TLS on
// sip.tls_port (lan_tls.go); calls of phones on TLS get SRTP (lan_srtp.go).
// TCP and TLS connections are kept within limits (lan_listener.go).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/xarvel/MudiVoLTE/volte/srtp"
)

const sipAllow = "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, REGISTER, UPDATE, MESSAGE"

type lanSIP struct {
	cfg     SIPConfig
	logger  *slog.Logger
	ip      net.IP
	port    int // UDP and TCP
	tlsPort int // 0 = no TLS
	ua      *sipgo.UserAgent
	srv     *sipgo.Server
	cli     *sipgo.Client
	// contact and dialogs per transport (udp, tcp, tls): our Contact names the
	// transport and port the phone must come back on.
	contact  sip.ContactHeader // UDP and TCP
	contacts map[string]sip.ContactHeader
	dialogs  map[string]*dialogCache
	reg      *registrar
	push     *pushStore
	pusher   pusher // nil: no account for pushes, sleeping phones are not woken
	auth     *digestAuth
	ports    *portAlloc
	mgr      *callManager
	conns    *sipConns // TCP and TLS connections
	closers  []io.Closer

	// A message between phones: msgRelayWait and msgRelayTrying, shorter in
	// tests. msgRelayTrying holds for a message to a number as well.
	relayWait, relayTrying time.Duration

	hookMu sync.Mutex
	// sms sends the phones' messages to numbers as SMS; nil = SMS off.
	sms smsSender
	// online is told the login of a phone that has just registered (pending
	// SMS go to it at once).
	online func(user string)
}

// setSMS connects the SMS bridge: s takes the phones' messages to numbers,
// online hears about every phone that registers.
func (l *lanSIP) setSMS(s smsSender, online func(user string)) {
	l.hookMu.Lock()
	l.sms, l.online = s, online
	l.hookMu.Unlock()
}

func (l *lanSIP) hooks() (smsSender, func(string)) {
	l.hookMu.Lock()
	defer l.hookMu.Unlock()
	return l.sms, l.online
}

// smsSender sends a phone's message to a number as an SMS and returns the
// SIP answer for the phone. lateAnswer hears of a 200 from the phone user to
// the MESSAGE id, after the wait for that answer was over.
type smsSender interface {
	send(user, number, text string) (int, string)
	lateAnswer(id, user string)
}

// startLANSIP starts the SIP server on sip.listen and connects it to the
// manager.
func startLANSIP(cfg SIPConfig, mgr *callManager, logger *slog.Logger) (*lanSIP, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	ip, port, err := cfg.listenAddr()
	if err != nil {
		return nil, err
	}
	// sipgo logs: warnings and above only (too noisy otherwise).
	sipLog := slog.New(slog.NewTextHandler(io.Discard, nil))
	if logger != nil {
		sipLog = slog.New(levelFilter{h: logger.Handler(), min: slog.LevelWarn})
	}
	sip.SetDefaultLogger(sipLog)
	var l *lanSIP
	late := sip.WithTransactionLayerUnhandledResponseHandler(func(res *sip.Response) { l.lateResponse(res) })
	ua, err := sipgo.NewUA(sipgo.WithUserAgent("mudi-imsd"), sipgo.WithUserAgentHostname(ip.String()),
		sipgo.WithUserAgentTransactionLayerOptions(late))
	if err != nil {
		return nil, err
	}
	srv, err := sipgo.NewServer(ua, sipgo.WithServerLogger(sipLog))
	if err != nil {
		ua.Close()
		return nil, err
	}
	cli, err := sipgo.NewClient(ua, sipgo.WithClientHostname(ip.String()), sipgo.WithClientLogger(sipLog))
	if err != nil {
		ua.Close()
		return nil, err
	}
	l = &lanSIP{
		cfg: cfg, logger: logger, ip: ip, ua: ua, srv: srv, cli: cli,
		reg:   newRegistrar(),
		push:  newPushStore(cfg.PushFile),
		auth:  newDigestAuth(cfg.Realm, cfg.Accounts),
		ports: newPortAlloc(ip, cfg.RTPPortMin, cfg.RTPPortMax),
		mgr:   mgr,
		conns: newSIPConns(logger),

		relayWait: msgRelayWait, relayTrying: msgRelayTrying,
	}
	mgr.lan = l
	if cfg.PhonesFile != "" {
		if n := l.reg.load(cfg.PhonesFile); n > 0 && logger != nil {
			logger.Info("SIP: phone registrations restored", "bindings", n, "users", strings.Join(l.reg.users(), ","))
		}
	}
	if err := l.push.keepOnly(cfg.Accounts); err != nil && logger != nil {
		logger.Warn("SIP: push parameters not saved", "err", err)
	}
	if cfg.Push.Login != "" {
		f := newFlexiAPI(cfg.Push)
		l.pusher = f
		if logger != nil {
			logger.Info("SIP: pushes wake sleeping phones", "api", f.base, "account", f.login+"@"+f.domain)
		}
	}

	// We create the listeners ourselves: a bind error shows up at once, and
	// port 0 (tests) turns into a real one.
	port0 := port == 0
	for _, t := range cfg.Transports {
		if t != "udp" {
			continue
		}
		pc, err := net.ListenPacket("udp4", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("SIP udp: %w", err)
		}
		port = pc.LocalAddr().(*net.UDPAddr).Port
		l.closers = append(l.closers, pc)
		go func() { _ = srv.ServeUDP(pc) }()
	}
	for _, t := range cfg.Transports {
		if t != "tcp" {
			continue
		}
		ln, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("SIP tcp: %w", err)
		}
		port = ln.Addr().(*net.TCPAddr).Port
		st := newSIPStream("tcp", ln, srv.ServeTCP, nil, l.conns)
		l.closers = append(l.closers, st)
		go st.run()
	}
	if cfg.hasTransport("tls") {
		cert, made, err := serverCertificate(cfg.TLSCertFile, cfg.TLSKeyFile, ip, time.Now())
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("SIP tls: certificate: %w", err)
		}
		tlsPort := cfg.TLSPort
		if port0 {
			tlsPort = 0 // tests: any free port
		}
		ln, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), strconv.Itoa(tlsPort)))
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("SIP tls: %w", err)
		}
		l.tlsPort = ln.Addr().(*net.TCPAddr).Port
		st := newSIPStream("tls", ln, srv.ServeTLS, tlsServerConfig(cert), l.conns)
		l.closers = append(l.closers, st)
		go st.run()
		if logger != nil {
			args := []any{"listen", ln.Addr().String(), "sha256", certFingerprint(cert)}
			if made {
				args = append(args, "file", cfg.TLSCertFile)
				logger.Info("SIP: new self-signed TLS certificate for the phones", args...)
			} else {
				logger.Info("SIP: TLS for the phones", args...)
			}
		}
	}
	l.port = port
	l.contact = sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: "mudi", Host: ip.String(), Port: port}}
	l.contacts = map[string]sip.ContactHeader{"udp": l.contact, "tcp": l.contact}
	l.dialogs = map[string]*dialogCache{
		"udp": newDialogCache(cli, l.contact, false),
		"tcp": newDialogCache(cli, l.contact, true),
	}
	if l.tlsPort != 0 {
		params := sip.NewParams()
		params.Add("transport", "tls")
		c := sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: "mudi", Host: ip.String(), Port: l.tlsPort, UriParams: params}}
		l.contacts["tls"] = c
		l.dialogs["tls"] = newDialogCache(cli, c, true)
	}

	srv.OnRegister(l.onRegister)
	srv.OnInvite(l.onInvite)
	srv.OnAck(l.onAck)
	srv.OnBye(l.onBye)
	srv.OnCancel(func(req *sip.Request, tx sip.ServerTransaction) {
		l.respond(req, tx, 481, "Call/Transaction Does Not Exist")
	})
	srv.OnOptions(l.onOptions)
	srv.OnInfo(l.onInfo)
	srv.OnUpdate(l.onUpdate)
	srv.OnMessage(l.onMessage)
	srv.OnSubscribe(func(req *sip.Request, tx sip.ServerTransaction) { l.respond(req, tx, 489, "Bad Event") })
	srv.OnPublish(func(req *sip.Request, tx sip.ServerTransaction) { l.respond(req, tx, 489, "Bad Event") })
	srv.OnNotify(func(req *sip.Request, tx sip.ServerTransaction) { l.respond(req, tx, 200, "OK") })
	srv.OnNoRoute(func(req *sip.Request, tx sip.ServerTransaction) {
		res := sip.NewResponseFromRequest(req, 405, "Method Not Allowed", nil)
		res.AppendHeader(sip.NewHeader("Allow", sipAllow))
		_ = tx.Respond(res)
	})

	if logger != nil {
		logger.Info("SIP: server for the phones started",
			"listen", net.JoinHostPort(ip.String(), strconv.Itoa(port)),
			"transports", strings.Join(cfg.Transports, ","), "tls_port", l.tlsPort,
			"accounts", len(cfg.Accounts), "codecs", strings.Join(cfg.Codecs, ","),
			"echo", cfg.EchoExt, "dial_allow", strings.Join(cfg.DialAllow, ","))
	}
	return l, nil
}

// onlineUsers returns the logins of the phones registered now (for status).
func (l *lanSIP) onlineUsers() []string { return l.reg.users() }

// secureUsers returns the logins of the phones registered now over TLS.
func (l *lanSIP) secureUsers() []string { return l.reg.secureUsers() }

// dialogsFor returns the dialog cache of a transport (UDP when unknown).
func (l *lanSIP) dialogsFor(transport string) *dialogCache {
	if d, ok := l.dialogs[strings.ToLower(transport)]; ok {
		return d
	}
	return l.dialogs["udp"]
}

// contactFor returns our Contact for a transport.
func (l *lanSIP) contactFor(transport string) sip.ContactHeader {
	if c, ok := l.contacts[strings.ToLower(transport)]; ok {
		return c
	}
	return l.contact
}

// reachable reports whether a request can go to the device: over TCP and TLS
// only into the connection the phone opened. Without it sipgo would dial the
// phone, which listens on no port, and wait for the dial to fail.
func (l *lanSIP) reachable(b binding) bool {
	if b.transport != "tcp" && b.transport != "tls" {
		return true
	}
	c, err := l.ua.TransportLayer().GetConnection(b.transport, b.source)
	return err == nil && c != nil
}

func (l *lanSIP) Close() {
	for _, c := range l.closers {
		_ = c.Close()
	}
	if l.ua != nil {
		_ = l.ua.Close()
	}
}

func (l *lanSIP) respond(req *sip.Request, tx sip.ServerTransaction, code int, reason string) {
	if err := tx.Respond(sip.NewResponseFromRequest(req, code, reason, nil)); err != nil {
		l.logger.Warn("SIP: response not sent", "code", code, "method", string(req.Method), "from", req.Source(), "err", err)
	}
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// authorize does digest authentication: 401 (REGISTER) or 407 (INVITE and
// the rest, as a proxy).
func (l *lanSIP) authorize(req *sip.Request, tx sip.ServerTransaction, proxy bool) (string, bool) {
	ip := hostOnly(req.Source())
	if l.auth.blocked(ip) {
		l.respond(req, tx, 403, "Forbidden")
		return "", false
	}
	hdr, chal, code, reason := "Authorization", "WWW-Authenticate", 401, "Unauthorized"
	if proxy {
		hdr, chal, code, reason = "Proxy-Authorization", "Proxy-Authenticate", 407, "Proxy Authentication Required"
	}
	h := req.GetHeader(hdr)
	if h == nil && proxy {
		h = req.GetHeader("Authorization")
	}
	stale := false
	if h != nil {
		user, ok, st := l.auth.verify(string(req.Method), h.Value(), ip, req.Recipient.String())
		if ok {
			l.auth.success(ip)
			l.conns.signedIn(req.Transport(), req.Source()) // no time limit for this connection from now on
			return user, true
		}
		stale = st
		if !st {
			if l.auth.fail(ip) {
				l.logger.Warn("SIP: too many wrong passwords, address blocked", "ip", ip, "user", user, "for", authBlockFor.String())
			} else {
				l.logger.Warn("SIP: wrong login or password", "ip", ip, "user", user)
			}
			// 403 rather than a new challenge: on a 401 Linphone with a wrong
			// password repeats the request over and over (10 times in 2 s) and gets
			// its IP blocked for a single typo; on a 403 it stops and shows an error.
			l.respond(req, tx, 403, "Forbidden")
			return "", false
		}
	}
	res := sip.NewResponseFromRequest(req, code, reason, nil)
	res.AppendHeader(sip.NewHeader(chal, l.auth.challenge(stale, ip)))
	_ = tx.Respond(res)
	return "", false
}

// --- REGISTER ---

func (l *lanSIP) onRegister(req *sip.Request, tx sip.ServerTransaction) {
	user, ok := l.authorize(req, tx, false)
	if !ok {
		return
	}
	if to := req.To(); to == nil || to.Address.User != user {
		l.respond(req, tx, 403, "AOR Mismatch")
		return
	}
	expires := regDefaultExpires
	if h := req.GetHeader("Expires"); h != nil {
		if v, err := strconv.Atoi(strings.TrimSpace(h.Value())); err == nil {
			expires = v
		}
	}
	src, transport := req.Source(), strings.ToLower(req.Transport())
	own := map[string]bool{} // bindings from this REGISTER: always in the reply, and first
	var back []binding       // new bindings: a call that rings now goes to them too
	granted := clampExpires(expires)
	for _, h := range req.GetHeaders("Contact") {
		ch, ok := h.(*sip.ContactHeader)
		if !ok {
			continue
		}
		if ch.Address.Wildcard {
			if expires != 0 {
				l.respond(req, tx, 400, "Bad Request") // RFC 3261 §10.3 step 6: Contact: * only with Expires: 0
				return
			}
			l.reg.removeAll(user)
			if err := l.push.forget(user, "", ch.Address, true); err != nil {
				l.logger.Warn("SIP: push sign-out not saved", "user", user, "err", err)
			}
			l.logger.Info("SIP: phone signed out (all its devices)", "user", user)
			continue
		}
		e := expires
		if v, ok := ch.Params.Get("expires"); ok {
			if n, err := strconv.Atoi(v); err == nil {
				e = n
			}
		}
		if e = clampExpires(e); e == 0 {
			l.reg.remove(user, ch.Address)
			if err := l.push.forget(user, contactInstance(ch), ch.Address, false); err != nil {
				l.logger.Warn("SIP: push sign-out not saved", "user", user, "err", err)
			}
			l.logger.Info("SIP: phone signed out", "user", user, "from", src)
			continue
		}
		nb := binding{user: user, contact: ch.Address, source: src, transport: transport,
			instance: contactInstance(ch), expires: time.Now().Add(time.Duration(e) * time.Second)}
		replaced := l.reg.update(nb)
		back = append(back, nb)
		if changed, err := l.push.remember(user, contactInstance(ch), ch.Address, time.Now()); err != nil {
			l.logger.Warn("SIP: push parameters not saved", "user", user, "err", err)
		} else if changed {
			l.logger.Info("SIP: phone push parameters saved", "user", user)
		}
		own[bindingKey(user, ch.Address)] = true
		granted = e
		args := []any{"user", user, "transport", transport, "from", src, "expires", e}
		if replaced > 0 {
			args = append(args, "replaced", replaced) // the same device from a new address
		}
		l.logger.Info("SIP: phone connected", args...)
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	res.AppendHeader(sip.NewHeader("Expires", strconv.Itoa(granted)))
	// RFC 3261 §10.3: the 200 OK lists all bindings of the login. But sipgo does
	// not send UDP datagrams larger than UDPMTUSize-200 = 1300 bytes, and three
	// Linphone Contacts with push parameters already take 1.7 KB: the reply was
	// silently lost, and the phone sent REGISTERs in bursts until the timeout.
	// So the bindings of this REGISTER always go in, the others while they fit.
	limit := 0
	if transport == "udp" {
		limit = sip.UDPMTUSize - 200
	}
	size := len(res.String())
	var mine, others []binding
	for _, b := range l.reg.forUser(user) {
		if own[bindingKey(b.user, b.contact)] {
			mine = append(mine, b)
		} else {
			others = append(others, b)
		}
	}
	for _, b := range append(mine, others...) {
		c := &sip.ContactHeader{Address: b.contact, Params: sip.NewParams()}
		c.Params.Add("expires", strconv.Itoa(int(time.Until(b.expires).Round(time.Second).Seconds())))
		n := len(c.String()) + 2
		if limit > 0 && size+n > limit && !own[bindingKey(b.user, b.contact)] {
			continue
		}
		res.AppendHeader(c)
		size += n
	}
	if err := tx.Respond(res); err != nil {
		l.logger.Warn("SIP: 200 to REGISTER not sent", "user", user, "from", src, "bytes", size, "err", err)
	}
	// After the 200 OK: a phone woken by a push gets its INVITE now.
	if l.mgr != nil {
		for _, b := range back {
			l.mgr.deviceBack(b)
		}
	}
	if _, online := l.hooks(); len(own) > 0 && online != nil {
		online(user)
	}
}

// --- INVITE from a phone ---

func (l *lanSIP) onInvite(req *sip.Request, tx sip.ServerTransaction) {
	if to := req.To(); to != nil {
		if tag, ok := to.Params.Get("tag"); ok && tag != "" {
			l.onReInvite(req, tx)
			return
		}
	}
	user, ok := l.authorize(req, tx, true)
	if !ok {
		return
	}
	target := req.Recipient.User
	if l.cfg.EchoExt != "" && target == l.cfg.EchoExt {
		l.mgr.echoCall(req, tx, user)
		return
	}
	if peer, ok := l.cfg.phoneFor(target); ok {
		l.mgr.internalCall(req, tx, user, peer)
		return
	}
	l.mgr.outgoingCall(req, tx, user, target)
}

// chooseFromOffer decides on the phone's SDP offer: our codec by preference
// and plain RTP or SRTP (lan_srtp.go). ok=false means 488.
func (l *lanSIP) chooseFromOffer(req *sip.Request) (mediaPlan, bool) {
	offer, err := parseSDP(req.Body())
	if err != nil || offer.Port == 0 {
		return mediaPlan{}, false
	}
	plan, err := planFromOffer(offer, req.Transport(), l.cfg.Codecs)
	if err != nil {
		l.logger.Warn("SIP: the phone's offer is not acceptable", "from", req.Source(), "transport", req.Transport(), "err", err)
		return mediaPlan{}, false
	}
	return plan, true
}

// prepareLeg sets up an RTP leg for the phone's offer and returns our SDP
// answer.
func (l *lanSIP) prepareLeg(lc *lineCall, plan mediaPlan) ([]byte, *rtpLeg, error) {
	leg, err := l.ports.open(l.logger)
	if err != nil {
		return nil, nil, err
	}
	f, offer := plan.format, plan.offer
	codec, err := newLANCodec(f)
	if err != nil {
		leg.Close()
		return nil, nil, err
	}
	var sec *sdpSecurity
	if plan.remote != nil {
		local, err := srtp.NewCrypto(plan.remote.Tag, plan.remote.Suite)
		if err == nil {
			err = leg.setSRTP(local, *plan.remote, plan.profile)
		}
		if err != nil {
			leg.Close()
			return nil, nil, err
		}
		sec = leg.security()
	}
	dtmfPT := offer.dtmfPT()
	leg.setRemote(offer.IP, offer.Port)
	leg.setCodec(codec, dtmfPT)
	lc.mu.Lock()
	lc.leg, lc.format, lc.dtmfPT = leg, f, dtmfPT
	ver := lc.sdpVer
	lc.mu.Unlock()
	answer := buildSDP(l.ip, leg.Port(), uint64(lc.id), ver, []lanFormat{f}, dtmfPT, answerDirection(offer.Direction), sec)
	return answer, leg, nil
}

// legOffer is our offer for one leg towards the phones: plain RTP for
// devices on UDP and TCP, RTP/SAVP with keys for devices on TLS.
type legOffer struct {
	plain, secure []byte
	keys          []srtp.Crypto // ours in the secure offer
}

// newLegOffer builds both offers for an RTP port; sessID tells the legs of an
// internal call apart.
func (l *lanSIP) newLegOffer(lc *lineCall, port int, sessID uint64) (legOffer, error) {
	lc.mu.Lock()
	ver := lc.sdpVer
	lc.mu.Unlock()
	formats := offerFormats(l.cfg.Codecs)
	o := legOffer{plain: buildSDP(l.ip, port, sessID, ver, formats, defaultDTMFPT, "sendrecv", nil)}
	if l.tlsPort == 0 {
		return o, nil
	}
	keys, err := newOfferKeys()
	if err != nil {
		return o, err
	}
	o.keys = keys
	o.secure = buildSDP(l.ip, port, sessID, ver, formats, defaultDTMFPT, "sendrecv", &sdpSecurity{Profile: "RTP/SAVP", Keys: keys})
	return o, nil
}

// forDevice returns the offer for a device.
func (o legOffer) forDevice(b binding) []byte {
	if secureTransport(b.transport) && o.secure != nil {
		return o.secure
	}
	return o.plain
}

// applyAnswer applies the SDP of the winning phone's answer: address, port,
// codec and, when we offered it keys, SRTP.
func (l *lanSIP) applyAnswer(lc *lineCall, leg *rtpLeg, win forkResult, offer legOffer) error {
	f, dtmfPT, err := l.answerToLeg(leg, win, offer)
	if err != nil {
		return err
	}
	lc.mu.Lock()
	lc.format, lc.dtmfPT = f, dtmfPT
	lc.mu.Unlock()
	return nil
}

// answerToLeg applies the SDP of the phone's answer to the RTP leg and
// returns the format and the PT of tones.
func (l *lanSIP) answerToLeg(leg *rtpLeg, win forkResult, offer legOffer) (lanFormat, int, error) {
	ans, err := parseSDP(win.sdp)
	if err != nil {
		return lanFormat{}, 0, err
	}
	f, ok := ans.chooseFirstKnown(l.cfg.Codecs)
	if !ok {
		return lanFormat{}, 0, errors.New("the phone chose none of our codecs")
	}
	codec, err := newLANCodec(f)
	if err != nil {
		return lanFormat{}, 0, err
	}
	if win.secure && offer.secure != nil {
		local, remote, err := keysFromAnswer(ans, offer.keys)
		if err != nil {
			return lanFormat{}, 0, err
		}
		if err := leg.setSRTP(local, remote, "RTP/SAVP"); err != nil {
			return lanFormat{}, 0, err
		}
	}
	dtmfPT := ans.dtmfPT()
	leg.setRemote(ans.IP, ans.Port)
	leg.setCodec(codec, dtmfPT)
	return f, dtmfPT, nil
}

// forkInvite sends an INVITE to one device; the first to answer takes the
// call. caller is who is calling: the number from the network (callerUser)
// or a phone login. The very first response (even 100 Trying) is reported to
// alive: the binding is live and worth waiting for (see waitFork).
func (l *lanSIP) forkInvite(ctx context.Context, lc *lineCall, idx int, b binding, caller string, offer []byte, out chan<- forkResult, alive chan<- int, callID string) {
	report := func(r forkResult) {
		select {
		case out <- r:
		case <-ctx.Done():
		}
	}
	req := sip.NewRequest(sip.INVITE, b.contact)
	req.SetDestination(b.source)
	req.SetTransport(strings.ToUpper(b.transport))
	if callID != "" {
		// The Call-ID named in the push: Linphone woken by it waits for this one.
		cid := sip.CallIDHeader(callID)
		req.AppendHeader(&cid)
	}
	fromHdr := &sip.FromHeader{DisplayName: caller, Address: sip.Uri{Scheme: "sip", User: caller, Host: l.ip.String()}, Params: sip.NewParams()}
	fromHdr.Params.Add("tag", sip.GenerateTagN(16))
	req.AppendHeader(fromHdr)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: b.user, Host: l.ip.String()}, Params: sip.NewParams()})
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	req.AppendHeader(sip.NewHeader("Allow", sipAllow))
	req.SetBody(offer)
	res := forkResult{idx: idx, user: b.user, secure: secureTransport(b.transport)}
	if !l.reachable(b) {
		l.logger.Info("incoming: the phone's connection is gone", "user", b.user, "transport", b.transport, "from", b.source)
		res.err = errors.New("no connection to the phone")
		report(res)
		return
	}
	dlg, err := l.dialogsFor(b.transport).WriteInvite(ctx, req)
	if err != nil {
		l.logger.Warn("incoming: INVITE to the phone not sent", "user", b.user, "to", b.source, "err", err)
		res.err = err
		report(res)
		return
	}
	if cid := req.CallID(); cid != nil && lc.dir == "internal" {
		lc.mu.Lock()
		lc.peerCallIDs = append(lc.peerCallIDs, cid.Value())
		lc.mu.Unlock()
	}
	note := func(*sip.Response) error {
		if !res.alive {
			res.alive = true
			select {
			case alive <- idx:
			default:
			}
		}
		return nil
	}
	if err := dlg.WaitAnswer(ctx, sipgo.AnswerOptions{OnResponse: note}); err != nil {
		if r := dlg.InviteResponse; r != nil && r.IsSuccess() {
			// sipgo's cancel path consumed a crossing 200 and returned ctx.Err.
			endAnsweredDialog(dlg)
		}
		res.err = err
		var de *sipgo.ErrDialogResponse
		if errors.As(err, &de) && de.Res != nil {
			res.code = de.Res.StatusCode
			res.busy = res.code == 486 || res.code == 600
		}
		_ = dlg.Close()
		report(res)
		return
	}
	if !lc.answered.CompareAndSwap(false, true) {
		// Another device has already picked up.
		endAnsweredDialog(dlg)
		res.err = errors.New("another device answered first")
		report(res)
		return
	}
	res.dlg = dlg
	lc.addDialog(dlg.ID)
	if dlg.InviteResponse != nil {
		res.sdp = dlg.InviteResponse.Body()
	}
	// The ringer's channel is unbuffered: ownership passes only to a caller
	// still waiting for the winner. If it has left, we must end the dialog.
	select {
	case out <- res:
	case <-ctx.Done():
		endAnsweredDialog(dlg)
	}
}

func endAnsweredDialog(dlg *sipgo.DialogClientSession) {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	defer dlg.Close()
	_ = dlg.Ack(c)
	_ = dlg.Bye(c)
}

// endPushedCall ends the call a device was woken for after that call is
// over: the INVITE with the Call-ID of the push lets Linphone match the call
// it shows since the push, and the CANCEL right after the first answer (or
// after 3 s) closes it as missed. If the device picks up first, it gets a BYE.
func (l *lanSIP) endPushedCall(b binding, lp latePush, logger *slog.Logger) {
	logger.Info("call: the phone woke up after the call ended, closing it there", "user", b.user, "transport", b.transport)
	gone := &lineCall{dir: "late"}
	gone.answered.Store(true) // a pickup is answered with ACK and BYE
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results, alive := make(chan forkResult, 1), make(chan int, 1)
	go l.forkInvite(ctx, gone, 0, b, lp.caller, lp.offer.forDevice(b), results, alive, lp.callID)
	select {
	case <-alive:
	case <-results:
		return
	case <-time.After(3 * time.Second):
	}
	cancel() // sipgo sends the CANCEL
	select {
	case <-results:
	case <-time.After(10 * time.Second):
	}
}

// --- Other requests ---

func (l *lanSIP) onAck(req *sip.Request, tx sip.ServerTransaction) {
	if l.dialogsFor(req.Transport()).ReadAck(req, tx) == nil {
		return
	}
	for _, d := range l.dialogs {
		if d.ReadAck(req, tx) == nil {
			return
		}
	}
}

func (l *lanSIP) onBye(req *sip.Request, tx sip.ServerTransaction) {
	if l.dialogsFor(req.Transport()).ReadBye(req, tx) == nil {
		return
	}
	for _, d := range l.dialogs {
		if d.ReadBye(req, tx) == nil {
			return
		}
	}
	l.respond(req, tx, 481, "Call/Transaction Does Not Exist")
}

func (l *lanSIP) onOptions(req *sip.Request, tx sip.ServerTransaction) {
	res := sip.NewResponseFromRequest(req, 200, "OK", nil)
	res.AppendHeader(sip.NewHeader("Allow", sipAllow))
	res.AppendHeader(sip.NewHeader("Accept", "application/sdp"))
	_ = tx.Respond(res)
}

// inDialog finds the dialog of a request a phone sends inside a call
// (re-INVITE, UPDATE, INFO) and admits it only when the dialog belongs to the
// current call and the request comes from the phone of that dialog
// (fromPhone); anything else gets 481. Without this check one INVITE with a
// To tag from any host on the Wi-Fi re-offered the media of the running call
// to that host and, on a TLS call, got our SRTP key back in the answer. On
// UDP the tags are readable on the Wi-Fi, so the address check is what keeps
// a third host out there; on TLS the dialog lives in the phone's connection.
func (l *lanSIP) inDialog(req *sip.Request, tx sip.ServerTransaction) (lc *lineCall, callID string, ok bool) {
	if h := req.CallID(); h != nil {
		callID = h.Value()
	}
	if lc = l.mgr.current(); lc != nil {
		for _, d := range l.dialogs {
			id, phone, found := d.find(req)
			if !found {
				continue
			}
			if !lc.ownsDialog(id) {
				break
			}
			if src := req.Source(); !fromPhone(src, req.Transport(), phone) {
				l.logger.Warn("SIP: request inside a call from another address than its phone's, refused",
					"method", string(req.Method), "from", src, "phone", strings.Join(phone, ","))
				l.respond(req, tx, 481, "Call/Transaction Does Not Exist")
				return nil, "", false
			}
			return lc, callID, true
		}
	}
	l.logger.Info("SIP: request outside any call of ours, refused", "method", string(req.Method), "from", req.Source())
	l.respond(req, tx, 481, "Call/Transaction Does Not Exist")
	return nil, "", false
}

// fromPhone tells whether a request inside a dialog came from one of the
// addresses of that dialog's phone. Over UDP the whole address counts. Over
// TCP and TLS the port belongs to the connection: a phone that reconnected
// during the call is still the same host, and a 481 would end its call.
func fromPhone(src, transport string, phone []string) bool {
	if strings.EqualFold(transport, "udp") {
		return slices.Contains(phone, src)
	}
	host := hostOnly(src)
	return slices.ContainsFunc(phone, func(p string) bool { return hostOnly(p) == host })
}

// onReInvite handles a re-INVITE in a dialog (hold, session refresh): we
// answer with the leg's current parameters and the mirrored direction.
func (l *lanSIP) onReInvite(req *sip.Request, tx sip.ServerTransaction) {
	lc, callID, ok := l.inDialog(req, tx)
	if !ok {
		return
	}
	l.reoffer(req, tx, lc, callID)
}

// reoffer answers the SDP of a re-INVITE or an UPDATE inside a dialog of lc.
func (l *lanSIP) reoffer(req *sip.Request, tx sip.ServerTransaction, lc *lineCall, callID string) {
	var body []byte
	var err error
	if lc.isPeerCall(callID) {
		body, err = l.peerRefreshSDP(lc, req.Body(), req.Transport())
	} else {
		body, err = l.sessionRefreshSDP(lc, req.Body(), req.Transport())
	}
	if err != nil {
		l.logger.Warn("SIP: re-offer of the phone refused", "from", req.Source(), "err", err)
		l.respond(req, tx, 488, "Not Acceptable Here")
		return
	}
	if body == nil {
		l.respond(req, tx, 481, "Call/Transaction Does Not Exist")
		return
	}
	res := sip.NewResponseFromRequest(req, 200, "OK", body)
	res.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	contact := l.contactFor(req.Transport())
	res.AppendHeader(&contact)
	_ = tx.Respond(res)
}

func (l *lanSIP) onUpdate(req *sip.Request, tx sip.ServerTransaction) {
	lc, callID, ok := l.inDialog(req, tx)
	if !ok {
		return
	}
	if len(req.Body()) == 0 {
		l.respond(req, tx, 200, "OK")
		return
	}
	l.reoffer(req, tx, lc, callID)
}

// sessionRefreshSDP returns the SDP answer to a re-INVITE/UPDATE that came
// over transport; nil when there is no call, an error when the offer must
// get 488.
func (l *lanSIP) sessionRefreshSDP(lc *lineCall, offerBody []byte, transport string) ([]byte, error) {
	lc.mu.Lock()
	leg, f, dtmfPT := lc.leg, lc.format, lc.dtmfPT
	lc.sdpVer++
	ver := lc.sdpVer
	lc.mu.Unlock()
	return l.refreshSDP(leg, f, dtmfPT, uint64(lc.id), ver, offerBody, transport)
}

// peerRefreshSDP does the same for the second phone of an internal call.
func (l *lanSIP) peerRefreshSDP(lc *lineCall, offerBody []byte, transport string) ([]byte, error) {
	lc.mu.Lock()
	leg, f, dtmfPT := lc.peer, lc.peerFormat, lc.peerDTMF
	lc.sdpVer++
	ver := lc.sdpVer
	lc.mu.Unlock()
	return l.refreshSDP(leg, f, dtmfPT, uint64(lc.id)+1<<32, ver, offerBody, transport)
}

// refreshSDP answers a re-offer on a live leg with its codec and, for SRTP,
// its keys; without an offer (late offer) it offers the same. The keys of an
// SRTP leg travel only inside TLS, like at the start of the call.
func (l *lanSIP) refreshSDP(leg *rtpLeg, f lanFormat, dtmfPT int, sessID, ver uint64, offerBody []byte, transport string) ([]byte, error) {
	if leg == nil || f.Name == "" {
		return nil, nil
	}
	dir := "sendrecv"
	sec := leg.security()
	if len(offerBody) > 0 {
		if offer, err := parseSDP(offerBody); err == nil {
			if sec != nil && !secureTransport(transport) {
				return nil, fmt.Errorf("the keys of an SRTP call re-offered over %s, not TLS", strings.ToUpper(transport))
			}
			if sec, err = leg.refreshKeys(offer); err != nil {
				return nil, err
			}
			dir = answerDirection(offer.Direction)
			if offer.Port > 0 && !offer.IP.IsUnspecified() {
				leg.setRemote(offer.IP, offer.Port)
			}
			leg.resetStream() // after hold/resume the first packet carries the marker again (RFC 3550 §5.3)
		}
	}
	return buildSDP(l.ip, leg.Port(), sessID, ver, []lanFormat{f}, dtmfPT, dir, sec), nil
}

// onInfo handles DTMF sent with SIP INFO (application/dtmf-relay).
func (l *lanSIP) onInfo(req *sip.Request, tx sip.ServerTransaction) {
	// INFO carries DTMF into a live call: only from an authorised phone and only
	// inside a dialog of the current call, otherwise any phone on the Wi-Fi
	// could dial digits into someone else's conversation.
	if _, ok := l.authorize(req, tx, true); !ok {
		return
	}
	if _, _, ok := l.inDialog(req, tx); !ok {
		return
	}
	if ct := req.GetHeader("Content-Type"); ct != nil && strings.Contains(strings.ToLower(ct.Value()), "dtmf") {
		if d, ok := parseInfoDTMF(string(req.Body())); ok {
			l.mgr.phoneDTMF(d)
		}
	}
	l.respond(req, tx, 200, "OK")
}

func parseInfoDTMF(body string) (byte, bool) {
	for _, line := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.EqualFold(strings.TrimSpace(k), "Signal") {
			v = strings.TrimSpace(v)
			if len(v) == 1 && strings.ContainsRune("0123456789*#ABCD", rune(v[0])) {
				return v[0], true
			}
		}
	}
	b := strings.TrimSpace(body)
	if len(b) == 1 && strings.ContainsRune("0123456789*#ABCD", rune(b[0])) {
		return b[0], true
	}
	return 0, false
}

// levelFilter passes records at level min and above (silence for the chatty
// sipgo).
type levelFilter struct {
	h   slog.Handler
	min slog.Level
}

func (f levelFilter) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= f.min && f.h.Enabled(ctx, l)
}
func (f levelFilter) Handle(ctx context.Context, r slog.Record) error { return f.h.Handle(ctx, r) }
func (f levelFilter) WithAttrs(a []slog.Attr) slog.Handler {
	return levelFilter{h: f.h.WithAttrs(a), min: f.min}
}
func (f levelFilter) WithGroup(n string) slog.Handler {
	return levelFilter{h: f.h.WithGroup(n), min: f.min}
}
