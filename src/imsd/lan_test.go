package main

// S7: tests of the SIP bridge. Unit tests (digest, SDP, codecs, numbers) and
// end-to-end scenarios over real SIP on 127.0.0.1: a fake "phone" on sipgo
// registers, calls the echo test and the outside world, and takes incoming
// calls; the network is played by a fake network call with an AMR-WB loop.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/xarvel/MudiVoLTE/volte/media"
	"github.com/xarvel/MudiVoLTE/volte/media/g722"
	"github.com/xarvel/MudiVoLTE/volte/srtp"
)

// --- Unit tests ---

func TestDigestAuthQopAndStale(t *testing.T) {
	a := newDigestAuth("mudi", []SIPAccount{{User: "pixel", Password: "secret-pass-1"}})
	const ip = "127.0.0.1"
	chal := a.challenge(false, ip)
	p := parseDigestParams(strings.TrimPrefix(chal, "Digest "))
	if p["realm"] != "mudi" || p["nonce"] == "" || p["qop"] != "auth" {
		t.Fatalf("challenge: %v", p)
	}
	const uri = "sip:192.168.8.1"
	mkNC := func(pass, nonce, nc string) string {
		ha1 := md5hex("pixel:mudi:" + pass)
		ha2 := md5hex("REGISTER:" + uri)
		resp := md5hex(ha1 + ":" + nonce + ":" + nc + ":abc:auth:" + ha2)
		return fmt.Sprintf(`Digest username="pixel", realm="mudi", nonce="%s", uri="%s", response="%s", algorithm=MD5, cnonce="abc", qop=auth, nc=%s`, nonce, uri, resp, nc)
	}
	mk := func(pass, nonce string) string { return mkNC(pass, nonce, "00000001") }
	if u, ok, _ := a.verify("REGISTER", mk("secret-pass-1", p["nonce"]), ip, uri); !ok || u != "pixel" {
		t.Fatal("the right password was not accepted")
	}
	if _, ok, _ := a.verify("REGISTER", mk("wrong", p["nonce"]), ip, uri); ok {
		t.Fatal("a wrong password was accepted")
	}
	// The same header from another address (intercepted on the Wi-Fi): a
	// foreign nonce → not accepted, no penalty.
	if _, ok, stale := a.verify("REGISTER", mk("secret-pass-1", p["nonce"]), "192.168.8.250", uri); ok || !stale {
		t.Fatalf("replay from another IP: ok=%v stale=%v", ok, stale)
	}
	// The same header from the phone's own address (a UDP request read off
	// the Wi-Fi, sent again with the phone's IP): the count does not grow, so
	// a fresh nonce is asked for, without a penalty.
	if _, ok, stale := a.verify("REGISTER", mk("secret-pass-1", p["nonce"]), ip, uri); ok || !stale {
		t.Fatalf("replay from the phone's own IP: ok=%v stale=%v", ok, stale)
	}
	// The phone's next request under the same nonce counts up.
	if _, ok, stale := a.verify("REGISTER", mkNC("secret-pass-1", p["nonce"], "00000002"), ip, uri); !ok || stale {
		t.Fatalf("second request under the nonce: ok=%v stale=%v", ok, stale)
	}
	// A header taken from a request to one target does not open another.
	if _, ok, stale := a.verify("INVITE", mkNC("secret-pass-1", p["nonce"], "00000003"), ip, "sip:+447700900123@192.168.8.1"); ok || stale {
		t.Fatalf("header for another target: ok=%v stale=%v", ok, stale)
	}
	// The port and the parameters of the Request-URI do not matter.
	if !sameURI("sip:192.168.8.1", "sip:192.168.8.1:5061;transport=tls") || sameURI("sip:600@192.168.8.1", "sip:601@192.168.8.1") {
		t.Fatal("sameURI")
	}
	// A response without qop (RFC 2069) carries no nonce count and could be
	// sent again for an hour: refused even with the right password.
	noQop := func(nonce string) string {
		ha1 := md5hex("pixel:mudi:secret-pass-1")
		resp := md5hex(ha1 + ":" + nonce + ":" + md5hex("REGISTER:"+uri))
		return fmt.Sprintf(`Digest username="pixel", realm="mudi", nonce="%s", uri="%s", response="%s", algorithm=MD5`, nonce, uri, resp)
	}
	if _, ok, stale := a.verify("REGISTER", noQop(a.newNonce(ip)), ip, uri); ok || stale {
		t.Fatalf("response without qop: ok=%v stale=%v, want refused", ok, stale)
	}
	// An unknown login in a valid format: rejected without stale (the same
	// path as a wrong password).
	if u, ok, stale := a.verify("REGISTER", strings.Replace(mk("x", p["nonce"]), `username="pixel"`, `username="nobody"`, 1), ip, uri); ok || stale || u != "nobody" {
		t.Fatalf("unknown login: u=%q ok=%v stale=%v", u, ok, stale)
	}
	if _, ok, stale := a.verify("REGISTER", mk("secret-pass-1", "deadbeef.00"), ip, uri); ok || !stale {
		t.Fatalf("foreign nonce (from a previous process): ok=%v stale=%v, want a retry without a penalty", ok, stale)
	}
	// An expired nonce: the right password → stale.
	a.now = func() time.Time { return time.Now().Add(-2 * nonceTTL) }
	old := a.newNonce(ip)
	a.now = time.Now
	if _, ok, stale := a.verify("REGISTER", mk("secret-pass-1", old), ip, uri); ok || !stale {
		t.Fatalf("expired nonce: ok=%v stale=%v", ok, stale)
	}
	// The record of nonce counts does not grow without bound. The nonces
	// here are spread over half an hour: among twelve thousand of one second
	// the four random bytes of two do meet now and then, and the second of
	// the pair is refused as a replay (7 runs in 400).
	start := time.Now()
	for i := 0; i < 3*nonceSeenMax; i++ {
		a.now = func() time.Time { return start.Add(-time.Duration(i%1800) * time.Second) }
		n := a.newNonce(ip)
		if _, ok, _ := a.verify("REGISTER", mk("secret-pass-1", n), ip, uri); !ok {
			t.Fatalf("nonce %d not accepted", i)
		}
	}
	a.now = time.Now
	if n := len(a.seen); n > nonceSeenMax {
		t.Fatalf("the record of nonce counts grew to %d entries", n)
	}
	// The failure map does not grow without bound under a scan from many addresses.
	for i := 0; i < 3*authFailsMax; i++ {
		a.fail(fmt.Sprintf("10.0.%d.%d", i/256, i%256))
	}
	if n := len(a.fails); n > authFailsMax {
		t.Fatalf("the failure map grew to %d entries", n)
	}
	// The guessing block. The address is not from the scan above: an entry from
	// there that survived the cleanup already carries one failure.
	for i := 0; i < authFailLimit-1; i++ {
		if a.fail("10.9.9.9") {
			t.Fatal("blocked before the limit")
		}
	}
	if !a.fail("10.9.9.9") || !a.blocked("10.9.9.9") {
		t.Fatal("the block did not trigger")
	}
}

// Only a response to a nonce issued to this address can count as a wrong
// password: the source of a UDP packet can be forged.
func TestDigestAuthFailureNeedsOurNonce(t *testing.T) {
	a := newDigestAuth("mudi", []SIPAccount{{User: "pixel", Password: "secret-pass-1"}})
	const ip, uri = "192.168.8.109", "sip:192.168.8.1"
	hdr := func(realm, nonce, target, alg string) string {
		return fmt.Sprintf(`Digest username="pixel", realm="%s", nonce="%s", uri="%s", response="00", algorithm=%s, cnonce="abc", qop=auth, nc=00000001`,
			realm, nonce, target, alg)
	}
	other := a.newNonce("192.168.8.66")
	for name, h := range map[string]string{
		"not Digest":    "Basic eA==",
		"no nonce":      `Digest username="pixel", realm="mudi", uri="sip:192.168.8.1", response="00"`,
		"foreign realm": hdr("other", other, uri, "MD5"),
		"foreign uri":   hdr("mudi", other, "sip:600@192.168.8.1", "MD5"),
		"foreign alg":   hdr("mudi", other, uri, "SHA-256"),
	} {
		if _, ok, stale := a.verify("REGISTER", h, ip, uri); ok || !stale {
			t.Errorf("%s without our nonce: ok=%v stale=%v, want a new challenge", name, ok, stale)
		}
	}
	// Under a nonce of its own the same headers are failures of that address.
	own := a.newNonce(ip)
	for name, h := range map[string]string{
		"foreign realm": hdr("other", own, uri, "MD5"),
		"foreign uri":   hdr("mudi", own, "sip:600@192.168.8.1", "MD5"),
		"foreign alg":   hdr("mudi", own, uri, "SHA-256"),
	} {
		if _, ok, stale := a.verify("REGISTER", h, ip, uri); ok || stale {
			t.Errorf("%s under our nonce: ok=%v stale=%v, want a failure", name, ok, stale)
		}
	}
}

// A packet that is not RTP at all is no failed SRTP check; one with a wrong
// tag is.
func TestSRTPFailureIsRTPOnly(t *testing.T) {
	ip := net.IPv4(127, 0, 0, 1)
	leg, err := newPortAlloc(ip, 41300, 41400).open(slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer leg.Close()
	local, err := srtp.NewCrypto(1, srtp.AES128CMSHA1_80)
	if err != nil {
		t.Fatal(err)
	}
	remote, err := srtp.NewCrypto(1, srtp.AES128CMSHA1_80)
	if err != nil {
		t.Fatal(err)
	}
	if err := leg.setSRTP(local, remote, "RTP/SAVP"); err != nil {
		t.Fatal(err)
	}
	phone, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: leg.Port()})
	if err != nil {
		t.Fatal(err)
	}
	defer phone.Close()
	leg.setRemote(ip, phone.LocalAddr().(*net.UDPAddr).Port)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = leg.Run(ctx, func([]int16) {}) }()
	wrongTag := make([]byte, 40)
	wrongTag[0] = 0x80
	for _, p := range [][]byte{make([]byte, 20), wrongTag} {
		if _, err := phone.Write(p); err != nil {
			t.Fatal(err)
		}
	}
	fails := func() int {
		leg.mu.Lock()
		defer leg.mu.Unlock()
		return leg.fails
	}
	waitFor(t, func() bool { return fails() > 0 }, "the packet with a wrong tag was not counted")
	if n := fails(); n != 1 {
		t.Fatalf("failed checks: %d, want 1: the packet that is not RTP counted too", n)
	}
}

func TestParseSDPLinphoneOffer(t *testing.T) {
	offer := "v=0\r\no=pixel 1 1 IN IP4 192.168.8.123\r\ns=Talk\r\nc=IN IP4 192.168.8.123\r\nt=0 0\r\n" +
		"m=audio 7078 RTP/AVP 96 97 98 0 8 9 101\r\n" +
		"a=rtpmap:96 opus/48000/2\r\na=rtpmap:97 speex/16000\r\na=rtpmap:98 speex/8000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\na=fmtp:101 0-15\r\na=sendrecv\r\n" +
		"m=video 9078 RTP/AVP 102\r\n"
	a, err := parseSDP([]byte(offer))
	if err != nil {
		t.Fatal(err)
	}
	if !a.IP.Equal(net.ParseIP("192.168.8.123")) || a.Port != 7078 || a.dtmfPT() != 101 {
		t.Fatalf("parse: %+v dtmf=%d", a, a.dtmfPT())
	}
	f, ok := a.chooseByPreference([]string{"G722", "PCMU", "PCMA"})
	if !ok || f.Name != "G722" || f.PT != 9 {
		t.Fatalf("choice: %+v %v", f, ok)
	}
	if answerDirection("sendonly") != "recvonly" || answerDirection("inactive") != "inactive" {
		t.Fatal("directions")
	}
	sdp := string(buildSDP(net.ParseIP("192.168.8.1"), 40000, 1, 2, []lanFormat{f}, 101, "sendrecv", nil))
	for _, want := range []string{"c=IN IP4 192.168.8.1", "m=audio 40000 RTP/AVP 9 101", "a=rtpmap:9 G722/8000", "a=rtpmap:101 telephone-event/8000"} {
		if !strings.Contains(sdp, want) {
			t.Fatalf("no %q in\n%s", want, sdp)
		}
	}
}

func tone(n int, rate float64, hz float64, amp float64, phase *float64) []int16 {
	out := make([]int16, n)
	for i := range out {
		out[i] = int16(amp * math.Sin(*phase))
		*phase += 2 * math.Pi * hz / rate
	}
	return out
}

func rms(s []int16) float64 {
	if len(s) == 0 {
		return 0
	}
	acc := 0.0
	for _, v := range s {
		acc += float64(v) * float64(v)
	}
	return math.Sqrt(acc / float64(len(s)))
}

func TestLANCodecsRoundtrip(t *testing.T) {
	for _, name := range []string{"G722", "PCMU", "PCMA"} {
		f := staticLANFormats[name]
		enc, _ := newLANCodec(f)
		dec, _ := newLANCodec(f)
		var ph float64
		var out []int16
		for i := 0; i < 50; i++ {
			pl := enc.Encode(tone(frameSamples16k, 16000, 1000, 8000, &ph))
			pcm := dec.Decode(pl)
			if len(pcm) != frameSamples16k {
				t.Fatalf("%s: frame of %d samples", name, len(pcm))
			}
			out = append(out, pcm...)
		}
		r := rms(out[len(out)/2:])
		if r < 4000 || r > 7500 { // sine of amplitude 8000 → RMS ≈ 5657
			t.Fatalf("%s: RMS after the round trip %.0f", name, r)
		}
	}
	// A-law: reference points.
	for _, s := range []int16{0, 100, -100, 1000, -1000, 30000, -30000} {
		if d := math.Abs(float64(alawDecode(alawEncode(s))) - float64(s)); d > math.Max(16, math.Abs(float64(s))*0.07) {
			t.Fatalf("A-law %d → %d", s, alawDecode(alawEncode(s)))
		}
	}
}

func TestNormalizeAndPolicy(t *testing.T) {
	cases := map[string]string{
		"+44 7700 900456":     "+447700900456",
		"00447700900456":      "+447700900456",
		"07700900456":         "+447700900456",
		"+33 6 39 98 12 34":   "+33639981234",
		"1500":                "1500",
		"077;phone-context=x": "+4477",
	}
	for in, want := range cases {
		got, err := normalizeDialed(in, "44")
		if err != nil || got != want {
			t.Fatalf("%q → %q (%v), want %q", in, got, err, want)
		}
	}
	if _, err := normalizeDialed("*100#", "44"); err == nil {
		t.Fatal("a USSD code accepted as a number")
	}
	allow := []string{"+44", "+33", "1500"}
	for num, want := range map[string]bool{"+447700900456": true, "+33639981234": true, "+1555": false, "1500": true, "1501": false} {
		if dialAllowed(allow, num) != want {
			t.Fatalf("policy %s", num)
		}
	}
	if callerUser("+447700900456") != "+447700900456" || callerUser("07700900456") != "07700900456" || callerUser("") != "anonymous" {
		t.Fatal("callerUser")
	}
}

// --- End-to-end scenarios ---

const testPass = "test-pass-123"

type fakeIMSCall struct {
	id        string
	dir       CallDirection
	media     NetMedia
	loop      chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	answered  atomic.Bool
	rang      atomic.Bool
	hungup    atomic.Bool
	rejected  atomic.Int32
	dtmf      chan string
	hangBlock chan struct{} // non-nil: Hangup hangs (BYE over a cut transport, §86)
}

func newFakeIMSCall(id string, dir CallDirection) *fakeIMSCall {
	// AMR-WB when the codec is linked in (cgo), otherwise G.711, as on the router.
	m := NetMedia{Negotiated: true, Codec: "PCMA", PayloadType: 8, ClockRate: 8000}
	if media.NewAMRWBCoder != nil {
		m = NetMedia{Negotiated: true, Codec: "AMR-WB", PayloadType: 104, ClockRate: 16000, ModeSet: "0,1,2"}
	}
	return &fakeIMSCall{id: id, dir: dir, media: m, loop: make(chan []byte, 64), closed: make(chan struct{}), dtmf: make(chan string, 8)}
}

func (c *fakeIMSCall) close()                       { c.closeOnce.Do(func() { close(c.closed) }) }
func (c *fakeIMSCall) ID() string                   { return c.id }
func (c *fakeIMSCall) Direction() CallDirection     { return c.dir }
func (c *fakeIMSCall) Media() NetMedia              { return c.media }
func (c *fakeIMSCall) Ring() error                  { c.rang.Store(true); return nil }
func (c *fakeIMSCall) Answer(context.Context) error { c.answered.Store(true); return nil }
func (c *fakeIMSCall) Reject(_ context.Context, code int, _ string) error {
	c.rejected.Store(int32(code))
	c.close()
	return nil
}
func (c *fakeIMSCall) Hangup(context.Context) error {
	c.hungup.Store(true)
	if c.hangBlock != nil {
		<-c.hangBlock // like a BYE over a dead transport (§86): ctx does not help
	}
	c.close()
	return nil
}
func (c *fakeIMSCall) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case p := <-c.loop:
		return p, nil, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-c.closed:
		return nil, nil, errors.New("the call is closed")
	}
}
func (c *fakeIMSCall) WriteRTP(_ context.Context, data []byte) error {
	select {
	case c.loop <- append([]byte(nil), data...): // loop: the network "returns" our audio
	default:
	}
	return nil
}
func (c *fakeIMSCall) SendDTMF(_ context.Context, digits string) error {
	c.dtmf <- digits
	return nil
}

type fakeDialer struct {
	mgr      *callManager
	call     *fakeIMSCall
	failCode int
	to       atomic.Value
}

func (d *fakeDialer) Dial(ctx context.Context, to string) (imsCall, error) {
	d.to.Store(to)
	d.mgr.onIMSEvent(d.call, CallStateDialing)
	time.Sleep(100 * time.Millisecond)
	d.mgr.onIMSEvent(d.call, CallStateRinging)
	select {
	case <-time.After(300 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if d.failCode != 0 {
		return nil, fmt.Errorf("dialing call: %w", &dialError{Code: d.failCode, Reason: "Busy Here"})
	}
	return d.call, nil
}

type testRig struct {
	t       *testing.T
	mgr     *callManager
	lan     *lanSIP
	srvAddr string
}

func newTestRig(t *testing.T, cfg *Config, withDialer bool) *testRig {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		logger = slog.New(slog.NewTextHandler(testLogWriter{t}, nil))
	}
	sc := SIPConfig{
		Listen: "127.0.0.1:0", Transports: []string{"udp"},
		Accounts:  []SIPAccount{{User: "pixel", Password: testPass, Ext: "201"}, {User: "iphone", Password: testPass, Ext: "202"}},
		DialAllow: []string{"+44"}, DefaultCountry: "44", EchoExt: "600",
		RTPPortMin: 41000, RTPPortMax: 41200, RingSec: 5,
	}.withDefaults()
	mgr := newCallManager(cfg, sc, nil, logger)
	lan, err := startLANSIP(sc, mgr, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lan.Close)
	return &testRig{t: t, mgr: mgr, lan: lan, srvAddr: fmt.Sprintf("127.0.0.1:%d", lan.port)}
}

type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

// testPhone is a "phone" on sipgo: registration, calls, incoming calls.
type testPhone struct {
	t         *testing.T
	user      string
	ip        string
	ua        *sipgo.UserAgent
	srv       *sipgo.Server
	cli       *sipgo.Client
	dcc       *sipgo.DialogClientCache
	dsc       *sipgo.DialogServerCache
	port      int
	rtp       *net.UDPConn
	sipSocket net.PacketConn // UDP listener; UA.Close does not own externally served sockets
	byeGot    chan struct{}
	incoming  chan *sipgo.DialogServerSession
	messages  chan *sip.Request // MESSAGEs to the phone; answered with msgCode (0 = 200)
	msgCode   atomic.Int32
	msgDelay  atomic.Int64                // ns it takes to answer a MESSAGE, as a phone asleep does
	refused   atomic.Pointer[sip.Request] // the last MESSAGE it answered with msgCode
	unreg     bool
	instance  string         // +sip.instance in the REGISTER Contact, as Linphone sends it; empty = none
	pn        []sip.HeaderKV // push parameters in the REGISTER Contact URI (pn-provider…), as Linphone sends them
	// tls: the phone talks SIP over TLS, through the connection it opens
	// (lan_tls_test.go); key: its SRTP key, offered as RTP/SAVP (nil = plain RTP).
	tls bool
	key *srtp.Crypto
	// seq and ts of the phone's RTP go on from one talk to the next, as on a
	// real phone: under SRTP a stream that starts over with the same key is a
	// replay.
	seq uint16
	ts  uint32
}

func newTestPhone(t *testing.T) *testPhone {
	t.Helper()
	return newTestPhoneOn(t, "127.0.0.1")
}

func newTestPhoneOn(t *testing.T, ip string) *testPhone {
	t.Helper()
	return newTestPhoneUser(t, ip, "pixel")
}

func newTestPhoneUser(t *testing.T, ip, user string) *testPhone {
	t.Helper()
	ua, err := sipgo.NewUA(sipgo.WithUserAgent("test-phone"), sipgo.WithUserAgentHostname(ip))
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := sipgo.NewServer(ua)
	cli, _ := sipgo.NewClient(ua, sipgo.WithClientHostname(ip))
	pc, err := net.ListenPacket("udp4", ip+":0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeUDP(pc) }()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	contact := sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: user, Host: ip, Port: port}}
	rtp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	p := &testPhone{t: t, user: user, ip: ip, ua: ua, srv: srv, cli: cli, port: port, rtp: rtp, sipSocket: pc,
		dcc: sipgo.NewDialogClientCache(cli, contact), dsc: sipgo.NewDialogServerCache(cli, contact),
		byeGot: make(chan struct{}, 4), incoming: make(chan *sipgo.DialogServerSession, 4),
		messages: make(chan *sip.Request, 16)}
	p.handle()
	t.Cleanup(func() { rtp.Close(); pc.Close(); ua.Close() })
	return p
}

// handle sets up the phone's answers to the server's requests.
func (p *testPhone) handle() {
	srv := p.srv
	srv.OnMessage(func(req *sip.Request, tx sip.ServerTransaction) {
		time.Sleep(time.Duration(p.msgDelay.Load()))
		code := int(p.msgCode.Load())
		if code == 0 {
			code = 200
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, code, "Test", nil))
		if code == 200 {
			p.messages <- req
		} else {
			p.refused.Store(req)
		}
	})
	srv.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		if p.dcc.ReadBye(req, tx) != nil {
			_ = p.dsc.ReadBye(req, tx)
		}
		p.byeGot <- struct{}{}
	})
	srv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) { _ = p.dsc.ReadAck(req, tx) })
	srv.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		dlg, err := p.dsc.ReadInvite(req, tx)
		if err != nil {
			return
		}
		_ = dlg.Respond(180, "Ringing", nil)
		p.incoming <- dlg
		<-dlg.Context().Done()
	})
}

func (p *testPhone) sdp() []byte {
	port := p.rtp.LocalAddr().(*net.UDPAddr).Port
	profile, crypto := "RTP/AVP", ""
	if p.key != nil {
		profile, crypto = "RTP/SAVP", "a=crypto:"+p.key.String()+"\r\n"
	}
	return []byte(fmt.Sprintf("v=0\r\no=pixel 1 1 IN IP4 %s\r\ns=Talk\r\nc=IN IP4 %s\r\nt=0 0\r\n"+
		"m=audio %d %s 96 9 0 101\r\na=rtpmap:96 opus/48000/2\r\na=rtpmap:101 telephone-event/8000\r\n"+
		"a=fmtp:101 0-15\r\n%sa=sendrecv\r\n", p.ip, p.ip, port, profile, crypto))
}

// uri returns a SIP URI on the server for the phone's transport.
func (p *testPhone) uri(srvAddr, user string) sip.Uri {
	host, portStr, _ := net.SplitHostPort(srvAddr)
	port, _ := strconv.Atoi(portStr)
	u := sip.Uri{Scheme: "sip", User: user, Host: host, Port: port}
	if p.tls {
		u.UriParams = sip.NewParams()
		u.UriParams.Add("transport", "tls")
	}
	return u
}

func (p *testPhone) expires() int {
	if p.unreg {
		return 0
	}
	return 600
}

func (p *testPhone) register(srvAddr, pass string) (*sip.Response, error) {
	host, _, _ := net.SplitHostPort(srvAddr)
	req := sip.NewRequest(sip.REGISTER, p.uri(srvAddr, ""))
	if p.tls {
		req.SetTransport("TLS")
	}
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: p.user, Host: host}})
	from := &sip.FromHeader{Address: sip.Uri{Scheme: "sip", User: p.user, Host: host}, Params: sip.NewParams()}
	from.Params.Add("tag", sip.GenerateTagN(8))
	req.AppendHeader(from)
	contact := &sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: p.user, Host: p.ip, Port: p.port}}
	if p.tls || len(p.pn) > 0 {
		contact.Address.UriParams = sip.NewParams()
	}
	if p.tls {
		contact.Address.UriParams.Add("transport", "tls")
	}
	for _, kv := range p.pn {
		contact.Address.UriParams.Add(kv.K, kv.V)
	}
	if p.instance != "" {
		contact.Params = sip.NewParams()
		contact.Params.Add("+sip.instance", p.instance)
	}
	req.AppendHeader(contact)
	req.AppendHeader(sip.NewHeader("Expires", strconv.Itoa(p.expires())))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := p.cli.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 401 {
		return res, nil
	}
	return p.cli.DoDigestAuth(ctx, req, res, sipgo.DigestAuth{Username: p.user, Password: pass})
}

// call sends an INVITE to number and returns the dialog and the codes of the
// provisional responses.
func (p *testPhone) call(srvAddr, number string) (*sipgo.DialogClientSession, []int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	dlg, err := p.dcc.Invite(ctx, p.uri(srvAddr, number), p.sdp(),
		sip.NewHeader("Content-Type", "application/sdp"))
	if err != nil {
		return nil, nil, err
	}
	var codes []int
	var mu sync.Mutex
	err = dlg.WaitAnswer(ctx, sipgo.AnswerOptions{Username: p.user, Password: testPass, OnResponse: func(r *sip.Response) error {
		mu.Lock()
		codes = append(codes, r.StatusCode)
		mu.Unlock()
		return nil
	}})
	if err != nil {
		return dlg, codes, err
	}
	return dlg, codes, dlg.Ack(ctx)
}

// talk sends a G.722 tone to the server's RTP (from the SDP) and returns the
// RMS of what it received.
func (p *testPhone) talk(remoteSDP []byte, dur time.Duration, dtmfDigit int) float64 {
	a, err := parseSDP(remoteSDP)
	if err != nil {
		p.t.Fatalf("server SDP: %v", err)
	}
	f, ok := a.chooseFirstKnown([]string{"G722"})
	if !ok {
		p.t.Fatalf("the server did not choose G722:\n%s", remoteSDP)
	}
	dst := &net.UDPAddr{IP: a.IP, Port: a.Port}
	// SRTP: we send under our key and open the server's packets with the key
	// of its line with our tag (its answer, or the line of its offer we took).
	var tx, rx *srtp.Context
	if p.key != nil {
		for _, c := range a.Crypto {
			if c.Tag == p.key.Tag && c.Suite == p.key.Suite {
				rx, _ = c.Context()
			}
		}
		if rx == nil || !a.savp() {
			p.t.Fatalf("the server's SDP has no %s key with tag %d in RTP/SAVP:\n%s", p.key.Suite.Name, p.key.Tag, remoteSDP)
		}
		tx, _ = p.key.Context()
	}
	protect := func(pkt []byte) []byte {
		if tx == nil {
			return pkt
		}
		out, err := tx.Protect(nil, pkt)
		if err != nil {
			p.t.Errorf("SRTP protect: %v", err)
		}
		return out
	}
	enc := g722.NewEncoder()
	dec := g722.NewDecoder()
	var got []int16
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		_ = p.rtp.SetReadDeadline(time.Now().Add(dur + 700*time.Millisecond))
		for {
			n, _, err := p.rtp.ReadFromUDP(buf)
			if err != nil {
				return
			}
			data := buf[:n]
			if rx != nil {
				if data, err = rx.Unprotect(nil, data); err != nil {
					p.t.Errorf("SRTP from the server: %v", err)
					continue
				}
			}
			pkt, err := media.ParsePacket(data)
			if err != nil || int(pkt.PT) != f.PT {
				continue
			}
			out := make([]int16, len(pkt.Payload)*2)
			k := dec.Decode(out, pkt.Payload)
			mu.Lock()
			got = append(got, out[:k]...)
			mu.Unlock()
		}
	}()
	var ph float64
	seq, ts := p.seq, p.ts
	defer func() { p.seq, p.ts = seq, ts }()
	frames := int(dur / (20 * time.Millisecond))
	for i := 0; i < frames; i++ {
		pcm := tone(frameSamples16k, 16000, 440, 9000, &ph)
		pl := make([]byte, 170)
		n := enc.Encode(pl, pcm)
		pkt := make([]byte, 12+n)
		pkt[0], pkt[1] = 0x80, byte(f.PT)
		binary.BigEndian.PutUint16(pkt[2:], seq)
		binary.BigEndian.PutUint32(pkt[4:], ts)
		binary.BigEndian.PutUint32(pkt[8:], 0x1234)
		copy(pkt[12:], pl[:n])
		_, _ = p.rtp.WriteToUDP(protect(pkt), dst)
		if dtmfDigit >= 0 && i == frames/2 {
			// The event takes the next sequence number, as on a real phone (SRTP
			// would take a jump for a replay of everything after it).
			seq++
			ev := make([]byte, 16)
			ev[0], ev[1] = 0x80, byte(a.dtmfPT())
			binary.BigEndian.PutUint16(ev[2:], seq)
			binary.BigEndian.PutUint32(ev[4:], ts)
			binary.BigEndian.PutUint32(ev[8:], 0x1234)
			ev[12] = byte(dtmfDigit)
			_, _ = p.rtp.WriteToUDP(protect(ev), dst)
		}
		seq++
		ts += 160
		time.Sleep(20 * time.Millisecond)
	}
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(got) < 16000 {
		return 0
	}
	return rms(got[len(got)/2:])
}

func TestSIPRegisterAuth(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	ph := newTestPhone(t)
	res, err := ph.register(rig.srvAddr, "wrong-password")
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 403 {
		t.Fatalf("wrong password: %d, want 403 (on a 401 Linphone retries over and over)", res.StatusCode)
	}
	if len(rig.lan.reg.active()) != 0 {
		t.Fatal("a binding with a wrong password")
	}
	res, err = ph.register(rig.srvAddr, testPass)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("registration: %v %v", res, err)
	}
	if b := rig.lan.reg.active(); len(b) != 1 || b[0].user != "pixel" {
		t.Fatalf("bindings: %+v", b)
	}
}

// rawRegister sends one REGISTER from a socket of its own on src (a test
// phone sends from 127.0.0.1, whatever its ip) and returns the answer.
func rawRegister(t *testing.T, srvAddr, src, auth string) string {
	t.Helper()
	srv, err := net.ResolveUDPAddr("udp4", srvAddr)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(src)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	port := c.LocalAddr().(*net.UDPAddr).Port
	m := "REGISTER sip:127.0.0.1 SIP/2.0\r\n" +
		fmt.Sprintf("Via: SIP/2.0/UDP %s:%d;branch=%s;rport\r\n", src, port, sip.GenerateBranch()) +
		"Max-Forwards: 70\r\n" +
		"From: <sip:pixel@127.0.0.1>;tag=" + sip.GenerateTagN(8) + "\r\n" +
		"To: <sip:pixel@127.0.0.1>\r\n" +
		"Call-ID: " + sip.GenerateTagN(16) + "\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		fmt.Sprintf("Contact: <sip:pixel@%s:%d>\r\n", src, port)
	if auth != "" {
		m += "Authorization: " + auth + "\r\n"
	}
	if _, err := c.WriteToUDP([]byte(m+"Content-Length: 0\r\n\r\n"), srv); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("no answer to %s: %v", src, err)
	}
	return string(buf[:n])
}

// Packets without a nonce of ours do not count against the address they
// claim to come from; wrong passwords under our nonce still do.
func TestSIPFailuresNeedOurNonce(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	digest := func(challenge, pass string) string {
		_, rest, _ := strings.Cut(challenge, "Digest ")
		line, _, _ := strings.Cut(rest, "\r\n")
		p := parseDigestParams(line)
		ha1 := md5hex("pixel:" + p["realm"] + ":" + pass)
		ha2 := md5hex("REGISTER:sip:127.0.0.1")
		resp := md5hex(ha1 + ":" + p["nonce"] + ":00000001:abc:auth:" + ha2)
		return fmt.Sprintf(`Digest username="pixel", realm="%s", nonce="%s", uri="sip:127.0.0.1", response="%s", algorithm=MD5, cnonce="abc", qop=auth, nc=00000001`,
			p["realm"], p["nonce"], resp)
	}
	const phone, guesser = "127.0.0.77", "127.0.0.90"
	for i := 0; i < 2*authFailLimit; i++ {
		if res := rawRegister(t, rig.srvAddr, phone, "Basic eA=="); !strings.HasPrefix(res, "SIP/2.0 401") {
			t.Fatalf("packet %d without a nonce: %.40q, want a new challenge", i, res)
		}
	}
	if rig.lan.auth.blocked(phone) {
		t.Fatal("packets without a nonce blocked the address")
	}
	if res := rawRegister(t, rig.srvAddr, phone, digest(rawRegister(t, rig.srvAddr, phone, ""), testPass)); !strings.HasPrefix(res, "SIP/2.0 200") {
		t.Fatalf("the right password after them: %.40q", res)
	}
	challenge := rawRegister(t, rig.srvAddr, guesser, "")
	for i := 0; i < authFailLimit; i++ {
		if res := rawRegister(t, rig.srvAddr, guesser, digest(challenge, "wrong")); !strings.HasPrefix(res, "SIP/2.0 403") {
			t.Fatalf("wrong password %d: %.40q", i, res)
		}
	}
	if !rig.lan.auth.blocked(guesser) {
		t.Fatal("wrong passwords under our nonce did not block the address")
	}
	if res := rawRegister(t, rig.srvAddr, guesser, digest(challenge, testPass)); !strings.HasPrefix(res, "SIP/2.0 403") {
		t.Fatalf("the right password from a blocked address: %.40q", res)
	}
}

// After a restart Linphone comes from a new port with the same +sip.instance:
// the old binding goes at once instead of hanging around for up to an hour
// (calls would go to the dead address as well). Another device of the same
// login keeps its own binding.
func TestSIPRegisterSameDeviceNewPort(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	const dev = `"<urn:uuid:0A1B2C3D-1111-2222-3333-444455556666>"`
	old, cur, other := newTestPhone(t), newTestPhone(t), newTestPhone(t)
	old.instance, cur.instance = dev, dev
	other.instance = `"<urn:uuid:99999999-1111-2222-3333-444455556666>"`
	for _, p := range []*testPhone{old, cur} {
		if res, err := p.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
			t.Fatalf("registration: %v %v", res, err)
		}
	}
	if b := rig.lan.reg.forUser("pixel"); len(b) != 1 || b[0].contact.Port != cur.port {
		t.Fatalf("after an app restart the bindings are %+v, want one from port %d", b, cur.port)
	}
	res, err := other.register(rig.srvAddr, testPass)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("registration of the second device: %v %v", res, err)
	}
	if n := len(res.GetHeaders("Contact")); n != 2 {
		t.Fatalf("%d Contacts in the 200 OK, want 2 (the current phone and the second device)", n)
	}
}

// sipgo does not send UDP datagrams larger than 1300 bytes. Three other
// bindings with Linphone push parameters (~430 bytes each) made the 200 OK to
// a REGISTER 1.7 KB long: the reply got lost and the phone sent REGISTERs in
// bursts. The phone's own binding is always in the reply, and first; the
// others go in while they fit.
func TestSIPRegisterResponseFitsUDP(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	linphone := func(port int) sip.Uri {
		var u sip.Uri
		s := fmt.Sprintf("sip:pixel@192.168.8.137:%d;pn-prid=%s:voip&%s:remote;pn-provider=apns;"+
			"pn-param=ABCD1234.org.linphone.phone.voip&remote;pn-silent=1;pn-timeout=0;pn-msg-str=IM_MSG;"+
			"pn-call-str=IC_MSG;pn-groupchat-str=GC_MSG;pn-call-snd=notes_of_the_optimistic.caf;pn-msg-snd=msg.caf;transport=udp",
			port, strings.Repeat("A", 64), strings.Repeat("b", 64))
		if err := sip.ParseUri(s, &u); err != nil {
			t.Fatal(err)
		}
		return u
	}
	exp := time.Now().Add(time.Hour)
	for _, port := range []int{54448, 50426, 52197} {
		rig.lan.reg.update(binding{user: "pixel", contact: linphone(port), source: fmt.Sprintf("192.168.8.137:%d", port), transport: "udp", expires: exp})
	}
	p := newTestPhone(t)
	res, err := p.register(rig.srvAddr, testPass)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("registration with three long bindings of other devices: %v %v", res, err)
	}
	cs := res.GetHeaders("Contact")
	if len(cs) == 0 || !strings.Contains(cs[0].Value(), fmt.Sprintf(":%d", p.port)) {
		t.Fatalf("the phone's own binding must come first: %v", cs)
	}
	if len(cs) == 4 {
		t.Errorf("all 4 Contacts cannot have fit into a UDP datagram")
	}
	if n, limit := len(res.String()), sip.UDPMTUSize-200; n > limit {
		t.Errorf("reply of %d bytes exceeds the UDP limit %d", n, limit)
	}
	if h := res.GetHeader("Expires"); h == nil || h.Value() != "600" {
		t.Errorf("Expires in the reply: %v, want 600", h)
	}
}

func TestSIPEchoCall(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	ph := newTestPhone(t)
	if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration: %v %v", res, err)
	}
	dlg, _, err := ph.call(rig.srvAddr, "600")
	if err != nil {
		t.Fatalf("echo call: %v", err)
	}
	r := ph.talk(dlg.InviteResponse.Body(), 1500*time.Millisecond, -1)
	t.Logf("echo through AMR-WB 12.65: RMS %.0f (input ≈ 6364)", r)
	if r < 1500 {
		t.Fatalf("the echo did not come back: RMS %.0f", r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := dlg.Bye(ctx); err != nil {
		t.Fatalf("BYE: %v", err)
	}
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released after BYE")
}

func TestSIPOutgoingBridge(t *testing.T) {
	cfg := &Config{}
	rig := newTestRig(t, cfg, true)
	call := newFakeIMSCall("out-1", CallOutgoing)
	d := &fakeDialer{mgr: rig.mgr, call: call}
	rig.mgr.dialer = d
	ph := newTestPhone(t)
	if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration: %v %v", res, err)
	}
	dlg, codes, err := ph.call(rig.srvAddr, "07700900456")
	if err != nil {
		t.Fatalf("outgoing: %v (codes %v)", err, codes)
	}
	if to, _ := d.to.Load().(string); to != "+447700900456" {
		t.Fatalf("Dial went to %q", to)
	}
	if !containsInt(codes, 180) {
		t.Fatalf("the phone heard no ringback (180): %v", codes)
	}
	r := ph.talk(dlg.InviteResponse.Body(), 1500*time.Millisecond, 5)
	t.Logf("phone → G.722 → AMR-WB → network (loop) → AMR-WB → G.722 → phone: RMS %.0f", r)
	if r < 1500 {
		t.Fatalf("no audio through the bridge: RMS %.0f", r)
	}
	select {
	case dg := <-call.dtmf:
		if dg != "5" {
			t.Fatalf("DTMF %q", dg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DTMF did not reach the network")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := dlg.Bye(ctx); err != nil {
		t.Fatalf("BYE: %v", err)
	}
	waitFor(t, call.hungup.Load, "the network call was not hung up after the phone's BYE")
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// TestSIPStuckHangupReleasesLine covers a network that does not confirm the
// BYE (a live case, 03.11 18:46): the line is released on a timeout and the
// next call goes through.
func TestSIPStuckHangupReleasesLine(t *testing.T) {
	rig := newTestRig(t, &Config{}, true)
	call := newFakeIMSCall("out-stuck", CallOutgoing)
	call.hangBlock = make(chan struct{})
	defer close(call.hangBlock)
	rig.mgr.dialer = &fakeDialer{mgr: rig.mgr, call: call}
	ph := newTestPhone(t)
	if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration: %v %v", res, err)
	}
	dlg, _, err := ph.call(rig.srvAddr, "+447700900456")
	if err != nil {
		t.Fatalf("outgoing: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := dlg.Bye(ctx); err != nil {
		t.Fatalf("BYE: %v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for rig.mgr.current() != nil {
		if time.Now().After(deadline) {
			t.Fatal("the line got stuck after a hung Hangup")
		}
		time.Sleep(100 * time.Millisecond)
	}
	// The next call does not get 486.
	call2 := newFakeIMSCall("out-next", CallOutgoing)
	rig.mgr.dialer = &fakeDialer{mgr: rig.mgr, call: call2}
	dlg2, _, err := ph.call(rig.srvAddr, "+447700900456")
	if err != nil {
		t.Fatalf("the next call after the hang: %v", err)
	}
	_ = dlg2.Bye(ctx)
}

func TestSIPOutgoingPolicyAndBusy(t *testing.T) {
	rig := newTestRig(t, &Config{}, true)
	call := newFakeIMSCall("out-2", CallOutgoing)
	rig.mgr.dialer = &fakeDialer{mgr: rig.mgr, call: call, failCode: 486}
	ph := newTestPhone(t)
	if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration: %v %v", res, err)
	}
	_, _, err := ph.call(rig.srvAddr, "+15551234567")
	var de *sipgo.ErrDialogResponse
	if !errors.As(err, &de) || de.Res.StatusCode != 403 {
		t.Fatalf("barred destination: %v", err)
	}
	_, _, err = ph.call(rig.srvAddr, "+441111111")
	if !errors.As(err, &de) || de.Res.StatusCode != 486 {
		t.Fatalf("busy in the network: %v", err)
	}
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

func TestSIPIncomingFork(t *testing.T) {
	cfg := &Config{Allow: []string{"+447700900456"}}
	rig := newTestRig(t, cfg, true)
	ph := newTestPhone(t)
	if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration: %v %v", res, err)
	}
	// A stranger's number: 603, the phone does not ring.
	stranger := newFakeIMSCall("in-0", CallIncoming)
	rig.mgr.incomingFromNetwork(stranger, "+447700900000")
	if stranger.rejected.Load() != rejectDecline {
		t.Fatalf("stranger: %d", stranger.rejected.Load())
	}
	call := newFakeIMSCall("in-1", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	var dlg *sipgo.DialogServerSession
	select {
	case dlg = <-ph.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE did not reach the phone")
	}
	if from := dlg.InviteRequest.From(); from == nil || from.Address.User != "+447700900456" {
		t.Fatalf("caller number on the phone: %v", dlg.InviteRequest.From())
	}
	if call.answered.Load() {
		t.Fatal("the network was answered before pickup")
	}
	if err := dlg.RespondSDP(ph.sdp()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, call.answered.Load, "the network was not answered after pickup")
	r := ph.talk(dlg.InviteRequest.Body(), 1500*time.Millisecond, -1)
	t.Logf("incoming: audio through the bridge RMS %.0f", r)
	if r < 1500 {
		t.Fatalf("no incoming audio came through: RMS %.0f", r)
	}
	// The other party hangs up → the phone gets a BYE.
	rig.mgr.onIMSEvent(call, CallStateEnded)
	select {
	case <-ph.byeGot:
	case <-time.After(3 * time.Second):
		t.Fatal("no BYE reached the phone")
	}
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

func TestSIPIncomingPhoneHangsUp(t *testing.T) {
	rig := newTestRig(t, &Config{IncomingAll: true}, true)
	ph := newTestPhone(t)
	if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration: %v %v", res, err)
	}
	call := newFakeIMSCall("in-3", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900123")
	var dlg *sipgo.DialogServerSession
	select {
	case dlg = <-ph.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE did not reach the phone")
	}
	if err := dlg.RespondSDP(ph.sdp()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, call.answered.Load, "the network was not answered")
	time.Sleep(200 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := dlg.Bye(ctx); err != nil {
		t.Fatalf("BYE from the phone: %v", err)
	}
	waitFor(t, call.hungup.Load, "the network call was not hung up after the phone's BYE")
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

func TestSIPIncomingCallerCancels(t *testing.T) {
	rig := newTestRig(t, &Config{IncomingAll: true}, true)
	ph := newTestPhone(t)
	if res, err := ph.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration: %v %v", res, err)
	}
	call := newFakeIMSCall("in-4", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	var dlg *sipgo.DialogServerSession
	select {
	case dlg = <-ph.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE did not reach the phone")
	}
	// The caller hangs up while the phone is ringing → CANCEL to the phone.
	rig.mgr.onIMSEvent(call, CallStateEnded)
	select {
	case <-dlg.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the phone keeps ringing after the caller cancelled")
	}
	if call.answered.Load() {
		t.Fatal("the network was answered after the cancel")
	}
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

func TestSIPIncomingNoPhones(t *testing.T) {
	rig := newTestRig(t, &Config{IncomingAll: true}, true)
	call := newFakeIMSCall("in-2", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	waitFor(t, func() bool { return call.rejected.Load() == rejectDecline }, "without phones want 603")
}

// --- Phone-to-phone calls ---

func TestSIPInternalCall(t *testing.T) {
	rig := newTestRig(t, &Config{IncomingAll: true}, false) // no network needed
	a, b := newTestPhoneUser(t, "127.0.0.1", "pixel"), newTestPhoneUser(t, "127.0.0.1", "iphone")
	for _, p := range []*testPhone{a, b} {
		if res, err := p.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
			t.Fatalf("registration %s: %v %v", p.user, res, err)
		}
	}
	type callRes struct {
		dlg   *sipgo.DialogClientSession
		codes []int
		err   error
	}
	done := make(chan callRes, 1)
	go func() {
		d, c, err := a.call(rig.srvAddr, "IPhone") // login is case-insensitive
		done <- callRes{d, c, err}
	}()
	var in *sipgo.DialogServerSession
	select {
	case in = <-b.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE did not reach the second phone")
	}
	if from := in.InviteRequest.From(); from == nil || from.Address.User != "pixel" {
		t.Fatalf("caller on the second phone: %v", in.InviteRequest.From())
	}
	if err := in.RespondSDP(b.sdp()); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("call: %v (codes %v)", r.err, r.codes)
	}
	if !containsInt(r.codes, 180) {
		t.Fatalf("the caller heard no ringback (180): %v", r.codes)
	}
	var ra, rb float64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); ra = a.talk(r.dlg.InviteResponse.Body(), 1500*time.Millisecond, -1) }()
	go func() { defer wg.Done(); rb = b.talk(in.InviteRequest.Body(), 1500*time.Millisecond, -1) }()
	wg.Wait()
	t.Logf("phone ↔ phone: the caller hears RMS %.0f, the second %.0f", ra, rb)
	if ra < 1500 || rb < 1500 {
		t.Fatalf("audio between the phones: caller RMS %.0f, second RMS %.0f", ra, rb)
	}
	// The line is busy with an internal call: an incoming call from the network gets 600.
	call := newFakeIMSCall("in-int", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	if call.rejected.Load() != rejectBusy {
		t.Fatalf("incoming during an internal call: %d, want 600", call.rejected.Load())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := r.dlg.Bye(ctx); err != nil {
		t.Fatalf("caller's BYE: %v", err)
	}
	select {
	case <-b.byeGot:
	case <-time.After(3 * time.Second):
		t.Fatal("the BYE did not reach the second phone")
	}
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// deadUDPAddr returns an address nobody listens on: a port that has just been released.
func deadUDPAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()
	return addr
}

// A dead binding (the phone left, the registration has not expired) must not
// hold up the call: "Decline" on the live device ends it at once, "busy"
// after a short pause, not after the 32 s transaction timeout towards the
// dead address (the iPhone case of 4.11).
func TestSIPInternalCallDeadDevice(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
	}{{"decline", 603}, {"busy", 486}} {
		t.Run(tc.name, func(t *testing.T) {
			rig := newTestRig(t, &Config{IncomingAll: true}, false)
			rig.mgr.forkGrace = time.Second
			a, b := newTestPhoneUser(t, "127.0.0.1", "pixel"), newTestPhoneUser(t, "127.0.0.1", "iphone")
			for _, p := range []*testPhone{a, b} {
				if res, err := p.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
					t.Fatalf("registration %s: %v %v", p.user, res, err)
				}
			}
			dead := deadUDPAddr(t)
			var u sip.Uri
			if err := sip.ParseUri("sip:iphone@"+dead, &u); err != nil {
				t.Fatal(err)
			}
			rig.lan.reg.update(binding{user: "iphone", contact: u, source: dead, transport: "udp", expires: time.Now().Add(time.Hour)})
			if n := len(rig.lan.reg.forUser("iphone")); n != 2 {
				t.Fatalf("iphone bindings: %d, want 2", n)
			}
			start := time.Now()
			done := make(chan error, 1)
			go func() {
				_, _, err := a.call(rig.srvAddr, "iphone")
				done <- err
			}()
			var in *sipgo.DialogServerSession
			select {
			case in = <-b.incoming:
			case <-time.After(3 * time.Second):
				t.Fatal("the INVITE did not reach the live device")
			}
			if err := in.Respond(tc.code, "No", nil); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if finalCode(err) != tc.code {
					t.Fatalf("the caller got %d (%v), want %d", finalCode(err), err, tc.code)
				}
			case <-time.After(6 * time.Second):
				t.Fatal("the caller waits longer than 6 s: the dead binding holds up the call")
			}
			// 603 at once; 486 after forkGrace (1 s here), but not after the call timeout.
			limit := 2 * time.Second
			if tc.code == 486 {
				limit = 3 * time.Second
			}
			if d := time.Since(start); d > limit {
				t.Errorf("response %d reached the caller after %v, limit %v", tc.code, d, limit)
			}
			waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
		})
	}
}

// finalCode returns the rejection code from a WaitAnswer error (0 when it is
// not a SIP response).
func finalCode(err error) int {
	var de *sipgo.ErrDialogResponse
	if errors.As(err, &de) && de.Res != nil {
		return de.Res.StatusCode
	}
	return 0
}

func TestSIPInternalCallByExtOfflineBusy(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	a := newTestPhoneUser(t, "127.0.0.1", "pixel")
	if res, err := a.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration: %v %v", res, err)
	}
	// The second phone is offline: 480.
	if _, _, err := a.call(rig.srvAddr, "202"); finalCode(err) != 480 {
		t.Fatalf("call to a phone that is off: %v", err)
	}
	// To oneself: 486.
	if _, _, err := a.call(rig.srvAddr, "201"); finalCode(err) != 486 {
		t.Fatalf("call to oneself: %v", err)
	}
	// By short number; the second phone rejects, so the caller gets 486.
	b := newTestPhoneUser(t, "127.0.0.1", "iphone")
	if res, err := b.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration of iphone: %v %v", res, err)
	}
	errc := make(chan error, 1)
	go func() {
		_, _, err := a.call(rig.srvAddr, "202")
		errc <- err
	}()
	select {
	case in := <-b.incoming:
		_ = in.Respond(486, "Busy Here", nil)
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE by short number did not arrive")
	}
	if err := <-errc; finalCode(err) != 486 {
		t.Fatalf("rejected internal call: %v", err)
	}
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

func TestValidExtAndPhoneFor(t *testing.T) {
	for _, bad := range []string{"1", "112", "911", "999", "0123", "1234567", "2a", "600"} {
		if validExt(bad, "600") == nil {
			t.Errorf("short number %q accepted", bad)
		}
	}
	for _, good := range []string{"20", "201", "777", "9999"} {
		if err := validExt(good, "600"); err != nil {
			t.Errorf("short number %q rejected: %v", good, err)
		}
	}
	sc := SIPConfig{Accounts: []SIPAccount{{User: "pixel", Ext: "201"}, {User: "iphone"}}}
	for target, want := range map[string]string{"pixel": "pixel", "PIXEL": "pixel", "201": "pixel", "iphone": "iphone"} {
		if got, ok := sc.phoneFor(target); !ok || got != want {
			t.Errorf("phoneFor(%q) = %q %v", target, got, ok)
		}
	}
	for _, target := range []string{"202", "+447700900456", "07700900456", ""} {
		if got, ok := sc.phoneFor(target); ok {
			t.Errorf("phoneFor(%q) = %q, but the number is not internal", target, got)
		}
	}
	dup := SIPConfig{Listen: "127.0.0.1:5060", Accounts: []SIPAccount{
		{User: "a", Password: "0123456789a", Ext: "201"}, {User: "b", Password: "0123456789b", Ext: "201"}}}.withDefaults()
	if dup.validate() == nil {
		t.Error("a duplicate short number accepted")
	}
}

// --- Requests inside a dialog belong to that dialog ---

// inDialogRequest sends a request with the Call-ID and tags of a dialog the
// way a host on the Wi-Fi would: made up, or copied from a dialog it has
// seen on the air, from a port of its own. A 401/407 is answered with the
// phone's password.
func (p *testPhone) inDialogRequest(method sip.RequestMethod, srvAddr, target, callID, fromTag, toTag, contentType string, body []byte) (*sip.Response, error) {
	host, _, _ := net.SplitHostPort(srvAddr)
	req := sip.NewRequest(method, p.uri(srvAddr, target))
	from := &sip.FromHeader{Address: sip.Uri{Scheme: "sip", User: p.user, Host: host}, Params: sip.NewParams()}
	from.Params.Add("tag", fromTag)
	to := &sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: target, Host: host}, Params: sip.NewParams()}
	to.Params.Add("tag", toTag)
	cid := sip.CallIDHeader(callID)
	req.AppendHeader(from)
	req.AppendHeader(to)
	req.AppendHeader(&cid)
	if body != nil {
		req.AppendHeader(sip.NewHeader("Content-Type", contentType))
		req.SetBody(body)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := p.cli.Do(ctx, req)
	if err == nil && (res.StatusCode == 401 || res.StatusCode == 407) {
		res, err = p.cli.DoDigestAuth(ctx, req, res, sipgo.DigestAuth{Username: p.user, Password: testPass})
	}
	return res, err
}

// dialogOf returns the Call-ID and the tags of the phone's dialog, as a
// listener on the Wi-Fi reads them off a UDP call.
func dialogOf(dlg *sipgo.DialogClientSession) (callID, fromTag, toTag string) {
	fromTag, _ = dlg.InviteRequest.From().Params.Get("tag")
	toTag, _ = dlg.InviteResponse.To().Params.Get("tag")
	return dlg.InviteRequest.CallID().Value(), fromTag, toTag
}

// A re-INVITE or an UPDATE is acted on only inside a dialog of the current
// call and only from the address of that dialog's phone: anything else gets
// 481 and moves nothing. Otherwise any host on the Wi-Fi could point the
// audio of the running call at itself with one packet (and, on a TLS call,
// get our SRTP key back).
func TestSIPReInviteOutsideDialogRefused(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	ph := newTestPhone(t)
	registerOK(t, ph, rig.srvAddr)
	dlg, _, err := ph.call(rig.srvAddr, "600")
	if err != nil {
		t.Fatalf("echo call: %v", err)
	}
	lc := rig.mgr.current()
	if lc == nil {
		t.Fatal("no call on the line")
	}
	remote := func() string {
		lc.leg.mu.Lock()
		defer lc.leg.mu.Unlock()
		return lc.leg.remote.String()
	}
	before := remote()
	stranger := newTestPhoneUser(t, "127.0.0.1", "iphone") // another port, not even registered
	for _, method := range []sip.RequestMethod{sip.INVITE, sip.UPDATE} {
		// A dialog that does not exist.
		res, err := stranger.inDialogRequest(method, rig.srvAddr, "600", "made-up@127.0.0.1", "f1", "t1", "application/sdp", stranger.sdp())
		if err != nil || res.StatusCode != 481 {
			t.Fatalf("%s in a made-up dialog: %v %v, want 481", method, res, err)
		}
		// The real dialog, read off the air, from another address.
		callID, fromTag, toTag := dialogOf(dlg)
		res, err = stranger.inDialogRequest(method, rig.srvAddr, "600", callID, fromTag, toTag, "application/sdp", stranger.sdp())
		if err != nil || res.StatusCode != 481 {
			t.Fatalf("%s with the tags of the real dialog from another address: %v %v, want 481", method, res, err)
		}
	}
	if got := remote(); got != before {
		t.Fatalf("the RTP destination moved from %s to %s", before, got)
	}
	if r := ph.talk(dlg.InviteResponse.Body(), time.Second, -1); r < 1500 {
		t.Fatalf("no echo after the refused re-INVITEs: RMS %.0f", r)
	}
	// The phone's own re-INVITE and UPDATE in the dialog keep working.
	if res := reinvite(t, dlg, ph.sdp()); res.StatusCode != 200 {
		t.Fatalf("the phone's re-INVITE: %d", res.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	upd := sip.NewRequest(sip.UPDATE, dlg.InviteResponse.Contact().Address)
	upd.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	upd.SetBody(ph.sdp())
	if res, err := dlg.Do(ctx, upd); err != nil || res.StatusCode != 200 {
		t.Fatalf("the phone's UPDATE: %v %v", res, err)
	}
	if r := ph.talk(dlg.InviteResponse.Body(), time.Second, -1); r < 1500 {
		t.Fatalf("no echo after the phone's own re-offers: RMS %.0f", r)
	}
	bye(t, dlg)
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// The address of a phone: its whole address over UDP, its host over TCP and
// TLS, where the port dies with the connection.
func TestFromPhone(t *testing.T) {
	phone := []string{"192.168.8.20:5070", "192.168.8.20:41000"}
	for _, tc := range []struct {
		src, transport string
		want           bool
	}{
		{"192.168.8.20:5070", "UDP", true},
		{"192.168.8.20:41000", "udp", true},
		{"192.168.8.20:6000", "UDP", false},
		{"192.168.8.21:5070", "UDP", false},
		{"192.168.8.20:6000", "TLS", true},
		{"192.168.8.20:6000", "TCP", true},
		{"192.168.8.21:41000", "TLS", false},
		{"192.168.8.21:41000", "TCP", false},
	} {
		if got := fromPhone(tc.src, tc.transport, phone); got != tc.want {
			t.Errorf("%s over %s: %v, want %v", tc.src, tc.transport, got, tc.want)
		}
	}
}

// DTMF in an INFO reaches the network only from a dialog of the current
// call: another phone, signed in with its own password, cannot dial digits
// into the conversation.
func TestSIPInfoOutsideDialogRefused(t *testing.T) {
	rig := newTestRig(t, &Config{}, true)
	call := newFakeIMSCall("out-info", CallOutgoing)
	rig.mgr.dialer = &fakeDialer{mgr: rig.mgr, call: call}
	a, b := newTestPhoneUser(t, "127.0.0.1", "pixel"), newTestPhoneUser(t, "127.0.0.1", "iphone")
	registerOK(t, a, rig.srvAddr)
	registerOK(t, b, rig.srvAddr)
	dlg, _, err := a.call(rig.srvAddr, "+447700900456")
	if err != nil {
		t.Fatalf("outgoing: %v", err)
	}
	const dtmf = "Signal=5\r\nDuration=160\r\n"
	res, err := b.inDialogRequest(sip.INFO, rig.srvAddr, "+447700900456", "made-up@127.0.0.1", "f1", "t1", "application/dtmf-relay", []byte(dtmf))
	if err != nil || res.StatusCode != 481 {
		t.Fatalf("INFO from a phone outside the call: %v %v, want 481", res, err)
	}
	callID, fromTag, toTag := dialogOf(dlg)
	res, err = b.inDialogRequest(sip.INFO, rig.srvAddr, "+447700900456", callID, fromTag, toTag, "application/dtmf-relay", []byte(dtmf))
	if err != nil || res.StatusCode != 481 {
		t.Fatalf("INFO with the tags of the call from another phone: %v %v, want 481", res, err)
	}
	select {
	case d := <-call.dtmf:
		t.Fatalf("DTMF %q from outside the call reached the network", d)
	case <-time.After(300 * time.Millisecond):
	}
	// The phone in the call: 407, then 200, and the digit goes out.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	info := sip.NewRequest(sip.INFO, dlg.InviteResponse.Contact().Address)
	info.AppendHeader(sip.NewHeader("Content-Type", "application/dtmf-relay"))
	info.SetBody([]byte(dtmf))
	res, err = dlg.Do(ctx, info)
	if err == nil && res.StatusCode == 407 {
		res, err = a.cli.DoDigestAuth(ctx, info, res, sipgo.DigestAuth{Username: a.user, Password: testPass})
	}
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("INFO from the phone in the call: %v %v", res, err)
	}
	select {
	case d := <-call.dtmf:
		if d != "5" {
			t.Fatalf("DTMF %q", d)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the digit of the phone in the call did not reach the network")
	}
	bye(t, dlg)
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// In a call between two phones both dialogs are the call's: either phone
// may re-offer its leg.
func TestSIPInternalCallReInviteBothLegs(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	a, b := newTestPhoneUser(t, "127.0.0.1", "pixel"), newTestPhoneUser(t, "127.0.0.1", "iphone")
	registerOK(t, a, rig.srvAddr)
	registerOK(t, b, rig.srvAddr)
	done := make(chan *sipgo.DialogClientSession, 1)
	go func() {
		d, _, err := a.call(rig.srvAddr, "202")
		if err != nil {
			t.Errorf("internal call: %v", err)
		}
		done <- d
	}()
	var in *sipgo.DialogServerSession
	select {
	case in = <-b.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE did not reach the second phone")
	}
	if err := in.RespondSDP(b.sdp()); err != nil {
		t.Fatal(err)
	}
	dlg := <-done
	if dlg == nil {
		t.FailNow()
	}
	if res := reinvite(t, dlg, a.sdp()); res.StatusCode != 200 {
		t.Fatalf("re-INVITE of the caller: %d", res.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := sip.NewRequest(sip.INVITE, in.InviteRequest.Contact().Address)
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	req.SetBody(b.sdp())
	res, err := in.Do(ctx, req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("re-INVITE of the called phone: %v %v", res, err)
	}
	ack := sip.NewRequest(sip.ACK, in.InviteRequest.Contact().Address)
	_ = in.WriteRequest(ack)
	bye(t, dlg)
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

// TestSIPSmokeMudi runs against the live server on the Mudi (sip-test mode):
// registration, echo 600 through AMR-WB on the Mudi hardware, BYE,
// de-registration. Run with:
// MUDI_SIP_SMOKE=192.168.8.1:5060 MUDI_SIP_LOCAL=192.168.8.233 MUDI_SIP_PASS=… go test -run TestSIPSmokeMudi -v
func TestSIPSmokeMudi(t *testing.T) {
	srv, local, pass := os.Getenv("MUDI_SIP_SMOKE"), os.Getenv("MUDI_SIP_LOCAL"), os.Getenv("MUDI_SIP_PASS")
	if srv == "" || local == "" || pass == "" {
		t.Skip("MUDI_SIP_SMOKE/MUDI_SIP_LOCAL/MUDI_SIP_PASS are not set")
	}
	ph := newTestPhoneOn(t, local)
	res, err := ph.register(srv, pass)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("registration on the Mudi: %v %v", res, err)
	}
	defer func() {
		ph.unreg = true
		_, _ = ph.register(srv, pass)
	}()
	dlgCtx := func() (*sipgo.DialogClientSession, error) {
		host, portStr, _ := net.SplitHostPort(srv)
		port, _ := strconv.Atoi(portStr)
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		dlg, err := ph.dcc.Invite(ctx, sip.Uri{Scheme: "sip", User: "600", Host: host, Port: port}, ph.sdp(),
			sip.NewHeader("Content-Type", "application/sdp"))
		if err != nil {
			return nil, err
		}
		if err := dlg.WaitAnswer(ctx, sipgo.AnswerOptions{Username: "pixel", Password: pass}); err != nil {
			return dlg, err
		}
		return dlg, dlg.Ack(ctx)
	}
	dlg, err := dlgCtx()
	if err != nil {
		t.Fatalf("call to 600: %v", err)
	}
	r := ph.talk(dlg.InviteResponse.Body(), 3*time.Second, -1)
	t.Logf("echo from the Mudi (G.722 → AMR-WB 12.65 → G.722 on the Mudi hardware): RMS %.0f (input ≈ 6364)", r)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = dlg.Bye(ctx)
	if r < 1500 {
		t.Fatalf("the echo did not come back: RMS %.0f", r)
	}
}
