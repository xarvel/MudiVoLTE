package main

// SIP over TLS and SRTP for the phones: end-to-end over 127.0.0.1 with a
// "phone" that, like Linphone set up by QR code, opens one TLS connection,
// takes the server's requests through it and offers RTP/SAVP with its own
// key; and the rules of lan_srtp.go one by one.

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/xarvel/MudiVoLTE/volte/srtp"
)

// newTLSTestRig is newTestRig with TLS next to UDP and the certificate in a
// temporary directory.
func newTLSTestRig(t *testing.T, cfg *Config, withDialer bool) (*testRig, string) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		logger = slog.New(slog.NewTextHandler(testLogWriter{t}, nil))
	}
	dir := t.TempDir()
	sc := SIPConfig{
		Listen: "127.0.0.1:0", Transports: []string{"udp", "tls"},
		Accounts:  []SIPAccount{{User: "pixel", Password: testPass, Ext: "201"}, {User: "iphone", Password: testPass, Ext: "202"}},
		DialAllow: []string{"+44"}, DefaultCountry: "44", EchoExt: "600",
		RTPPortMin: 41400, RTPPortMax: 41600, RingSec: 5,
		TLSCertFile: filepath.Join(dir, "tls.crt"), TLSKeyFile: filepath.Join(dir, "tls.key"),
	}.withDefaults()
	mgr := newCallManager(cfg, sc, nil, logger)
	lan, err := startLANSIP(sc, mgr, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lan.Close)
	if lan.tlsPort == 0 {
		t.Fatal("no TLS port")
	}
	rig := &testRig{t: t, mgr: mgr, lan: lan, srvAddr: fmt.Sprintf("127.0.0.1:%d", lan.port)}
	return rig, fmt.Sprintf("127.0.0.1:%d", lan.tlsPort)
}

// newTLSTestPhone is a phone on TLS without a listening socket. suite nil:
// it offers plain RTP over TLS.
func newTLSTestPhone(t *testing.T, user string, suite *srtp.Suite) *testPhone {
	t.Helper()
	const ip = "127.0.0.1"
	ua, err := sipgo.NewUA(sipgo.WithUserAgent("test-phone-tls"), sipgo.WithUserAgentHostname(ip),
		sipgo.WithUserAgenTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := sipgo.NewServer(ua)
	cli, _ := sipgo.NewClient(ua, sipgo.WithClientHostname(ip))
	rtp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	// The Contact port is made up on purpose: the phone listens nowhere, and
	// the server must answer into its connection, not to the Contact.
	params := sip.NewParams()
	params.Add("transport", "tls")
	contact := sip.ContactHeader{Address: sip.Uri{Scheme: "sip", User: user, Host: ip, Port: 9, UriParams: params}}
	p := &testPhone{t: t, user: user, ip: ip, ua: ua, srv: srv, cli: cli, port: 9, rtp: rtp, tls: true,
		dcc: sipgo.NewDialogClientCache(cli, contact), dsc: sipgo.NewDialogServerCache(cli, contact),
		byeGot: make(chan struct{}, 4), incoming: make(chan *sipgo.DialogServerSession, 4),
		messages: make(chan *sip.Request, 16)}
	if suite != nil {
		k, err := srtp.NewCrypto(1, *suite)
		if err != nil {
			t.Fatal(err)
		}
		p.key = &k
	}
	p.handle()
	t.Cleanup(func() { rtp.Close(); ua.Close() })
	return p
}

func suitePtr(s srtp.Suite) *srtp.Suite { return &s }

func registerOK(t *testing.T, p *testPhone, addr string) {
	t.Helper()
	if res, err := p.register(addr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("registration of %s: %v %v", p.user, res, err)
	}
}

func bye(t *testing.T, d interface{ Bye(context.Context) error }) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := d.Bye(ctx); err != nil {
		t.Fatalf("BYE: %v", err)
	}
}

func TestTLSEchoWithSRTP(t *testing.T) {
	for _, s := range []srtp.Suite{srtp.AES128CMSHA1_80, srtp.AES256CMSHA1_80, srtp.AES128CMSHA1_32} {
		t.Run(s.Name, func(t *testing.T) {
			rig, tlsAddr := newTLSTestRig(t, &Config{}, false)
			ph := newTLSTestPhone(t, "pixel", suitePtr(s))
			registerOK(t, ph, tlsAddr)
			if got := rig.lan.secureUsers(); len(got) != 1 || got[0] != "pixel" {
				t.Fatalf("phones on TLS: %v", got)
			}
			dlg, _, err := ph.call(tlsAddr, "600")
			if err != nil {
				t.Fatalf("echo call over TLS: %v", err)
			}
			ans, err := parseSDP(dlg.InviteResponse.Body())
			if err != nil {
				t.Fatal(err)
			}
			if !ans.savp() || len(ans.Crypto) != 1 || ans.Crypto[0].Tag != 1 || ans.Crypto[0].Suite != s ||
				string(ans.Crypto[0].Key) == string(ph.key.Key) {
				t.Fatalf("the answer must be RTP/SAVP with our own %s key under tag 1:\n%s", s.Name, dlg.InviteResponse.Body())
			}
			if c := dlg.InviteResponse.Contact(); c == nil || !strings.Contains(c.Value(), "transport=tls") {
				t.Fatalf("Contact of the 200 OK must bring the phone back over TLS: %v", c)
			}
			r := ph.talk(dlg.InviteResponse.Body(), 1500*time.Millisecond, 3)
			t.Logf("echo over SRTP %s: RMS %.0f", s.Name, r)
			if r < 1500 {
				t.Fatalf("no echo over SRTP: RMS %.0f", r)
			}
			bye(t, dlg)
			waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released after BYE")
		})
	}
}

func TestTLSIncomingSRTPAndBye(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, true)
	ph := newTLSTestPhone(t, "pixel", suitePtr(srtp.AES128CMSHA1_80))
	registerOK(t, ph, tlsAddr)
	call := newFakeIMSCall("in-tls", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	var dlg *sipgo.DialogServerSession
	select {
	case dlg = <-ph.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE did not reach the phone over TLS")
	}
	if dlg.InviteRequest.Transport() != "TLS" {
		t.Fatalf("the INVITE came over %s", dlg.InviteRequest.Transport())
	}
	offer, err := parseSDP(dlg.InviteRequest.Body())
	if err != nil {
		t.Fatal(err)
	}
	if !offer.savp() || len(offer.Crypto) != 2 || offer.Crypto[0].Suite != srtp.AES128CMSHA1_80 || offer.Crypto[1].Suite != srtp.AES256CMSHA1_80 {
		t.Fatalf("our offer over TLS must be RTP/SAVP with two suites:\n%s", dlg.InviteRequest.Body())
	}
	if err := dlg.RespondSDP(ph.sdp()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, call.answered.Load, "the network was not answered after pickup")
	r := ph.talk(dlg.InviteRequest.Body(), 1500*time.Millisecond, -1)
	t.Logf("incoming over SRTP: RMS %.0f", r)
	if r < 1500 {
		t.Fatalf("no incoming audio over SRTP: RMS %.0f", r)
	}
	if lc := rig.mgr.current(); lc == nil || !lc.leg.secure() {
		t.Fatal("the leg of the call is not SRTP")
	}
	// The BYE of the server must go into the phone's connection: its Contact
	// port is made up.
	rig.mgr.onIMSEvent(call, CallStateEnded)
	select {
	case <-ph.byeGot:
	case <-time.After(3 * time.Second):
		t.Fatal("no BYE reached the phone through its TLS connection")
	}
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// The answer of a phone on TLS to our keys must carry a key of ours (the tag
// and the suite of one of our lines); a plain answer would leave the call
// without encryption, so it fails.
func TestTLSIncomingAnswerWithoutKeysFails(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, true)
	ph := newTLSTestPhone(t, "pixel", nil)
	ackGot := make(chan struct{}, 1)
	ph.srv.OnAck(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = ph.dsc.ReadAck(req, tx)
		select {
		case ackGot <- struct{}{}:
		default:
		}
	})
	registerOK(t, ph, tlsAddr)
	call := newFakeIMSCall("in-tls-plain", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	var dlg *sipgo.DialogServerSession
	select {
	case dlg = <-ph.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE did not reach the phone")
	}
	// The daemon sends ACK then BYE, but sipgo dispatches them in separate
	// goroutines: BYE can end the dialog before RespondSDP observes the ACK.
	// Check both requests themselves, not the helper's transient state.
	_ = dlg.RespondSDP(ph.sdp())
	select {
	case <-ackGot:
	case <-time.After(3 * time.Second):
		t.Fatal("the phone that answered without keys got no ACK")
	}
	select {
	case <-ph.byeGot:
	case <-time.After(3 * time.Second):
		t.Fatal("the phone that answered without keys got no BYE")
	}
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
	if call.answered.Load() {
		t.Fatal("the network was answered for a phone without keys")
	}
}

// With TLS as the only transport (option plain '0') the server opens no UDP
// or TCP port and the phones sign in over TLS as before.
func TestTLSOnlyTransports(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dir := t.TempDir()
	sc := SIPConfig{
		Listen: "127.0.0.1:0", Transports: []string{"tls"},
		Accounts:  []SIPAccount{{User: "pixel", Password: testPass, Ext: "201"}},
		DialAllow: []string{"+44"}, EchoExt: "600", RTPPortMin: 41700, RTPPortMax: 41800,
		TLSCertFile: filepath.Join(dir, "tls.crt"), TLSKeyFile: filepath.Join(dir, "tls.key"),
	}.withDefaults()
	mgr := newCallManager(&Config{}, sc, nil, logger)
	lan, err := startLANSIP(sc, mgr, logger)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lan.Close)
	if lan.tlsPort == 0 || lan.port != 0 {
		t.Fatalf("TLS port %d, plain port %d: want TLS only", lan.tlsPort, lan.port)
	}
	ph := newTLSTestPhone(t, "pixel", suitePtr(srtp.AES128CMSHA1_80))
	registerOK(t, ph, fmt.Sprintf("127.0.0.1:%d", lan.tlsPort))
	if got := lan.secureUsers(); len(got) != 1 || got[0] != "pixel" {
		t.Fatalf("phones on TLS: %v", got)
	}
}

func TestSAVPOverUDPRefused(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	ph := newTestPhone(t)
	k, _ := srtp.NewCrypto(1, srtp.AES128CMSHA1_80)
	ph.key = &k
	registerOK(t, ph, rig.srvAddr)
	_, _, err := ph.call(rig.srvAddr, "600")
	var de *sipgo.ErrDialogResponse
	if !errors.As(err, &de) || de.Res.StatusCode != 488 {
		t.Fatalf("keys in SDP over UDP: %v, want 488", err)
	}
}

func TestTLSPlainOfferStaysPlain(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{}, false)
	ph := newTLSTestPhone(t, "pixel", nil)
	registerOK(t, ph, tlsAddr)
	dlg, _, err := ph.call(tlsAddr, "600")
	if err != nil {
		t.Fatalf("plain echo call over TLS: %v", err)
	}
	ans, _ := parseSDP(dlg.InviteResponse.Body())
	if ans.Proto != "RTP/AVP" || ans.CryptoLines != 0 {
		t.Fatalf("a plain offer must get a plain answer:\n%s", dlg.InviteResponse.Body())
	}
	if r := ph.talk(dlg.InviteResponse.Body(), time.Second, -1); r < 1500 {
		t.Fatalf("no plain echo over TLS: RMS %.0f", r)
	}
	bye(t, dlg)
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// reinvite sends a re-INVITE with body in the dialog and ACKs a 2xx.
func reinvite(t *testing.T, dlg *sipgo.DialogClientSession, body []byte) *sip.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req := sip.NewRequest(sip.INVITE, dlg.InviteResponse.Contact().Address)
	req.SetBody(body)
	req.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	res, err := dlg.Do(ctx, req)
	if err != nil {
		t.Fatalf("re-INVITE: %v", err)
	}
	if res.IsSuccess() {
		ack := sip.NewRequest(sip.ACK, dlg.InviteResponse.Contact().Address)
		_ = dlg.WriteRequest(ack)
	}
	return res
}

// A re-INVITE with the same keys keeps the SRTP contexts (the rollover count
// goes on), one with a new phone key replaces the phone's context only, and
// one without keys is refused.
func TestTLSReInviteKeys(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{}, false)
	ph := newTLSTestPhone(t, "pixel", suitePtr(srtp.AES128CMSHA1_80))
	registerOK(t, ph, tlsAddr)
	dlg, _, err := ph.call(tlsAddr, "600")
	if err != nil {
		t.Fatalf("echo call: %v", err)
	}
	first, _ := parseSDP(dlg.InviteResponse.Body())
	if r := ph.talk(dlg.InviteResponse.Body(), time.Second, -1); r < 1500 {
		t.Fatalf("no echo: RMS %.0f", r)
	}
	res := reinvite(t, dlg, ph.sdp())
	if res.StatusCode != 200 {
		t.Fatalf("re-INVITE with the same keys: %d", res.StatusCode)
	}
	same, _ := parseSDP(res.Body())
	if len(same.Crypto) != 1 || !same.Crypto[0].Equal(first.Crypto[0]) {
		t.Fatalf("our key changed on a re-INVITE with the same keys:\n%s", res.Body())
	}
	if r := ph.talk(res.Body(), time.Second, -1); r < 1500 {
		t.Fatalf("no echo after the re-INVITE: RMS %.0f", r)
	}
	k, _ := srtp.NewCrypto(1, srtp.AES128CMSHA1_80)
	ph.key = &k
	res = reinvite(t, dlg, ph.sdp())
	if res.StatusCode != 200 {
		t.Fatalf("re-INVITE with a new phone key: %d", res.StatusCode)
	}
	if r := ph.talk(res.Body(), time.Second, -1); r < 1500 {
		t.Fatalf("no echo after the phone's new key: RMS %.0f", r)
	}
	ph.key = nil
	if res = reinvite(t, dlg, ph.sdp()); res.StatusCode != 488 {
		t.Fatalf("re-INVITE that drops the keys: %d, want 488", res.StatusCode)
	}
	bye(t, dlg)
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// An incoming call to a phone on UDP and one on TLS: keys only to the second.
func TestIncomingForkMixedTransports(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, true)
	udp := newTestPhoneUser(t, "127.0.0.1", "iphone")
	registerOK(t, udp, rig.srvAddr)
	sec := newTLSTestPhone(t, "pixel", suitePtr(srtp.AES128CMSHA1_80))
	registerOK(t, sec, tlsAddr)
	call := newFakeIMSCall("in-mixed", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	var plainDlg, secDlg *sipgo.DialogServerSession
	for plainDlg == nil || secDlg == nil {
		select {
		case plainDlg = <-udp.incoming:
		case secDlg = <-sec.incoming:
		case <-time.After(3 * time.Second):
			t.Fatal("the INVITEs did not reach both phones")
		}
	}
	if b := string(plainDlg.InviteRequest.Body()); strings.Contains(b, "a=crypto") || !strings.Contains(b, "RTP/AVP") {
		t.Fatalf("keys went to a phone on UDP:\n%s", b)
	}
	if b := string(secDlg.InviteRequest.Body()); !strings.Contains(b, "a=crypto") {
		t.Fatalf("no keys for the phone on TLS:\n%s", b)
	}
	if err := secDlg.RespondSDP(sec.sdp()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, call.answered.Load, "the network was not answered")
	if r := sec.talk(secDlg.InviteRequest.Body(), time.Second, -1); r < 1500 {
		t.Fatalf("no audio on the TLS phone: RMS %.0f", r)
	}
	rig.mgr.onIMSEvent(call, CallStateEnded)
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// Phone on TLS with SRTP calls a phone on UDP: each leg as its phone has it.
func TestTLSInternalCallToUDPPhone(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, false)
	a := newTLSTestPhone(t, "pixel", suitePtr(srtp.AES128CMSHA1_80))
	registerOK(t, a, tlsAddr)
	b := newTestPhoneUser(t, "127.0.0.1", "iphone")
	registerOK(t, b, rig.srvAddr)
	type callRes struct {
		dlg *sipgo.DialogClientSession
		err error
	}
	done := make(chan callRes, 1)
	go func() {
		d, _, err := a.call(tlsAddr, "202")
		done <- callRes{d, err}
	}()
	var in *sipgo.DialogServerSession
	select {
	case in = <-b.incoming:
	case <-time.After(3 * time.Second):
		t.Fatal("the INVITE did not reach the second phone")
	}
	if strings.Contains(string(in.InviteRequest.Body()), "a=crypto") {
		t.Fatal("keys went to the phone on UDP")
	}
	if err := in.RespondSDP(b.sdp()); err != nil {
		t.Fatal(err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("internal call: %v", r.err)
	}
	var ra, rb float64
	finished := make(chan struct{})
	go func() { ra = a.talk(r.dlg.InviteResponse.Body(), 1500*time.Millisecond, -1); close(finished) }()
	rb = b.talk(in.InviteRequest.Body(), 1500*time.Millisecond, -1)
	<-finished
	t.Logf("SRTP phone ↔ plain phone: RMS %.0f and %.0f", ra, rb)
	if ra < 1500 || rb < 1500 {
		t.Fatalf("audio between the phones: %.0f and %.0f", ra, rb)
	}
	bye(t, r.dlg)
	select {
	case <-b.byeGot:
	case <-time.After(3 * time.Second):
		t.Fatal("the BYE did not reach the second phone")
	}
	waitFor(t, func() bool { return rig.mgr.current() == nil }, "the line was not released")
}

// A phone on TLS whose connection is gone is not dialled: the INVITE fails at
// once instead of waiting for a dial to a port nobody listens on.
func TestTLSGoneConnectionNotDialled(t *testing.T) {
	rig, tlsAddr := newTLSTestRig(t, &Config{IncomingAll: true}, true)
	ph := newTLSTestPhone(t, "pixel", suitePtr(srtp.AES128CMSHA1_80))
	registerOK(t, ph, tlsAddr)
	ph.ua.Close()
	b := rig.lan.reg.active()
	if len(b) != 1 {
		t.Fatalf("bindings: %+v", b)
	}
	waitFor(t, func() bool { return !rig.lan.reachable(b[0]) }, "the server still sees the closed connection")
	start := time.Now()
	call := newFakeIMSCall("in-gone", CallIncoming)
	rig.mgr.incomingFromNetwork(call, "+447700900456")
	waitFor(t, func() bool { return call.rejected.Load() != 0 }, "the call to a gone phone was not declined")
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("declining took %s", d)
	}
}

func TestPlanFromOffer(t *testing.T) {
	k, _ := srtp.NewCrypto(5, srtp.AES256CMSHA1_80)
	sdp := func(proto, extra string) *sdpAudio {
		a, err := parseSDP([]byte("v=0\r\nc=IN IP4 192.168.8.20\r\nm=audio 7078 " + proto + " 9 0\r\n" + extra))
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	crypto := "a=crypto:5 " + strings.SplitN(k.String(), " ", 2)[1] + "\r\n"
	unsupported := "a=crypto:1 AEAD_AES_128_GCM inline:MTIzNDU2Nzg5QUJDREUwMTIzNDU2Nzg5\r\n"
	codecs := []string{"G722", "PCMU"}
	for _, tc := range []struct {
		name, proto, extra, transport string
		wantErr, wantSRTP             bool
		wantProfile                   string
	}{
		{"SAVP over TLS", "RTP/SAVP", unsupported + crypto, "TLS", false, true, "RTP/SAVP"},
		{"SAVPF over TLS", "RTP/SAVPF", crypto, "TLS", false, true, "RTP/SAVP"},
		{"SAVP over UDP", "RTP/SAVP", crypto, "UDP", true, false, ""},
		{"SAVP over TCP", "RTP/SAVP", crypto, "TCP", true, false, ""},
		{"SAVP without a suite we do", "RTP/SAVP", unsupported, "TLS", true, false, ""},
		{"AVP with keys over TLS", "RTP/AVP", crypto, "TLS", false, true, "RTP/AVP"},
		{"AVP with keys over UDP", "RTP/AVP", crypto, "UDP", false, false, "RTP/AVP"},
		{"AVP over TLS", "RTP/AVP", "", "TLS", false, false, "RTP/AVP"},
		{"DTLS-SRTP", "UDP/TLS/RTP/SAVP", "a=fingerprint:sha-256 AB:CD\r\n", "TLS", true, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, err := planFromOffer(sdp(tc.proto, tc.extra), tc.transport, codecs)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %t", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if (plan.remote != nil) != tc.wantSRTP || plan.profile != tc.wantProfile || plan.format.Name != "G722" {
				t.Fatalf("plan %+v", plan)
			}
			if plan.remote != nil && !plan.remote.Equal(k) {
				t.Fatalf("the phone's key: %+v", plan.remote)
			}
		})
	}
	if _, err := planFromOffer(sdp("RTP/AVP", ""), "UDP", []string{"PCMA"}); !errors.Is(err, errNoCodec) {
		t.Fatalf("no common codec: %v", err)
	}
}

func TestServerCertificate(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "sub", "tls.crt"), filepath.Join(dir, "sub", "tls.key")
	ip := net.ParseIP("192.168.8.1").To4()
	now := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	c1, made, err := serverCertificate(cert, key, ip, now)
	if err != nil || !made {
		t.Fatalf("first: made=%t %v", made, err)
	}
	if st, err := os.Stat(key); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", st, err)
	}
	if !certCovers(c1.Leaf, ip) || c1.Leaf.NotAfter.Sub(now) < 9*365*24*time.Hour {
		t.Fatalf("certificate: %v until %v", c1.Leaf.IPAddresses, c1.Leaf.NotAfter)
	}
	c2, made, err := serverCertificate(cert, key, ip, now.Add(24*time.Hour))
	if err != nil || made || certFingerprint(c2) != certFingerprint(c1) {
		t.Fatalf("the same certificate must stay: made=%t %v", made, err)
	}
	c3, made, err := serverCertificate(cert, key, net.ParseIP("192.168.9.1").To4(), now)
	if err != nil || !made || certFingerprint(c3) == certFingerprint(c1) {
		t.Fatalf("a new LAN address needs a new certificate: made=%t %v", made, err)
	}
	if _, made, _ := serverCertificate(cert, key, net.ParseIP("192.168.9.1").To4(), c3.Leaf.NotAfter.Add(-10*24*time.Hour)); !made {
		t.Fatal("a certificate ten days from its end was not renewed")
	}
	if err := os.WriteFile(cert, []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, made, err := serverCertificate(cert, key, ip, now); err != nil || !made {
		t.Fatalf("a broken file must be replaced: made=%t %v", made, err)
	}
	if fp := certFingerprint(c1); len(fp) != 95 || strings.Count(fp, ":") != 31 {
		t.Fatalf("fingerprint %q", fp)
	}
}

func TestLinphoneXMLEncryption(t *testing.T) {
	acc := SIPAccount{User: "pixel", Password: "s3cret-pass-1"}
	ip := net.ParseIP("192.168.8.1")
	parse := func(b []byte) lpConfig {
		var c lpConfig
		if err := xml.Unmarshal(b, &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	sec := parse(linphoneXML(acc, "mudi", ip, 5060, 5061, "Mudi"))
	for k, want := range map[[2]string]string{
		{"proxy_0", "reg_proxy"}:              "<sip:192.168.8.1:5061;transport=tls>",
		{"sip", "media_encryption"}:           "srtp",
		{"sip", "media_encryption_mandatory"}: "1",
		{"sip", "verify_server_certs"}:        "0",
		{"sip", "verify_server_cn"}:           "0",
		{"sip", "default_proxy"}:              "0",
	} {
		if got := sec.get(k[0], k[1]); got != want {
			t.Errorf("TLS: %s/%s = %q, want %q", k[0], k[1], got, want)
		}
	}
	plain := parse(linphoneXML(acc, "mudi", ip, 5060, 0, "Mudi"))
	for k, want := range map[[2]string]string{
		{"proxy_0", "reg_proxy"}:              "<sip:192.168.8.1;transport=udp>",
		{"sip", "media_encryption"}:           "none",
		{"sip", "media_encryption_mandatory"}: "0",
		{"sip", "verify_server_certs"}:        "1",
	} {
		if got := plain.get(k[0], k[1]); got != want {
			t.Errorf("UDP: %s/%s = %q, want %q", k[0], k[1], got, want)
		}
	}
}
