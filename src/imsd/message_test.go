package main

// Tests of text messages: MESSAGE bodies, the echo number, phone to phone,
// SMS out through a fake smsd, and incoming SMS to the phones (new ones only,
// once, a phone that was away gets them when it registers).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

func TestMessageBody(t *testing.T) {
	cpim := func(ct, body string) []byte {
		return []byte("From: <sip:pixel@192.168.8.1>\r\nTo: <sip:+447700900789@192.168.8.1>\r\n" +
			"NS: imdn <urn:ietf:params:imdn>\r\nimdn.Message-ID: abc\r\n\r\n" +
			"Content-Type: " + ct + "\r\nContent-Length: " + fmt.Sprint(len(body)) + "\r\n\r\n" + body)
	}
	cases := []struct {
		ct   string
		body []byte
		text string
		kind msgKind
	}{
		{"text/plain;charset=UTF-8", []byte("Καλημέρα"), "Καλημέρα", msgText},
		{"message/cpim", cpim("text/plain;charset=UTF-8", "hi there"), "hi there", msgText},
		{"message/cpim", cpim("message/imdn+xml", "<imdn/>"), "", msgIgnore},
		{"application/im-iscomposing+xml", []byte("<isComposing/>"), "", msgIgnore},
		{"application/vnd.gsma.rcs-ft-http+xml", []byte("<file/>"), "", msgUnsupported},
		{"message/cpim", []byte("garbage"), "", msgUnsupported},
	}
	for _, c := range cases {
		text, kind := messageBody(c.ct, c.body)
		if text != c.text || kind != c.kind {
			t.Errorf("%s: got %q/%d, want %q/%d", c.ct, text, kind, c.text, c.kind)
		}
	}
}

func TestSplitTextAndSIPUser(t *testing.T) {
	long := strings.Repeat("λέξη ", 400) // 3600 bytes of two-byte characters
	parts := splitText(long, msgUDPText)
	if strings.Join(parts, "") != long || len(parts) < 5 {
		t.Fatalf("split into %d parts, joined back differently", len(parts))
	}
	for _, p := range parts {
		if len(p) > msgUDPText || !utf8Valid(p) {
			t.Fatalf("part of %d bytes or cut inside a character", len(p))
		}
	}
	if got := splitText("short", msgUDPText); len(got) != 1 || got[0] != "short" {
		t.Fatalf("short text: %q", got)
	}
	for in, want := range map[string]string{"+447700900789": "+447700900789", "My Bank": "My%20Bank", "": "unknown", "a@b;c": "a%40b%3Bc"} {
		if got := sipUser(in); got != want {
			t.Errorf("sipUser(%q) = %q, want %q", in, got, want)
		}
	}
	if smsDisplayName("+447700900789") != "" || smsDisplayName("Operator") != "Operator" {
		t.Error("smsDisplayName")
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "\x00") == s }

func TestSMSEncodingAndParts(t *testing.T) {
	if a, b := smsEncoding("Hello [1]"); a != "UTF-8" || string(b) != "Hello [1]" {
		t.Fatalf("GSM text: %s %q", a, b)
	}
	a, b := smsEncoding("Olá 😀")
	if a != "UCS" || !bytes.Equal(b, []byte{0x00, 'O', 0x00, 'l', 0x00, 0xE1, 0x00, ' ', 0xD8, 0x3D, 0xDE, 0x00}) {
		t.Fatalf("UCS-2 text: %s % x", a, b)
	}
	for text, want := range map[string]int{
		strings.Repeat("a", 160): 1, strings.Repeat("a", 161): 2, strings.Repeat("[", 80): 1, strings.Repeat("[", 81): 2,
		strings.Repeat("ω", 70): 1, strings.Repeat("ω", 71): 2, strings.Repeat("ω", 134): 2, strings.Repeat("ω", 135): 3,
	} {
		if got := smsParts(text); got != want {
			t.Errorf("smsParts(%d × %q) = %d, want %d", len([]rune(text)), []rune(text)[0], got, want)
		}
	}
}

// messageRequest builds a MESSAGE from the phone; callID "" leaves the
// Call-ID to sipgo.
func (p *testPhone) messageRequest(srvAddr, target, contentType string, body []byte, callID string) *sip.Request {
	host, _, _ := net.SplitHostPort(srvAddr)
	req := sip.NewRequest(sip.MESSAGE, p.uri(srvAddr, target))
	if p.tls {
		req.SetTransport("TLS")
	}
	from := &sip.FromHeader{Address: sip.Uri{Scheme: "sip", User: p.user, Host: host}, Params: sip.NewParams()}
	from.Params.Add("tag", sip.GenerateTagN(8))
	req.AppendHeader(from)
	req.AppendHeader(&sip.ToHeader{Address: sip.Uri{Scheme: "sip", User: target, Host: host}})
	req.AppendHeader(sip.NewHeader("Content-Type", contentType))
	if callID != "" {
		h := sip.CallIDHeader(callID)
		req.AppendHeader(&h)
	}
	req.SetBody(body)
	return req
}

// message sends a MESSAGE from the phone, answering the 407 challenge.
func (p *testPhone) message(srvAddr, target, contentType string, body []byte) (*sip.Response, error) {
	return p.send(p.messageRequest(srvAddr, target, contentType, body, ""))
}

func (p *testPhone) send(req *sip.Request) (*sip.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := p.cli.Do(ctx, req)
	if err != nil || res.StatusCode != 407 {
		return res, err
	}
	return p.cli.DoDigestAuth(ctx, req, res, sipgo.DigestAuth{Username: p.user, Password: testPass})
}

func (p *testPhone) nextMessage(t *testing.T, within time.Duration) *sip.Request {
	t.Helper()
	select {
	case m := <-p.messages:
		return m
	case <-time.After(within):
		t.Fatalf("%s: no message in %s", p.user, within)
		return nil
	}
}

func (p *testPhone) noMessage(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case m := <-p.messages:
		t.Fatalf("%s: unexpected message from %s: %q", p.user, m.From().Address.User, m.Body())
	case <-time.After(within):
	}
}

func TestSIPMessageEchoAndPhoneToPhone(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	pixel := newTestPhoneUser(t, "127.0.0.1", "pixel")
	iphone := newTestPhoneUser(t, "127.0.0.1", "iphone")
	if res, err := pixel.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("register: %v %v", res, err)
	}

	res, err := pixel.message(rig.srvAddr, "600", "text/plain;charset=UTF-8", []byte("ηχώ?"))
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("to the echo: %v %v", res, err)
	}
	m := pixel.nextMessage(t, 3*time.Second)
	if m.From().Address.User != "600" || string(m.Body()) != "ηχώ?" {
		t.Fatalf("echo: from %s body %q", m.From().Address.User, m.Body())
	}

	// iphone is away: 480, nothing is queued for phone-to-phone messages.
	if res, err := pixel.message(rig.srvAddr, "202", "text/plain", []byte("are you there?")); err != nil || res.StatusCode != 480 {
		t.Fatalf("to an absent phone: %v %v", res, err)
	}
	if res, err := iphone.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("register iphone: %v %v", res, err)
	}
	if res, err := pixel.message(rig.srvAddr, "202", "text/plain", []byte("are you there?")); err != nil || res.StatusCode != 200 {
		t.Fatalf("to iphone by its short number: %v %v", res, err)
	}
	m = iphone.nextMessage(t, 3*time.Second)
	if m.From().Address.User != "pixel" || string(m.Body()) != "are you there?" {
		t.Fatalf("phone to phone: from %s body %q", m.From().Address.User, m.Body())
	}
	// Typing notifications are taken and dropped; files are refused.
	if res, err := pixel.message(rig.srvAddr, "iphone", "application/im-iscomposing+xml", []byte("<x/>")); err != nil || res.StatusCode != 200 {
		t.Fatalf("is-composing: %v %v", res, err)
	}
	iphone.noMessage(t, 300*time.Millisecond)
	if res, err := pixel.message(rig.srvAddr, "iphone", "image/jpeg", []byte{1, 2}); err != nil || res.StatusCode != 415 {
		t.Fatalf("a file: %v %v", res, err)
	}
	// Without the SMS bridge a number gets 403.
	if res, err := pixel.message(rig.srvAddr, "+447700900789", "text/plain", []byte("hi")); err != nil || res.StatusCode != 403 {
		t.Fatalf("SMS off: %v %v", res, err)
	}
}

// smsTestDirs makes an smsd spool in a temporary directory.
func smsTestDirs(t *testing.T) SMSConfig {
	t.Helper()
	root := t.TempDir()
	c := SMSConfig{
		Incoming: filepath.Join(root, "spool", "incoming"), Outgoing: filepath.Join(root, "spool", "outgoing"),
		Sent: filepath.Join(root, "spool", "sent"), Failed: filepath.Join(root, "spool", "failed"),
		StateFile: filepath.Join(root, "sms-phones.json"),
	}
	for _, d := range []string{c.Incoming, c.Outgoing, c.Sent, c.Failed} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return c.withDefaults()
}

// fakeSMSD moves what appears in outgoing to sent, or to failed with a
// reason when the text says "fail".
func fakeSMSD(t *testing.T, c SMSConfig, seen chan<- []byte) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		for ctx.Err() == nil {
			es, _ := os.ReadDir(c.Outgoing)
			for _, e := range es {
				src := filepath.Join(c.Outgoing, e.Name())
				b, err := os.ReadFile(src)
				if err != nil {
					continue
				}
				seen <- b
				if bytes.Contains(b, []byte("fail")) {
					_ = os.WriteFile(filepath.Join(c.Failed, e.Name()), append([]byte("Failed: now\nFail_reason: Error from modem\nError: CMS ERROR: 38\n"), b...), 0o644)
				} else {
					_ = os.WriteFile(filepath.Join(c.Sent, e.Name()), b, 0o644)
				}
				_ = os.Remove(src)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
}

func TestSIPMessageToNumberAsSMS(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	c := smsTestDirs(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := newSMSBridge(c, filepath.Join(t.TempDir(), "inbox.jsonl"), rig.lan, logger)
	b.sendWait, b.watchLate = 2*time.Second, 2*time.Second
	rig.lan.setSMS(b, b.phoneOnline)
	pixel := newTestPhoneUser(t, "127.0.0.1", "pixel")
	if res, err := pixel.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("register: %v %v", res, err)
	}

	// Nobody takes the file: 202 Accepted, the file stays in outgoing.
	res, err := pixel.message(rig.srvAddr, "07700900789", "text/plain", []byte("Hi"))
	if err != nil || res.StatusCode != 202 {
		t.Fatalf("no smsd: %v %v", res, err)
	}
	es, _ := os.ReadDir(c.Outgoing)
	if len(es) != 1 {
		t.Fatalf("outgoing holds %d files", len(es))
	}
	got, _ := os.ReadFile(filepath.Join(c.Outgoing, es[0].Name()))
	want := "To: +447700900789\nAlphabet: UTF-8\nBus: cpu\nSlot: 1\nTo_TOA: international\n\nHi"
	if string(got) != want {
		t.Fatalf("spool file:\n%s\nwant:\n%s", got, want)
	}
	_ = os.Remove(filepath.Join(c.Outgoing, es[0].Name()))

	seen := make(chan []byte, 8)
	fakeSMSD(t, c, seen)
	// Greek in CPIM, as Linphone sends it when it wants receipts: UCS-2, 200.
	body := []byte("From: <sip:pixel@127.0.0.1>\r\n\r\nContent-Type: text/plain;charset=UTF-8\r\n\r\nΓειά")
	if res, err := pixel.message(rig.srvAddr, "+447700900789", "message/cpim", body); err != nil || res.StatusCode != 200 {
		t.Fatalf("sent: %v %v", res, err)
	}
	f := <-seen
	if !bytes.Contains(f, []byte("Alphabet: UCS\n")) || !bytes.HasSuffix(f, []byte{0x03, 0x93, 0x03, 0xB5, 0x03, 0xB9, 0x03, 0xAC}) {
		t.Fatalf("UCS-2 file: %q", f)
	}
	// smsd gives up: 500.
	if res, err := pixel.message(rig.srvAddr, "+447700900789", "text/plain", []byte("please fail")); err != nil || res.StatusCode != 500 {
		t.Fatalf("failed: %v %v", res, err)
	}
	<-seen
	// Outside dial_allow (+44 in the rig): 403, nothing queued.
	if res, err := pixel.message(rig.srvAddr, "+33639981234", "text/plain", []byte("Hi")); err != nil || res.StatusCode != 403 {
		t.Fatalf("not allowed: %v %v", res, err)
	}
	// 672 characters with a backquote: UCS-2, 11 parts (and under 1300 bytes,
	// so that the test phone can send it over UDP).
	if res, err := pixel.message(rig.srvAddr, "+447700900789", "text/plain", []byte(strings.Repeat("a", 671)+"`")); err != nil || res.StatusCode != 513 {
		t.Fatalf("too long: %v %v", res, err)
	}
	select {
	case f := <-seen:
		t.Fatalf("queued anyway: %q", f)
	case <-time.After(200 * time.Millisecond):
	}
}

func writeSpoolSMS(t *testing.T, dir, name, from, sent, text string) {
	t.Helper()
	f := fmt.Sprintf("From: %s\nFrom_TOA: 91 international, ISDN/telephone\nSent: %s\nReceived: %s\nModem: GMS1\nBus: cpu\nSlot: 1\nAlphabet: UTF-8\nCharset: UTF-8\nLength: %d\n\n%s",
		from, sent, sent, len(text), text)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(f), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestSMSToPhones(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	c := smsTestDirs(t)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		logger = slog.New(slog.NewTextHandler(testLogWriter{t}, nil))
	}
	inbox := filepath.Join(t.TempDir(), "inbox.jsonl")
	writeSpoolSMS(t, c.Incoming, "GMS1.old", "447700900001", "26-11-01 10:00:00", "old one")

	// start runs a bridge; its stop cancels it and waits until run returns.
	// Without the wait a pass over the spool could still run after the test:
	// it finds the SMS gone with the cleanup of t.TempDir and saves the state
	// file into the directory being removed ("directory not empty"), or makes
	// the directory again. The stop is registered after t.TempDir, so it runs
	// before that cleanup, after a Fatal as well.
	start := func() func() {
		b := newSMSBridge(c, inbox, rig.lan, logger)
		b.poll, b.retryMin = 50*time.Millisecond, 100*time.Millisecond
		rig.lan.setSMS(b, b.phoneOnline)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			b.run(ctx)
		}()
		stop := sync.OnceFunc(func() {
			cancel()
			<-done
		})
		t.Cleanup(stop)
		return stop
	}
	stop := start()
	pixel := newTestPhoneUser(t, "127.0.0.1", "pixel")
	if res, err := pixel.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("register: %v %v", res, err)
	}
	// The SMS that was there before the first start stays out of the phones.
	pixel.noMessage(t, 300*time.Millisecond)

	// A new one goes to the registered phone, from the sender's number; the
	// copy smsd stored for the second slot does not go again.
	writeSpoolSMS(t, c.Incoming, "GMS1.new", "447700900789", "26-11-06 18:00:00", "Κωδικός 1234")
	m := pixel.nextMessage(t, 3*time.Second)
	if m.From().Address.User != "+447700900789" || string(m.Body()) != "Κωδικός 1234" {
		t.Fatalf("SMS to the phone: from %s body %q", m.From().Address.User, m.Body())
	}
	writeSpoolSMS(t, c.Incoming, "GMS2.new", "447700900789", "26-11-06 18:00:00", "Κωδικός 1234")
	pixel.noMessage(t, 300*time.Millisecond)

	// iphone was away: the SMS waits for it, across a restart of the daemon
	// (the old bridge is gone before the new one reads the state file).
	stop()
	start()
	pixel.noMessage(t, 300*time.Millisecond)
	iphone := newTestPhoneUser(t, "127.0.0.1", "iphone")
	if res, err := iphone.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("register iphone: %v %v", res, err)
	}
	m = iphone.nextMessage(t, 3*time.Second)
	if string(m.Body()) != "Κωδικός 1234" {
		t.Fatalf("pending SMS: %q", m.Body())
	}
	iphone.noMessage(t, 300*time.Millisecond) // and the old one never

	// A phone that refuses gets it again later; an alphanumeric sender keeps
	// its name.
	pixel.msgCode.Store(486)
	writeSpoolSMS(t, c.Incoming, "GMS1.bank", "MyBank", "26-11-06 18:05:00", "Card blocked")
	iphone.nextMessage(t, 3*time.Second)
	time.Sleep(300 * time.Millisecond)
	pixel.msgCode.Store(0)
	m = pixel.nextMessage(t, 3*time.Second)
	if m.From().Address.User != "MyBank" || m.From().DisplayName != "MyBank" {
		t.Fatalf("alphanumeric sender: %s %q", m.From().Address.User, m.From().DisplayName)
	}
	// The attempts at one SMS are one message for the phone (§119).
	if got, first := m.CallID().Value(), pixel.refused.Load().CallID().Value(); got != first {
		t.Fatalf("Call-ID of the retry %q, of the first attempt %q", got, first)
	}

	// SMS over IMS go too, to both phones.
	line := `{"received_at":"2026-11-06T18:10:00+01:00","from":"+447700900123","text":"over IMS"}` + "\n"
	if err := os.WriteFile(inbox, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []*testPhone{pixel, iphone} {
		if m := p.nextMessage(t, 3*time.Second); string(m.Body()) != "over IMS" {
			t.Fatalf("IMS SMS to %s: %q", p.user, m.Body())
		}
	}
	// The test is over when the bridge has the answers of both. A phone hands
	// the message to the test after it has sent its 200; a 200 still on its
	// way at the stop comes late (§119), and the bridge saves its state into
	// the directory t.TempDir is removing ("directory not empty").
	waitFor(t, func() bool {
		var st smsState
		raw, err := os.ReadFile(c.StateFile)
		if err != nil || json.Unmarshal(raw, &st) != nil {
			return false
		}
		for _, p := range st.Messages {
			if len(p.Pending) > 0 {
				return false
			}
		}
		return true
	}, "the bridge still waits for the answer of a phone")
}

// A phone asleep answers after the daemon has stopped waiting. Its 200 still
// counts: no further attempt goes to it (§119).
func TestSMSLateAnswerEndsAttempts(t *testing.T) {
	rig := newTestRig(t, &Config{}, false) // pixel and iphone
	c := smsTestDirs(t)
	b := newSMSBridge(c, filepath.Join(t.TempDir(), "inbox.jsonl"), rig.lan, quietLog())
	b.poll, b.retryMin = 50*time.Millisecond, 500*time.Millisecond
	rig.lan.setSMS(b, b.phoneOnline)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	pixel := newTestPhoneUser(t, "127.0.0.1", "pixel")
	if res, err := pixel.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("register: %v %v", res, err)
	}
	pixel.noMessage(t, 200*time.Millisecond) // the first pass is over

	pixel.msgCode.Store(486)
	writeSpoolSMS(t, c.Incoming, "GMS1.one", "447700900789", "26-11-06 18:00:00", "Code 1234")
	var first *sip.Request
	for end := time.Now().Add(3 * time.Second); first == nil && time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		first = pixel.refused.Load()
	}
	if first == nil {
		t.Fatal("the SMS did not reach the phone")
	}
	pixel.msgCode.Store(0)
	rig.lan.lateResponse(sip.NewResponseFromRequest(first, 200, "OK", nil))
	pixel.noMessage(t, time.Second)

	// iphone never answered. The answer for one piece of a text settles
	// nothing, the answer for the whole text does.
	pending := func() (string, bool) {
		b.mu.Lock()
		defer b.mu.Unlock()
		for k, p := range b.state.Messages {
			if containsString(p.Pending, "iphone") {
				return k, true
			}
		}
		return "", false
	}
	key, ok := pending()
	if !ok {
		t.Fatal("the SMS is not pending for iphone")
	}
	b.lateAnswer(smsIDPrefix+key+".0", "iphone")
	if _, ok := pending(); !ok {
		t.Fatal("the answer for one piece settled the SMS")
	}
	b.lateAnswer(smsIDPrefix+key, "iphone")
	if _, ok := pending(); ok {
		t.Fatal("the late answer did not settle the SMS")
	}
}

// Over UDP a long text goes in pieces. Each has a Call-ID of its own, or a
// phone would keep only the first, and every attempt repeats them (§119).
func TestSendTextCallIDs(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	pixel := newTestPhoneUser(t, "127.0.0.1", "pixel")
	if res, err := pixel.register(rig.srvAddr, testPass); err != nil || res.StatusCode != 200 {
		t.Fatalf("register: %v %v", res, err)
	}
	send := func(text, id string) []string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if ok, err := rig.lan.sendText(ctx, "pixel", "+447700900789", "", text, id); !ok {
			t.Fatalf("sendText: %v", err)
		}
		var ids []string
		for range splitText(text, msgUDPText) {
			ids = append(ids, pixel.nextMessage(t, 3*time.Second).CallID().Value())
		}
		return ids
	}
	long := strings.Repeat("x", msgUDPText+10)
	first, again := send(long, "sms-abc"), send(long, "sms-abc")
	if len(first) != 2 || first[0] == first[1] || first[0] != again[0] || first[1] != again[1] {
		t.Fatalf("pieces: first attempt %q, second %q", first, again)
	}
	if a, b := send("short", "sms-abc"), send("short", "sms-abc"); a[0] != b[0] || !strings.HasPrefix(a[0], "sms-abc@") {
		t.Fatalf("one piece: %q and %q", a, b)
	}
	if a, b := send("short", ""), send("short", ""); a[0] == b[0] {
		t.Fatalf("one-off texts share a Call-ID: %q", a[0])
	}
}

// relayRig is a rig with pixel and iphone registered and a short wait for the
// addressee's answer.
func relayRig(t *testing.T, wait time.Duration) (*testRig, *testPhone, *testPhone) {
	t.Helper()
	rig := newTestRig(t, &Config{}, false)
	rig.lan.relayWait = wait
	pixel, iphone := newTestPhoneUser(t, "127.0.0.1", "pixel"), newTestPhoneUser(t, "127.0.0.1", "iphone")
	registerOK(t, pixel, rig.srvAddr)
	registerOK(t, iphone, rig.srvAddr)
	return rig, pixel, iphone
}

// say sends a text from p and returns the code of the final answer and how
// long it took.
func say(t *testing.T, p *testPhone, srvAddr, target, text string) (int, time.Duration) {
	t.Helper()
	start := time.Now()
	res, err := p.message(srvAddr, target, "text/plain", []byte(text))
	if err != nil {
		t.Fatalf("%q: %v", text, err)
	}
	return res.StatusCode, time.Since(start)
}

// A phone asleep answers when it next wakes up. An answer within the wait
// reaches the sender as 200. After the wait the sender hears 202, not a
// refusal, and the phone has the text all the same, once.
func TestPhoneToPhoneAsleep(t *testing.T) {
	const wait = 600 * time.Millisecond
	rig, pixel, iphone := relayRig(t, wait)

	iphone.msgDelay.Store(int64(250 * time.Millisecond))
	if code, took := say(t, pixel, rig.srvAddr, "iphone", "in time"); code != 200 || took < 250*time.Millisecond {
		t.Fatalf("an answer in time: %d after %v", code, took)
	}
	iphone.nextMessage(t, time.Second)

	asleep := wait + 900*time.Millisecond
	iphone.msgDelay.Store(int64(asleep))
	if code, took := say(t, pixel, rig.srvAddr, "202", "asleep"); code != 202 || took < wait || took >= asleep {
		t.Fatalf("no answer during the wait: %d after %v", code, took)
	}
	m := iphone.nextMessage(t, 3*time.Second)
	if m.From().Address.User != "pixel" || string(m.Body()) != "asleep" {
		t.Fatalf("from %s body %q", m.From().Address.User, m.Body())
	}
	iphone.noMessage(t, 300*time.Millisecond)

	iphone.msgDelay.Store(0)
	iphone.msgCode.Store(486)
	if code, _ := say(t, pixel, rig.srvAddr, "iphone", "refused"); code != 480 {
		t.Fatalf("a refusal: %d", code)
	}
}

// The first device to take a text settles it for the sender: a stale binding
// must not keep the sender waiting. Without one, silence anywhere means the
// text may have arrived, and only refusals all round mean it has not.
func TestPhoneToPhoneSeveralDevices(t *testing.T) {
	const wait = 500 * time.Millisecond
	rig, pixel, quick := relayRig(t, wait)
	slow := newTestPhoneUser(t, "127.0.0.1", "iphone")
	registerOK(t, slow, rig.srvAddr)
	slow.msgDelay.Store(int64(wait + 700*time.Millisecond))

	if code, took := say(t, pixel, rig.srvAddr, "iphone", "one has it"); code != 200 || took >= wait {
		t.Fatalf("one device took it: %d after %v", code, took)
	}
	quick.nextMessage(t, time.Second)

	quick.msgCode.Store(486)
	if code, _ := say(t, pixel, rig.srvAddr, "iphone", "refused and silent"); code != 202 {
		t.Fatalf("one refused, one silent: %d", code)
	}

	slow.msgDelay.Store(0)
	slow.msgCode.Store(486)
	if code, _ := say(t, pixel, rig.srvAddr, "iphone", "refused twice"); code != 480 {
		t.Fatalf("both refused: %d", code)
	}
}

// One request of the sender is one message for the addressee; a new message
// with the same words is a new one.
func TestPhoneToPhoneCallID(t *testing.T) {
	rig, pixel, iphone := relayRig(t, 2*time.Second)
	callID := func(id, text string) string {
		t.Helper()
		res, err := pixel.send(pixel.messageRequest(rig.srvAddr, "iphone", "text/plain", []byte(text), id))
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("%q: %v %v", text, res, err)
		}
		return iphone.nextMessage(t, 3*time.Second).CallID().Value()
	}
	first := callID("abc", "hello")
	if !strings.HasPrefix(first, msgIDPrefix) {
		t.Fatalf("Call-ID %q", first)
	}
	if again := callID("abc", "hello"); again != first {
		t.Fatalf("the same request: %q, then %q", first, again)
	}
	if other := callID("def", "hello"); other == first {
		t.Fatalf("a new message shares the Call-ID %q", first)
	}
	if other := callID("abc", "bye"); other == first {
		t.Fatalf("another text shares the Call-ID %q", first)
	}
	req := pixel.messageRequest(rig.srvAddr, "iphone", "text/plain", []byte("hello"), "abc")
	if relayID("pixel", "iphone", req, "hello") == relayID("iphone", "pixel", req, "hello") {
		t.Fatal("the two directions share an id")
	}
}

// Over UDP a long text goes in pieces. A phone asleep answers none of them
// during the wait; they all go out inside it, each under its own Call-ID. A
// refusal ends the text there.
func TestRelayTextPieces(t *testing.T) {
	const wait = 600 * time.Millisecond
	rig, _, iphone := relayRig(t, wait)
	long := strings.Repeat("x", msgUDPText+10)

	iphone.msgDelay.Store(int64(wait + 500*time.Millisecond))
	start := time.Now()
	if err := rig.lan.relayText("iphone", "pixel", long, "msg-long"); !errors.Is(err, errNoAnswer) {
		t.Fatalf("asleep: %v", err)
	}
	if took := time.Since(start); took < wait*3/4 || took > wait+400*time.Millisecond {
		t.Fatalf("the pieces took %v of a wait of %v", took, wait)
	}
	a, b := iphone.nextMessage(t, 3*time.Second), iphone.nextMessage(t, 3*time.Second)
	if string(a.Body())+string(b.Body()) != long || a.CallID().Value() == b.CallID().Value() {
		t.Fatalf("pieces %q and %q under %s and %s", a.Body(), b.Body(), a.CallID().Value(), b.CallID().Value())
	}

	iphone.msgDelay.Store(0)
	iphone.msgCode.Store(486)
	err := rig.lan.relayText("iphone", "pixel", long, "msg-refused")
	if err == nil || errors.Is(err, errNoAnswer) {
		t.Fatalf("refused: %v", err)
	}
	if got := iphone.refused.Load().CallID().Value(); !strings.HasPrefix(got, "msg-refused.0@") {
		t.Fatalf("the last request the phone refused: %s", got)
	}
}

// responseCodes sends a text from p and returns the codes of the responses it
// hears, the final one last; heard, unless nil, is told of each as it comes.
func responseCodes(t *testing.T, p *testPhone, srvAddr, target, text string, heard func(code int)) []int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req := p.messageRequest(srvAddr, target, "text/plain", []byte(text), "")
	challenge, err := p.cli.Do(ctx, req)
	if err != nil || challenge.StatusCode != 407 {
		t.Fatalf("%q: %v %v", text, challenge, err)
	}
	tx, err := p.cli.TransactionDigestAuth(ctx, req, challenge, sipgo.DigestAuth{Username: p.user, Password: testPass})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Terminate()
	var got []int
	for {
		select {
		case res := <-tx.Responses():
			got = append(got, res.StatusCode)
			if heard != nil {
				heard(res.StatusCode)
			}
			if !res.IsProvisional() {
				return got
			}
		case <-tx.Done():
			t.Fatalf("%q: %v after %v", text, tx.Err(), got)
		case <-ctx.Done():
			t.Fatalf("%q: no final answer after %v", text, got)
		}
	}
}

// While the answer is held up the sender hears 100 Trying (RFC 4320 §4.1),
// again for every copy of the request it repeats over UDP; an answer at once
// comes without it.
func TestPhoneToPhoneTrying(t *testing.T) {
	const wait = 500 * time.Millisecond
	rig, pixel, iphone := relayRig(t, wait)
	rig.lan.relayTrying = 100 * time.Millisecond
	codes := func(text string) []int {
		t.Helper()
		return responseCodes(t, pixel, rig.srvAddr, "iphone", text, nil)
	}
	if got := codes("at once"); len(got) != 1 || got[0] != 200 {
		t.Errorf("an answer at once: %v", got)
	}
	iphone.msgDelay.Store(int64(wait + 300*time.Millisecond))
	got := codes("asleep")
	if len(got) < 2 || got[len(got)-1] != 202 {
		t.Fatalf("no answer during the wait: %v", got)
	}
	for _, c := range got[:len(got)-1] {
		if c != 100 {
			t.Fatalf("no answer during the wait: %v", got)
		}
	}
}

// An SMS waits for smsd in the sender's transaction under the same rule:
// silence at first, while the sender is repeating its request (at 0.5 s here,
// before 100 Trying is due), then 100 Trying, then smsd's verdict. A verdict
// in time comes without 100 Trying.
func TestPhoneToNumberTrying(t *testing.T) {
	const (
		trying = time.Second // well over the 250 ms between smsBridge.wait's looks
		number = "+447700900789"
	)
	rig := newTestRig(t, &Config{}, false)
	rig.lan.relayTrying = trying
	c := smsTestDirs(t)
	b := newSMSBridge(c, filepath.Join(t.TempDir(), "inbox.jsonl"), rig.lan, quietLog())
	b.sendWait = 3 * trying // over before a 100 at the real msgRelayTrying
	rig.lan.setSMS(b, b.phoneOnline)
	pixel := newTestPhoneUser(t, "127.0.0.1", "pixel")
	registerOK(t, pixel, rig.srvAddr)

	// smsd comes to the file only when the sender has heard something.
	seen := make(chan []byte, 8)
	var first time.Duration
	start := time.Now()
	got := responseCodes(t, pixel, rig.srvAddr, number, "held up", func(int) {
		if first == 0 {
			first = time.Since(start)
			fakeSMSD(t, c, seen)
		}
	})
	if len(got) < 2 || got[len(got)-1] != 200 || first < trying {
		t.Fatalf("held up: %v, the first after %v", got, first)
	}
	for _, code := range got[:len(got)-1] {
		if code != 100 {
			t.Fatalf("held up: %v", got)
		}
	}
	if len(seen) != 1 {
		t.Fatalf("held up: %d SMS for one request", len(seen))
	}

	if got := responseCodes(t, pixel, rig.srvAddr, number, "at once", nil); len(got) != 1 || got[0] != 200 {
		t.Errorf("sent at once: %v", got)
	}
	if got := responseCodes(t, pixel, rig.srvAddr, number, "please fail", nil); len(got) != 1 || got[0] != 500 {
		t.Errorf("refused at once: %v", got)
	}
}

// Over TLS, as the phones set up by QR code are: no retransmissions, so all
// the phone can do is answer late, and 202 says so. A phone without a
// connection cannot have the text: 480 at once.
func TestPhoneToPhoneTLS(t *testing.T) {
	const wait = 400 * time.Millisecond
	rig, tlsAddr := newTLSTestRig(t, &Config{}, false)
	rig.lan.relayWait = wait
	pixel, iphone := newTLSTestPhone(t, "pixel", nil), newTLSTestPhone(t, "iphone", nil)
	registerOK(t, pixel, tlsAddr)
	registerOK(t, iphone, tlsAddr)

	iphone.msgDelay.Store(int64(wait + 300*time.Millisecond))
	if code, took := say(t, pixel, tlsAddr, "iphone", "asleep"); code != 202 || took < wait {
		t.Fatalf("asleep: %d after %v", code, took)
	}
	if m := iphone.nextMessage(t, 3*time.Second); string(m.Body()) != "asleep" {
		t.Fatalf("body %q", m.Body())
	}

	iphone.ua.Close()
	b := rig.lan.reg.forUser("iphone")[0]
	waitFor(t, func() bool { return !rig.lan.reachable(b) }, "the connection of the phone is still there")
	if code, took := say(t, pixel, tlsAddr, "iphone", "gone"); code != 480 || took >= wait {
		t.Fatalf("no connection: %d after %v", code, took)
	}
}

// The wait ends before the sender's Timer F (64*T1, sipgo's as belle-sip's)
// with time for the answer to get there, and 100 Trying does not come before
// the sender's Timer E has reached T2 (0.5+1+2 s).
func TestRelayTimers(t *testing.T) {
	if msgRelayWait > sip.Timer_F-time.Second {
		t.Errorf("msgRelayWait %v leaves too little of Timer F %v", msgRelayWait, sip.Timer_F)
	}
	if msgRelayTrying != 7*sip.T1 {
		t.Errorf("msgRelayTrying %v, want %v", msgRelayTrying, 7*sip.T1)
	}
}

// After a boot the router's clock starts from the newest file under /etc,
// days behind when the router was off for days, and NTP steps it later. An
// SMS for a phone that is away must not count the step as its age: by
// smsd's Received line it was past smsKeepPending at once.
func TestSMSPendingClockStep(t *testing.T) {
	rig := newTestRig(t, &Config{}, false) // pixel and iphone, neither registered
	c := smsTestDirs(t)
	inbox := filepath.Join(t.TempDir(), "inbox.jsonl")
	boot := time.Date(2026, 10, 28, 10, 31, 0, 0, time.Local) // the clock at the boot, 10 days behind
	var up, step time.Duration                                // time since the boot; NTP's correction
	open := func() *smsBridge {
		b := newSMSBridge(c, inbox, rig.lan, quietLog())
		b.now = func() time.Time { return boot.Add(up + step) }
		b.mono = func() time.Time { return boot.Add(up) }
		return b
	}
	pending := func(b *smsBridge) []string {
		b.mu.Lock()
		defer b.mu.Unlock()
		for _, p := range b.state.Messages {
			return p.Pending
		}
		return nil
	}
	ctx := context.Background()
	b := open()
	b.scan(ctx) // the first start, nothing on the router yet

	up = time.Minute
	writeSpoolSMS(t, c.Incoming, "GMS1.away", "447700900789", "26-10-28 10:32:00", "for later")
	b.scan(ctx)
	if p := pending(b); len(p) != 2 {
		t.Fatalf("pending %v, want both phones", p)
	}
	step = 10 * 24 * time.Hour // NTP
	up = 2 * time.Minute
	b.scan(ctx)
	if p := pending(b); len(p) != 2 {
		t.Fatalf("after the step: pending %v, want both phones", p)
	}
	var st smsState
	raw, err := os.ReadFile(c.StateFile)
	if err == nil {
		err = json.Unmarshal(raw, &st)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range st.Messages {
		if got, err := time.Parse(time.RFC3339, p.Received); err != nil || !got.Equal(boot.Add(step+time.Minute)) {
			t.Errorf("received %q in the file, want %v: the SMS was found a minute after the boot", p.Received, boot.Add(step+time.Minute))
		}
	}

	// After a restart the corrected time in the file is the start.
	up = 3 * time.Minute
	b2 := open()
	b2.scan(ctx)
	if p := pending(b2); len(p) != 2 {
		t.Fatalf("after a restart: pending %v, want both phones", p)
	}
	// The phones still have only smsKeepPending, on the monotonic clock.
	up = time.Minute + smsKeepPending + time.Second
	b.scan(ctx)
	if p := pending(b); len(p) != 0 {
		t.Errorf("after smsKeepPending: pending %v, want none", p)
	}
}
