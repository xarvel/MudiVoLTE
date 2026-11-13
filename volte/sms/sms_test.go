package sms

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/reg"
	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Widely published SMS-DELIVER example ("How are you?" from +31641600986).
func TestParseDeliverKnown(t *testing.T) {
	d, err := ParseDeliver(unhex(t, "040B911346610089F60000208062917314080CC8F71D14969741F977FD07"))
	if err != nil {
		t.Fatal(err)
	}
	if d.From.Number != "+31641600986" || d.Text != "How are you?" || d.Timestamp.Year() != 2002 ||
		d.Timestamp.Month() != 8 || d.Timestamp.Day() != 26 || d.Timestamp.Hour() != 19 || d.Timestamp.Second() != 41 {
		t.Fatalf("%+v", d)
	}
}

// Widely published SMS-SUBMIT example: "hellohello" packs to E8329BFD4697D9EC37.
func TestSubmitSeptetPacking(t *testing.T) {
	tp, err := Submit(ParseNumber("+46708251358"), "hellohello", 0, 0)
	if err != nil || len(tp) != 1 {
		t.Fatal(err)
	}
	want := "0100" + "0B916407281553F8" + "0000" + "0AE8329BFD4697D9EC37"
	if got := strings.ToUpper(hex.EncodeToString(tp[0])); got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}

// deliverFromSubmit turns our SMS-SUBMIT into the SMS-DELIVER the recipient
// would get: same DCS and user data, originator instead of destination.
func deliverFromSubmit(t *testing.T, sub []byte, from Address) []byte {
	daLen := 2 + (int(sub[2])+1)/2
	pid, dcs := sub[2+daLen], sub[3+daLen]
	ud := sub[4+daLen:]
	oa, _ := encodeTPAddress(from)
	first := byte(0x04) | sub[0]&0x40
	out := append([]byte{first}, oa...)
	out = append(out, pid, dcs)
	out = append(out, 0x62, 0x11, 0x30, 0x12, 0x00, 0x00, 0x40) // 2026-11-03 21:00:00 +01:00
	return append(out, ud...)
}

func TestSubmitDeliverRoundTrip(t *testing.T) {
	from := ParseNumber("+447700900002")
	for _, text := range []string{
		"Hi! €5 [ok] {braces} ~tilde^ |pipe\\",
		strings.Repeat("Long GSM text with €uro signs. ", 12),
		// Cyrillic on purpose, here and below: it does not fit the GSM 7-bit
		// alphabet, so these texts go as UCS-2.
		"Привет! Как дела? 👋",
		strings.Repeat("Длинное сообщение по-русски, чтобы порезалось на части. ", 5),
	} {
		parts, err := Submit(ParseNumber("+447700900001"), text, 7, 42)
		if err != nil {
			t.Fatal(err)
		}
		var got strings.Builder
		for i, p := range parts {
			d, err := ParseDeliver(deliverFromSubmit(t, p, from))
			if err != nil {
				t.Fatalf("%q part %d: %v", text[:10], i, err)
			}
			if len(parts) > 1 && (d.Part == nil || d.Part.Index != i+1 || d.Part.Total != len(parts) || d.Part.Ref != 42) {
				t.Fatalf("part header %+v", d.Part)
			}
			if d.Timestamp.Format(time.RFC3339) != "2026-11-03T21:00:00+01:00" {
				t.Fatalf("timestamp %s", d.Timestamp)
			}
			got.WriteString(d.Text)
		}
		if got.String() != text {
			t.Fatalf("round trip:\n got %q\nwant %q", got.String(), text)
		}
	}
}

func TestRPRoundTrip(t *testing.T) {
	sc := ParseNumber("+447700900500")
	for _, m := range []RP{
		{MTI: RPDataNToMS, MR: 9, OA: &sc, TPDU: []byte{1, 2, 3}},
		{MTI: RPDataMSToN, MR: 10, DA: &sc, TPDU: []byte{4}},
		{MTI: RPAckMSToN, MR: 11},
		{MTI: RPErrorMSToN, MR: 12, Cause: CauseMemoryExceeded},
		{MTI: RPAckNToMS, MR: 13, TPDU: []byte{0, 1}},
	} {
		b, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseRP(b)
		if err != nil || got.MTI != m.MTI || got.MR != m.MR || got.Cause != m.Cause || !bytes.Equal(got.TPDU, m.TPDU) {
			t.Fatalf("%+v → %+v %v", m, got, err)
		}
		if m.OA != nil && (got.OA == nil || got.OA.Number != "+447700900500") {
			t.Fatalf("OA %+v", got.OA)
		}
		if m.DA != nil && (got.DA == nil || got.DA.Number != "+447700900500") {
			t.Fatalf("DA %+v", got.DA)
		}
	}
}

// --- SIP level -------------------------------------------------------------

type fakeNet struct {
	t      *testing.T
	ps     *sipnet.Listener
	ue     *sipnet.Listener
	ueConn *sipnet.Conn
	toUE   *sipnet.Conn
	fromUE chan struct {
		conn *sipnet.Conn
		req  *sip.Request
	}
}

func (f *fakeNet) Conn() *sipnet.Conn { return f.ueConn }
func (f *fakeNet) SentBy() string     { return f.ue.Addr().String() }
func (f *fakeNet) IMPU() string       { return "sip:001010000000001@ims.test" }
func (f *fakeNet) Binding() (reg.Binding, bool) {
	return reg.Binding{Routes: []string{"<sip:orig@scscf.test;lr>"}}, true
}

func newFakeNet(t *testing.T, s **Service, cfg Config) *fakeNet {
	f := &fakeNet{t: t, fromUE: make(chan struct {
		conn *sipnet.Conn
		req  *sip.Request
	}, 8)}
	lo := netip.MustParseAddrPort("127.0.0.1:0")
	var err error
	f.ps, err = sipnet.Listen(lo, func(c *sipnet.Conn, r *sip.Request) {
		f.fromUE <- struct {
			conn *sipnet.Conn
			req  *sip.Request
		}{c, r}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	*s = New(f, cfg)
	f.ue, _ = sipnet.Listen(lo, func(c *sipnet.Conn, r *sip.Request) { (*s).Handle(c, r) }, nil)
	ctx := context.Background()
	f.ueConn, _ = sipnet.Dial(ctx, netip.AddrPort{}, f.ps.Addr(), func(c *sipnet.Conn, r *sip.Request) { (*s).Handle(c, r) }, nil)
	f.toUE, _ = sipnet.Dial(ctx, netip.AddrPort{}, f.ue.Addr(), nil, nil)
	t.Cleanup(func() { f.toUE.Close(); f.ueConn.Close(); f.ps.Close(); f.ue.Close() })
	return f
}

func (f *fakeNet) recvMessage() (*sipnet.Conn, *sip.Request, RP) {
	f.t.Helper()
	select {
	case in := <-f.fromUE:
		rp, err := ParseRP(in.req.Body())
		if err != nil || in.req.Method != sip.MESSAGE {
			f.t.Fatalf("%s %v", in.req.Method, err)
		}
		return in.conn, in.req, rp
	case <-time.After(3 * time.Second):
		f.t.Fatal("no MESSAGE from UE")
	}
	return nil, nil, RP{}
}

func (f *fakeNet) mtMessage(callID string, rp RP) *sip.Response {
	body, _ := rp.Marshal()
	r := sipnet.NewRequest("MESSAGE", "sip:ue@x").
		Add("Via", "SIP/2.0/TCP 127.0.0.1:9900;branch="+sipnet.NewBranch()).
		Add("From", "<sip:+447700900500@ims.test>;tag=sc").Add("To", "<tel:+447700900001>").
		Add("Call-ID", callID).Add("CSeq", "1 MESSAGE").
		Add("P-Asserted-Identity", "<sip:+447700900500@ims.test;user=phone>").
		Add("Content-Type", ContentType)
	r.Body = body
	res, err := f.toUE.Do(context.Background(), r, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return res
}

func TestMobileTerminatedConcatenated(t *testing.T) {
	var s *Service
	f := newFakeNet(t, &s, Config{Domain: "ims.test"})
	var mu sync.Mutex
	var got []Message
	s.OnMessage = func(m Message) error { mu.Lock(); got = append(got, m); mu.Unlock(); return nil }

	text := strings.Repeat("Тест длинного SMS. ", 6) // Cyrillic on purpose: UCS-2 in several parts
	parts, _ := Submit(ParseNumber("+447700900001"), text, 0, 77)
	sc := ParseNumber("+447700900500")
	for i, p := range parts {
		tpdu := deliverFromSubmit(t, p, ParseNumber("+447700900002"))
		res := f.mtMessage("mt"+string(rune('a'+i)), RP{MTI: RPDataNToMS, MR: byte(30 + i), OA: &sc, TPDU: tpdu})
		if res.StatusCode != 200 {
			t.Fatalf("MESSAGE answered %d", res.StatusCode)
		}
		_, req, rp := f.recvMessage()
		if rp.MTI != RPAckMSToN || rp.MR != byte(30+i) {
			t.Fatalf("report %+v", rp)
		}
		if req.Recipient.String() != "sip:+447700900500@ims.test;user=phone" ||
			req.GetHeaders("In-Reply-To")[0].Value() != "mt"+string(rune('a'+i)) {
			t.Fatalf("report addressing:\n%s", req)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Text != text || got[0].From != "+447700900002" || got[0].SMSC != "+447700900500" {
		t.Fatalf("%d messages: %+v", len(got), got)
	}
}

func TestMobileTerminatedWithoutStoreAsksRetry(t *testing.T) {
	var s *Service
	f := newFakeNet(t, &s, Config{Domain: "ims.test"})
	tp := unhex(t, "040B911346610089F60000208062917314080CC8F71D14969741F977FD07")
	f.mtMessage("mt1", RP{MTI: RPDataNToMS, MR: 5, TPDU: tp})
	_, _, rp := f.recvMessage()
	if rp.MTI != RPErrorMSToN || rp.Cause != CauseMemoryExceeded {
		t.Fatalf("%+v", rp)
	}
}

func TestMobileOriginated(t *testing.T) {
	var s *Service
	f := newFakeNet(t, &s, Config{Domain: "ims.test", SMSC: "+447700900500"})
	errc := make(chan error, 1)
	// Cyrillic on purpose: the TPDU must declare UCS-2 (DCS 0x08).
	go func() { errc <- s.Send(context.Background(), "+447700900002", "Привет из volte") }()
	conn, req, rp := f.recvMessage()
	if req.Recipient.String() != "sip:+447700900500@ims.test;user=phone" || rp.MTI != RPDataMSToN ||
		rp.DA == nil || rp.DA.Number != "+447700900500" || req.GetHeaders("Route")[0].Value() != "<sip:orig@scscf.test;lr>" {
		t.Fatalf("MO MESSAGE:\n%s\n%+v", req, rp)
	}
	if rp.TPDU[0]&3 != 1 || rp.TPDU[4+(int(rp.TPDU[2])+1)/2+1] != 0x08 {
		t.Fatalf("TPDU %x", rp.TPDU)
	}
	_ = conn.Respond(req, 202, "Accepted")
	ack, _ := RP{MTI: RPAckNToMS, MR: rp.MR}.Marshal()
	r := sipnet.NewRequest("MESSAGE", "sip:ue@x").
		Add("Via", "SIP/2.0/TCP 127.0.0.1:9900;branch="+sipnet.NewBranch()).
		Add("From", "<sip:+447700900500@ims.test>;tag=sc").Add("To", "<tel:+447700900001>").
		Add("Call-ID", "ack1").Add("CSeq", "1 MESSAGE").Add("Content-Type", ContentType)
	r.Body = ack
	if res, err := f.toUE.Do(context.Background(), r, nil); err != nil || res.StatusCode != 200 {
		t.Fatalf("RP-ACK MESSAGE: %v %v", res, err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Send did not complete")
	}
}
