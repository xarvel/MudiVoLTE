package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/MudiVoLTE/volte/media"
	"github.com/xarvel/MudiVoLTE/volte/sms"
)

// --- ATLink: the §69 trap ---

func TestATLinkRetriesWrongContext(t *testing.T) {
	var calls []string
	link := &ATLink{
		Run: func(ctx context.Context, cmd string) (string, error) {
			calls = append(calls, cmd)
			switch {
			case cmd == "AT+QUIMSUB=1;+QUIMSUB?":
				return "\r\n+QUIMSUB: 1,\"SUB1\"\r\n\r\nOK\r\n", nil
			case len(calls) < 5: // first attempts: the empty slot
				return "\r\n+CME ERROR: 10\r\n", nil
			default:
				return "\r\n+CGCONTRDP: 2,5,\"ims\",\"10.153.116.224/30\"\r\n\r\nOK\r\n", nil
			}
		},
	}
	out, err := link.command(context.Background(), "AT+CGCONTRDP=2")
	if err != nil {
		t.Fatalf("command: %v", err)
	}
	if !strings.Contains(out, "+CGCONTRDP: 2") {
		t.Errorf("reply without +CGCONTRDP: %q", out)
	}
	if len(calls) < 4 { // QUIMSUB+command at least twice
		t.Errorf("want a retry, calls: %d", len(calls))
	}
}

func TestATLinkSubscriptionNotConfirmed(t *testing.T) {
	link := &ATLink{
		Retries: 2,
		Run: func(ctx context.Context, cmd string) (string, error) {
			if cmd == "AT+QUIMSUB=1;+QUIMSUB?" {
				return "\r\n+QUIMSUB: 2,\"SUB2\",\"No Service\"\r\n\r\nOK\r\n", nil
			}
			return "", errors.New("the command must not get through without SUB1")
		},
	}
	if _, err := link.command(context.Background(), "AT+CGSN"); err == nil {
		t.Fatal("want a subscription error")
	} else if !strings.Contains(err.Error(), "SUB1") {
		t.Errorf("the error does not mention the subscription: %v", err)
	}
}

func TestATLinkExhaustsRetries(t *testing.T) {
	link := &ATLink{
		Retries: 2,
		Run: func(ctx context.Context, cmd string) (string, error) {
			if cmd == "AT+QUIMSUB=1;+QUIMSUB?" {
				return "+QUIMSUB: 1\r\nOK", nil
			}
			return "\r\nERROR\r\n", nil
		},
	}
	if _, err := link.command(context.Background(), "AT+CSIM=4,\"00A40000\""); err == nil {
		t.Fatal("want the retries to run out")
	}
}

// SQN protection (§72): a valid SIM reply (+CSIM:) is never retried, not even DC.
func TestCSIMResponseNeverRetried(t *testing.T) {
	var dataCalls int
	link := &ATLink{Run: func(ctx context.Context, cmd string) (string, error) {
		if cmd == "AT+QUIMSUB=1;+QUIMSUB?" {
			return "\r\n+QUIMSUB: 1,\"SUB1\"\r\n\r\nOK\r\n", nil
		}
		dataCalls++
		return "\r\n+CSIM: 4,\"DC00\"\r\n\r\nOK\r\n", nil
	}}
	out, err := link.command(context.Background(), "AT+CSIM=32,\"0011...\"")
	if err != nil {
		t.Fatal(err)
	}
	if dataCalls != 1 {
		t.Errorf("+CSIM reply was retried: %d calls", dataCalls)
	}
	if !strings.Contains(out, "+CSIM:") {
		t.Errorf("reply not passed through: %q", out)
	}
}

// --- CSIM Transmitter ---

// An APDU goes in one AT line with the slot selection (§117): a live SIM in
// the other slot answers as normally as ours, so nothing else would show it.
func TestCSIMPinnedInOneLine(t *testing.T) {
	var calls []string
	link := &ATLink{Run: func(ctx context.Context, cmd string) (string, error) {
		calls = append(calls, cmd)
		return "\r\n+QUIMSUB: 1,\"SUB1\",\"L\"\r\n\r\n+CSIM: 8,\"3F009000\"\r\n\r\nOK\r\n", nil
	}}
	resp, err := newCSIMTransmitter(link).Transmit(context.Background(), []byte{0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || !strings.HasPrefix(calls[0], "AT+QUIMSUB=1;+QUIMSUB?;+CSIM=") {
		t.Fatalf("calls: %q", calls)
	}
	if len(resp) != 4 || resp[2] != 0x90 || resp[3] != 0x00 {
		t.Errorf("resp = % X", resp)
	}
}

// Right after boot a compound line can fail (§69): the APDU goes the old way.
func TestCSIMFallsBackWhenTheLineFails(t *testing.T) {
	var calls []string
	link := &ATLink{Run: func(ctx context.Context, cmd string) (string, error) {
		calls = append(calls, cmd)
		switch {
		case strings.HasPrefix(cmd, "AT+QUIMSUB=1;+QUIMSUB?;"):
			return "\r\nERROR\r\n", nil
		case cmd == "AT+QUIMSUB=1;+QUIMSUB?":
			return "\r\n+QUIMSUB: 1,\"SUB1\"\r\n\r\nOK\r\n", nil
		}
		return "\r\n+CSIM: 8,\"3F009000\"\r\n\r\nOK\r\n", nil
	}}
	if _, err := newCSIMTransmitter(link).Transmit(context.Background(), []byte{0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 || !strings.HasPrefix(calls[2], "AT+CSIM=") {
		t.Fatalf("calls: %q", calls)
	}
}

func TestCSIMTransmitterTransmit(t *testing.T) {
	link := &ATLink{Run: func(ctx context.Context, cmd string) (string, error) {
		if cmd == "AT+QUIMSUB=1;+QUIMSUB?" {
			return "\r\n+QUIMSUB: 1,\"SUB1\"\r\n\r\nOK\r\n", nil
		}
		if !strings.HasPrefix(cmd, "AT+CSIM=") {
			return "", errors.New("unexpected command " + cmd)
		}
		return "\r\n+CSIM: 8,\"3F009000\"\r\n\r\nOK\r\n", nil
	}}
	tx := newCSIMTransmitter(link)
	apdu := []byte{0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00} // SELECT MF
	resp, err := tx.Transmit(context.Background(), apdu)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != 4 || resp[2] != 0x90 || resp[3] != 0x00 {
		t.Errorf("resp = % X", resp)
	}
}

func TestCSIMTransmitterTransportError(t *testing.T) {
	link := &ATLink{
		Retries: 1,
		Run: func(ctx context.Context, cmd string) (string, error) {
			if cmd == "AT+QUIMSUB=1;+QUIMSUB?" {
				return "+QUIMSUB: 1\r\nOK", nil
			}
			return "\r\nERROR\r\n", nil
		},
	}
	tx := newCSIMTransmitter(link)
	if _, err := tx.Transmit(context.Background(), []byte{0x00, 0xA4, 0x00, 0x04}); err == nil {
		t.Fatal("want a transport error")
	}
}

// --- PDN: discovery and parsing ---

func TestFindIMSIface(t *testing.T) {
	oldIf, oldAd, oldDef := netIfaces, netAddrs, defaultRouteIface
	defer func() { netIfaces, netAddrs, defaultRouteIface = oldIf, oldAd, oldDef }()
	// The numbers have swapped places (§87): internet on rmnet_data1, IMS on rmnet_data0.
	netIfaces = func() ([]net.Interface, error) {
		return []net.Interface{{Name: "lo"}, {Name: "rmnet_data0"}, {Name: "rmnet_data1"}, {Name: "rmnet_data2"}}, nil
	}
	netAddrs = func(name string) ([]net.Addr, error) {
		switch name {
		case "rmnet_data0": // IMS-PDN
			return []net.Addr{&net.IPNet{IP: net.ParseIP("198.51.100.207")}}, nil
		case "rmnet_data1": // internet PDN
			return []net.Addr{&net.IPNet{IP: net.ParseIP("10.181.173.198")}}, nil
		case "rmnet_data2":
			return nil, nil
		}
		return nil, errors.New("no such interface")
	}
	defaultRouteIface = func() string { return "rmnet_data1" }

	// The address from CGCONTRDP decides.
	iface, ip, err := findIMSIface("auto", net.ParseIP("198.51.100.207"))
	if err != nil || iface != "rmnet_data0" || !ip.Equal(net.ParseIP("198.51.100.207")) {
		t.Errorf("by address: iface=%s ip=%v err=%v", iface, ip, err)
	}
	if _, _, err := findIMSIface("auto", net.ParseIP("10.1.2.3")); err == nil {
		t.Error("a foreign address was found")
	}
	// Without an address: anything but the interface of the default route.
	defaultRouteIface = func() string { return "rmnet_data0" }
	iface, _, err = findIMSIface("auto", nil)
	if err != nil || iface != "rmnet_data1" {
		t.Errorf("without an address: iface=%s err=%v", iface, err)
	}
	// A specific interface from the config.
	iface, ip, err = findIMSIface("rmnet_data1", nil)
	if err != nil || iface != "rmnet_data1" || ip == nil {
		t.Errorf("specific interface: %v %v %v", iface, ip, err)
	}
}

func TestParseCGCONTRDP(t *testing.T) {
	// A live reply (§75, DNS addresses replaced): the gateway is empty, the P-CSCFs come after the DNS servers.
	out := "\r\n+CGCONTRDP: 2,6,\"ims\",\"198.51.100.20\",,\"203.0.113.105\",\"203.0.113.106\",\"192.0.2.20\",\"192.0.2.28\"\r\n\r\nOK\r\n"
	info := parseCGCONTRDP(out)
	if info.APN != "ims" || !info.Local.Equal(net.ParseIP("198.51.100.20")) {
		t.Errorf("apn/local: %+v", info)
	}
	if len(info.PCSCF) != 2 || !info.PCSCF[0].Equal(net.ParseIP("192.0.2.20")) || !info.PCSCF[1].Equal(net.ParseIP("192.0.2.28")) {
		t.Errorf("P-CSCF (DNS servers must not get here): %v", info.PCSCF)
	}
	// An address with the mask in dotted form, a second line with IPv6 and one more P-CSCF.
	out = "+CGCONTRDP: 2,5,\"ims\",\"10.1.2.3.255.255.255.0\",\"10.1.2.1\",\"8.8.8.8\",\"\",\"10.9.9.9\"\r\n" +
		"+CGCONTRDP: 2,5,\"ims\",\"32.1.0.0.0.0.0.0.0.0.0.0.0.0.0.1\",,,,\"10.9.9.9\",\"10.9.9.10\"\r\nOK"
	info = parseCGCONTRDP(out)
	if !info.Local.Equal(net.ParseIP("10.1.2.3")) || len(info.PCSCF) != 2 || !info.PCSCF[1].Equal(net.ParseIP("10.9.9.10")) {
		t.Errorf("mask/two lines: %+v", info)
	}
	if info := parseCGCONTRDP("ERROR"); info.Local != nil || info.PCSCF != nil {
		t.Error("want empty")
	}
}

func TestParseIMSProfile(t *testing.T) {
	out := "\r\n+CGDCONT: 1,\"IPV4V6\",\"internet\",\"0.0.0.0\",0,0\r\n+CGDCONT: 2,\"IPV4V6\",\"ims\",\"0.0.0.0\",0,0\r\n+CGDCONT: 3,\"IPV4V6\",\"sos\",\"\",0,0\r\n\r\nOK\r\n"
	if cid := parseIMSProfile(out); cid != 2 {
		t.Fatalf("cid = %d", cid)
	}
	if cid := parseIMSProfile("+CGDCONT: 1,\"IP\",\"internet\"\r\nOK"); cid != 0 {
		t.Fatalf("without ims: %d", cid)
	}
}

// --- Identities and config ---

func TestDeriveIdentities(t *testing.T) {
	ids, err := deriveIdentities("001010123456789", "001", "01", "")
	if err != nil {
		t.Fatal(err)
	}
	if ids.Domain != "ims.mnc001.mcc001.3gppnetwork.org" || ids.IMPI != "001010123456789@ims.mnc001.mcc001.3gppnetwork.org" ||
		ids.IMPU != "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org" {
		t.Fatalf("%+v", ids)
	}
	if ids, _ := deriveIdentities("310260123456789", "310", "260", ""); ids.Domain != "ims.mnc260.mcc310.3gppnetwork.org" {
		t.Fatalf("three-digit MNC: %+v", ids)
	}
	if _, err := deriveIdentities("abc", "001", "01", ""); err == nil {
		t.Fatal("a malformed IMSI accepted")
	}
}

func TestRunCheckOffline(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := runCheck(defaultConfig(), logger); err != nil {
		t.Fatal(err)
	}
	bad := defaultConfig()
	bad.PCSCF = []string{"not-an-ip"}
	if runCheck(bad, logger) == nil {
		t.Fatal("a malformed P-CSCF accepted")
	}
	last := defaultConfig()
	last.IMSProfile = 255
	if err := runCheck(last, logger); err != nil {
		t.Errorf("ims_profile 255: %v", err)
	}
	for _, profile := range []int{-1, 256} {
		bad = defaultConfig()
		bad.IMSProfile = profile
		if err := runCheck(bad, logger); err == nil || !strings.Contains(err.Error(), "ims_profile") {
			t.Fatalf("ims_profile %d accepted: %v", profile, err)
		}
	}
}

func TestCauseError(t *testing.T) {
	var de *dialError
	if err := causeError("486 Busy Here"); !errors.As(err, &de) || de.Code != 486 || de.Reason != "Busy Here" {
		t.Fatalf("%v", err)
	}
	if err := causeError("INVITE: connection reset"); errors.As(err, &de) {
		t.Fatal("a transport error became a code")
	}
}

func TestLoadConfigDefaultsAndOverride(t *testing.T) {
	cfg, err := loadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "check" || cfg.Interface != "auto" || cfg.PCSCFPort != 5060 || !cfg.looseSrcPort() {
		t.Errorf("defaults: %+v", cfg)
	}
	// The defaults are not tied to an operator: the P-CSCF comes from CGCONTRDP.
	if len(cfg.pcscfIPs()) != 0 {
		t.Errorf("default pcscf: %v", cfg.PCSCF)
	}
	if cfg.stateFile() != "/var/run/mudi-volte/state.json" || cfg.dsiHelper() != "/usr/sbin/mudi-dsi-helper" {
		t.Errorf("default paths: %q %q", cfg.stateFile(), cfg.dsiHelper())
	}
	path := filepath.Join(t.TempDir(), "c.json")
	// dsi_path named the firmware's tool for version 0.1.0, which placed the
	// data call with it: a config that still has the key is read as before.
	if err := os.WriteFile(path, []byte(`{"mode":"daemon","pcscf":["192.0.2.20"],"loose_inbound_src_port":false,"dsi_path":"/usr/bin/dsi_netctrl_test","dsi_helper":"/tmp/helper"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg2, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Mode != "daemon" || len(cfg2.PCSCF) != 1 || cfg2.PCSCFPort != 5060 || cfg2.looseSrcPort() ||
		cfg2.dsiHelper() != "/tmp/helper" {
		t.Errorf("overlay: %+v", cfg2)
	}
}

// --- Gates and parsing ---

func TestDaemonGate(t *testing.T) {
	// The S3 gate inside runDaemon: without --hold-registration it refuses
	// BEFORE any network action.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := runDaemon(defaultConfig(), logger, false)
	if err == nil || !strings.Contains(err.Error(), "hold-registration") {
		t.Fatalf("daemon gate did not trigger: %v", err)
	}
}

func TestNumberAllowed(t *testing.T) {
	allow := []string{"+995 555 123 456", "447700900123"}
	cases := []struct {
		from string
		want bool
	}{
		{"+995555123456", true},  // full, with the plus
		{"995555123456", true},   // without the plus
		{"+7995555123456", true}, // suffix match (long prefix)
		{"+447700900123", true},  // the second number
		{"+447700900789", false}, // not on the list
		{"", false},              // empty
	}
	for _, tc := range cases {
		if got := numberAllowed(allow, tc.from); got != tc.want {
			t.Errorf("numberAllowed(%q) = %v, want %v", tc.from, got, tc.want)
		}
	}
	if numberAllowed(nil, "+995555123456") {
		t.Error("an empty allow must reject everyone")
	}
	if numberAllowed([]string{"456"}, "+995559999456") {
		t.Error("a short entry must not match as a suffix")
	}
	if !numberAllowed([]string{"456"}, "456") {
		t.Error("short entry: an exact match must work")
	}
}

func TestMaskNumber(t *testing.T) {
	if got := maskNumber("+995555123456"); got != "…3456" {
		t.Errorf("maskNumber = %q", got)
	}
	if got := maskNumber(""); got != "" {
		t.Errorf("maskNumber(\"\") = %q", got)
	}
	// The cell in the log: the PLMN is visible (5 or 6 digits), the TAC and ECI are not.
	for in, want := range map[string]string{
		"3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=001013C0D01A2B03":  "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=00101…",
		"3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=3102603C0D01A2B03": "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=310260…",
		"3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=3C0D01A":           "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=…",
		"IEEE-802.11": "IEEE-802.11",
	} {
		if got := maskANI(in); got != want {
			t.Errorf("maskANI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseIMEI(t *testing.T) {
	got := parseIMEI("\r\n864184061234567\r\n\r\nOK\r\n")
	if got != "864184061234567" {
		t.Errorf("parseIMEI = %q", got)
	}
	if parseIMEI("\r\nERROR\r\n") != "" {
		t.Error("want an empty IMEI on ERROR")
	}
	if parseIMEI("\r\n8641840612345678\r\n") != "" {
		t.Error("16 digits are not an IMEI")
	}
}

func TestParseQENGANI(t *testing.T) {
	// Live format (S2/S3, with the state field):
	out := "+QENG: \"servingcell\",\"NOCONN\",\"LTE\",\"FDD\",001,01,1A2B03,123,1300,3,5,5,3C0D,-102,-14,-67,12,0,-,25\r\nOK"
	ani, err := parseQENGANI(out)
	if err != nil {
		t.Fatal(err)
	}
	want := "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=001013C0D01A2B03" // TAC 3C0D (§85)
	if ani != want {
		t.Errorf("ani = %q, want %q", ani, want)
	}
	// Shifted format (no state: a transient modem state, caught on 03.11):
	out2 := "+QENG: \"servingcell\",\"LTE\",\"FDD\",001,01,1A2B03,123,1300,3,5,5,3C0D,-102\r\nOK"
	ani2, err := parseQENGANI(out2)
	if err != nil {
		t.Fatal(err)
	}
	if ani2 != want {
		t.Errorf("ani2 = %q, want %q", ani2, want)
	}
	// Multi-line EN-DC (a live reply, 03.11 17:36, §85).
	out3 := "\r\n+QENG: \"servingcell\",\"NOCONN\"\r\n+QENG: \"LTE\",\"FDD\",001,01,1A2B03,123,1300,3,5,5,3C0D,-103,-15,-67,10,8,127,-\r\n+QENG: \"NR5G-NSA\",001,01,123,-104,13,-10,636768,7\r\n\r\nOK\r\n"
	if ani3, err := parseQENGANI(out3); err != nil || ani3 != want {
		t.Errorf("EN-DC: ani = %q, err = %v, want %q", ani3, err, want)
	}
	if _, err := parseQENGANI("\r\nERROR\r\n"); err == nil {
		t.Error("want an error without +QENG")
	}
	if _, err := parseQENGANI("+QENG: \"servingcell\",\"NOCONN\",\"NR5G\",\"TDD\",1,2,3,4,5,6,7\r\nOK"); err == nil {
		t.Error("want an error for non-LTE")
	}
}

// TestIMSLegRoundtrip runs the network leg as in a live call: 16 kHz PCM →
// network codec → RTP → back. G.711 works in any build; AMR-WB when the
// codec is linked in (cgo).
func TestIMSLegRoundtrip(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []NetMedia{{Negotiated: true, Codec: "PCMA", PayloadType: 8, ClockRate: 8000}}
	if media.NewAMRWBCoder != nil {
		cases = append(cases, NetMedia{Negotiated: true, Codec: "AMR-WB", PayloadType: 101, ClockRate: 16000, ModeSet: "0,1,2"})
	}
	for _, m := range cases {
		call := newLoopCall(m)
		leg, err := newIMSLeg(call, logger)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		got := make(chan []int16, 64)
		go func() { _ = leg.Run(ctx, func(p []int16) { got <- p }) }()
		var ph float64
		for i := 0; i < 30; i++ {
			if err := leg.WriteFrame(ctx, tone(frameSamples16k, 16000, 440, 6000, &ph)); err != nil {
				t.Fatal(err)
			}
		}
		var energy float64
		for i := 0; i < 30; i++ {
			select {
			case p := <-got:
				if len(p) != frameSamples16k {
					t.Fatalf("%s: frame of %d samples", m.Codec, len(p))
				}
				if i >= 10 {
					for _, s := range p {
						energy += float64(s) * float64(s)
					}
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("%s: got %d frames of 30", m.Codec, i)
			}
		}
		cancel()
		if energy < 20*320*1e6 {
			t.Errorf("%s: no audio came through (energy %.3g)", m.Codec, energy)
		}
	}
}

// loopCall is a network that returns our own RTP packets.
type loopCall struct {
	m    NetMedia
	loop chan []byte
}

func newLoopCall(m NetMedia) *loopCall { return &loopCall{m: m, loop: make(chan []byte, 128)} }

func (c *loopCall) Media() NetMedia { return c.m }
func (c *loopCall) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case p := <-c.loop:
		return p, nil, nil
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}
func (c *loopCall) WriteRTP(_ context.Context, data []byte) error {
	c.loop <- append([]byte(nil), data...)
	return nil
}

func TestSaveSMS(t *testing.T) {
	dir := t.TempDir()
	cfg := &Config{SMSInbox: dir + "/inbox.jsonl"}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// The non-ASCII letter in the SMS text is deliberate: the check below makes
	// sure such text reaches the inbox as plain UTF-8, not as \u escapes.
	if err := saveSMS(cfg, logger, sms.Message{From: "+447700900456", Text: "Código: 1234", Time: time.Unix(0, 0)}); err != nil {
		t.Fatal(err)
	}
	if err := saveSMS(cfg, logger, sms.Message{From: "Operator", Text: "Balance"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(cfg.SMSInbox)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(b), "\n"); n != 2 || !strings.Contains(string(b), "Código: 1234") {
		t.Fatalf("inbox: %q", b)
	}
	if st, _ := os.Stat(cfg.SMSInbox); st.Mode().Perm() != 0o600 {
		t.Fatalf("permissions %v", st.Mode().Perm())
	}
}

func TestSaveSMSFailureIsReported(t *testing.T) {
	cfg := &Config{SMSInbox: filepath.Join(t.TempDir(), "no-such-dir", "inbox.jsonl")}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if saveSMS(cfg, logger, sms.Message{From: "+44", Text: "x"}) == nil {
		t.Fatal("a write error must reach the network as RP-ERROR")
	}
}
