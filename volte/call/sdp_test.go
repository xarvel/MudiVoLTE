package call

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func TestParseLiveOffer(t *testing.T) {
	body, err := os.ReadFile("testdata/live_offer.sdp")
	if err != nil {
		t.Fatal(err)
	}
	a, err := ParseSDP(body)
	if err != nil {
		t.Fatal(err)
	}
	if a.Addr != netip.MustParseAddrPort("192.0.2.82:26390") || a.Ptime != 20 || a.Direction != "sendrecv" {
		t.Fatalf("%+v", a)
	}
	if len(a.Formats) != 17 || a.Formats[0].Name != "AMR-WB" || a.Formats[0].ClockRate != 16000 {
		t.Fatalf("formats %+v", a.Formats[:2])
	}
	if ms, _ := a.Formats[0].Param("mode-set"); ms != "0,1,2" {
		t.Fatalf("mode-set %q", ms)
	}
	n, err := Negotiate(a, DefaultCodecs)
	if err != nil {
		t.Fatal(err)
	}
	if n.Codec.PT != 101 || n.DTMF == nil || n.DTMF.PT != 116 || n.Codec.OctetAligned() {
		t.Fatalf("negotiated %+v dtmf %+v", n.Codec, n.DTMF)
	}
	ans := string(n.Answer(netip.MustParseAddrPort("198.51.100.26:40000"), 7, 1, a.Direction).Bytes())
	for _, want := range []string{
		"o=- 7 1 IN IP4 198.51.100.26\r\n", "c=IN IP4 198.51.100.26\r\n", "m=audio 40000 RTP/AVP 101 116\r\n",
		"a=rtpmap:101 AMR-WB/16000\r\n", "a=fmtp:101 mode-set=0,1,2;", "a=rtpmap:116 telephone-event/16000\r\n",
		"a=fmtp:116 0-15\r\n", "a=sendrecv\r\n",
	} {
		if !strings.Contains(ans, want) {
			t.Errorf("answer lacks %q:\n%s", want, ans)
		}
	}
	// The answer must parse back to the same stream.
	back, err := ParseSDP([]byte(ans))
	if err != nil || back.Formats[0].PT != 101 {
		t.Fatalf("round trip: %v %+v", err, back)
	}
}

func TestNegotiateFallbackAndHold(t *testing.T) {
	offer := "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 5004 RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\na=sendonly\r\n"
	a, err := ParseSDP([]byte(offer))
	if err != nil {
		t.Fatal(err)
	}
	n, err := Negotiate(a, DefaultCodecs)
	if err != nil || n.Codec.Name != "PCMU" || n.DTMF == nil {
		t.Fatalf("%+v %v", n, err)
	}
	if d := n.Answer(netip.MustParseAddrPort("192.0.2.2:6000"), 1, 1, a.Direction); d.Direction != "recvonly" {
		t.Fatalf("hold answer direction %q", d.Direction)
	}
	if _, err := Negotiate(a, []string{"AMR-WB"}); err == nil {
		t.Fatal("expected no common codec")
	}
}

func TestOfferFormatsFiltered(t *testing.T) {
	var names []string
	for _, f := range OfferFormats([]string{"PCMA", "PCMU"}) {
		names = append(names, fmt.Sprintf("%s/%d", f.Name, f.ClockRate))
	}
	if got := strings.Join(names, " "); got != "PCMA/8000 PCMU/8000 telephone-event/8000" {
		t.Fatal(got)
	}
	if len(OfferFormats(nil)) != 5 {
		t.Fatal("unfiltered offer")
	}
}
