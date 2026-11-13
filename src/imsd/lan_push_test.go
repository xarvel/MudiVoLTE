package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/emiago/sipgo/sip"
)

// The Contact of Linphone 6 on an iPhone (tokens made up): two tokens, VoIP
// and remote, in one pn-prid, and the app in pn-param.
const linphoneIOSContact = "sip:iphone@192.168.8.20:57607;transport=tls;pn-prid=v1:voip&r1:remote;" +
	"pn-provider=apns;pn-param=ABCD1234.org.linphone.phone.voip&remote;pn-silent=1;pn-timeout=0;pn-call-str=IC_MSG"

func TestContactPush(t *testing.T) {
	var u sip.Uri
	if err := sip.ParseUri(linphoneIOSContact, &u); err != nil {
		t.Fatal(err)
	}
	p, ok := contactPush(u)
	if !ok {
		t.Fatal("no push parameters")
	}
	want := pushParams{Provider: "apns", Param: "ABCD1234.org.linphone.phone.voip&remote", PRID: "v1:voip&r1:remote"}
	if p != want {
		t.Fatalf("got %+v, want %+v", p, want)
	}
	// Case of the names does not matter; without a token there is nothing to wake.
	if err := sip.ParseUri("sip:pixel@192.168.8.120:5060;PN-Provider=fcm;PN-PRID=abc;pn-param=proj", &u); err != nil {
		t.Fatal(err)
	}
	if p, ok := contactPush(u); !ok || p.Provider != "fcm" || p.PRID != "abc" {
		t.Fatalf("mixed case: %+v %v", p, ok)
	}
	if err := sip.ParseUri("sip:pixel@192.168.8.120:5060;pn-provider=fcm", &u); err != nil {
		t.Fatal(err)
	}
	if _, ok := contactPush(u); ok {
		t.Fatal("a provider without a token counts")
	}
}

func TestPushSignOutPersistsAndKeepsOtherDevices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "push.json")
	s := newPushStore(path)
	var contact sip.Uri
	if err := sip.ParseUri(linphoneIOSContact, &contact); err != nil {
		t.Fatal(err)
	}
	for _, device := range []struct{ user, instance string }{{"iphone", "a"}, {"iphone", "b"}, {"pixel", "c"}} {
		if _, err := s.remember(device.user, device.instance, contact, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.forget("iphone", "a", contact, false); err != nil {
		t.Fatal(err)
	}
	s = newPushStore(path)
	if ps := s.forUser("iphone"); len(ps) != 1 || ps[0].Instance != "b" {
		t.Fatalf("remaining devices: %+v", ps)
	}
	if err := s.forget("iphone", "", sip.Uri{Wildcard: true}, true); err != nil {
		t.Fatal(err)
	}
	s = newPushStore(path)
	if len(s.forUser("iphone")) != 0 || len(s.forUser("pixel")) != 1 {
		t.Fatal("wildcard sign-out did not preserve other logins")
	}
}

func TestPushStoreWritesOnlyChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "push.json")
	s := newPushStore(path)
	var u sip.Uri
	if err := sip.ParseUri(linphoneIOSContact, &u); err != nil {
		t.Fatal(err)
	}
	t0 := time.Date(2026, 11, 7, 13, 0, 0, 0, time.UTC)
	if changed, err := s.remember("iphone", "urn:uuid:1", u, t0); err != nil || !changed {
		t.Fatalf("first: %v %v", changed, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v: the tokens are the owner's only", st.Mode().Perm())
	}
	// The same parameters on the next REGISTER: no write.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.remember("iphone", "urn:uuid:1", u, t0.Add(time.Hour)); err != nil || changed {
		t.Fatalf("same again: %v %v", changed, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("rewritten without a change")
	}
	// A new token of the same device replaces the old one.
	if err := sip.ParseUri("sip:iphone@192.168.8.20:57700;transport=tls;pn-provider=apns;pn-param=ABCD1234.org.linphone.phone.voip&remote;pn-prid=99:voip&88:remote", &u); err != nil {
		t.Fatal(err)
	}
	if changed, err := s.remember("iphone", "urn:uuid:1", u, t0.Add(2*time.Hour)); err != nil || !changed {
		t.Fatalf("new token: %v %v", changed, err)
	}
	// A phone without push parameters (Android with its own service) is not kept.
	if err := sip.ParseUri("sip:pixel@192.168.8.120:5060", &u); err != nil {
		t.Fatal(err)
	}
	if changed, _ := s.remember("pixel", "urn:uuid:2", u, t0); changed {
		t.Fatal("a Contact without push parameters was kept")
	}

	// After a restart: the same, and a removed login is dropped.
	s2 := newPushStore(path)
	got := s2.forUser("iphone")
	if len(got) != 1 || got[0].PRID != "99:voip&88:remote" || got[0].Instance != "urn:uuid:1" || !got[0].Updated.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("reloaded: %+v", got)
	}
	if err := s2.keepOnly([]SIPAccount{{User: "pixel"}}); err != nil {
		t.Fatal(err)
	}
	if got := newPushStore(path).forUser("iphone"); len(got) != 0 {
		t.Fatalf("removed phone kept: %+v", got)
	}
}

func TestRegisterKeepsPushParameters(t *testing.T) {
	rig := newTestRig(t, &Config{}, false)
	p := newTestPhoneUser(t, "127.0.0.1", "iphone")
	p.instance = `"<urn:uuid:5f0c6d3e-0000-4000-8000-000000000202>"`
	p.pn = []sip.HeaderKV{{K: "pn-provider", V: "apns"}, {K: "pn-param", V: "ABCD1234.org.linphone.phone.voip&remote"},
		{K: "pn-prid", V: "0a1b2c:voip&d4e5f6:remote"}}
	res, err := p.register(rig.srvAddr, testPass)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("REGISTER: %v %v", res, err)
	}
	got := rig.lan.push.forUser("iphone")
	if len(got) != 1 || got[0].Provider != "apns" || got[0].PRID != "0a1b2c:voip&d4e5f6:remote" ||
		got[0].Instance != "urn:uuid:5f0c6d3e-0000-4000-8000-000000000202" {
		t.Fatalf("push parameters: %+v", got)
	}
}
