package main

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// iphonePush is what the daemon keeps from the Contact of Linphone on an
// iPhone (tokens made up).
var iphonePush = pushParams{User: "iphone", Instance: "urn:uuid:1", Provider: "apns",
	Param: "ABCD1234.org.linphone.phone.voip&remote", PRID: "0a1b2c3d4e5f:voip&f5e4d3c2b1a0:remote"}

func TestAPNSCall(t *testing.T) {
	for _, tc := range []struct {
		name         string
		p            pushParams
		param, token string
		ok           bool
	}{
		{"two tokens", iphonePush, "ABCD1234.org.linphone.phone.voip", "0a1b2c3d4e5f", true},
		{"remote first", pushParams{Provider: "apns", Param: "T.org.linphone.phone.remote&voip", PRID: "r1:remote&v1:voip"}, "T.org.linphone.phone.voip", "v1", true},
		{"one token for voip", pushParams{Provider: "apns.dev", Param: "T.org.linphone.phone.voip", PRID: "v2"}, "T.org.linphone.phone.voip", "v2", true},
		{"escaped", pushParams{Provider: "apns", Param: "T.org.linphone.phone.voip%26remote", PRID: "v3:voip%26r3:remote"}, "T.org.linphone.phone.voip", "v3", true},
		{"remote only", pushParams{Provider: "apns", Param: "T.org.linphone.phone.remote", PRID: "r4:remote"}, "", "", false},
		{"android", pushParams{Provider: "fcm", Param: "251776523448", PRID: "abc:APA91b"}, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			param, token, ok := tc.p.apnsCall()
			if ok != tc.ok || param != tc.param || token != tc.token {
				t.Fatalf("got %q %q %v, want %q %q %v", param, token, ok, tc.param, tc.token, tc.ok)
			}
		})
	}
}

// Linphone on Android sends pn-provider=fcm, pn-param=<Firebase project
// number> and pn-prid=<FCM token>, whose ':' is part of the token.
func TestCallPush(t *testing.T) {
	android := pushParams{Provider: "fcm", Param: "123456789012", PRID: "dXyZ_1:APA91b-x_y"}
	if param, token, ok := android.callPush(); !ok || param != "123456789012" || token != "dXyZ_1:APA91b-x_y" {
		t.Fatalf("android: %q %q %v", param, token, ok)
	}
	if param, token, ok := (pushParams{Provider: "fcm", Param: "1", PRID: "a%3Ab"}).callPush(); !ok || param != "1" || token != "a:b" {
		t.Fatalf("escaped android token: %q %q %v", param, token, ok)
	}
	if param, token, ok := iphonePush.callPush(); !ok || param != "ABCD1234.org.linphone.phone.voip" || token != "0a1b2c3d4e5f" {
		t.Fatalf("iphone: %q %q %v", param, token, ok)
	}
	if !android.canPush() || !iphonePush.canPush() {
		t.Fatal("a phone that sent push parameters cannot be woken")
	}
	for _, p := range []pushParams{
		{Provider: "fcm", Param: "", PRID: "x"},
		{Provider: "fcm", Param: "1", PRID: ""},
		{Provider: "webpush", Param: "x", PRID: "y"},
		{Provider: "apns", Param: "T.org.linphone.phone.remote", PRID: "r:remote"},
	} {
		if p.canPush() {
			t.Errorf("%+v counts as a phone that can be woken for a call", p)
		}
	}
}

func TestParseDigest(t *testing.T) {
	c, ok := parseDigest(`Digest realm=sip.linphone.org,qop=auth,algorithm=SHA-256,nonce="a,b\"c",opaque="o"`)
	if !ok || c.realm != "sip.linphone.org" || c.qop != "auth" || c.algorithm != "SHA-256" || c.nonce != `a,b"c` || c.opaque != "o" {
		t.Fatalf("%+v %v", c, ok)
	}
	if _, ok := parseDigest(`Basic realm="x"`); ok {
		t.Fatal("Basic taken for Digest")
	}
	got, ok := pickDigest([]string{`Digest realm=r,algorithm=MD5,nonce="n1"`, `Digest realm=r,algorithm=SHA-256,nonce="n2"`, `Digest realm=r,algorithm=SHA-512-256,nonce="n3"`})
	if !ok || got.nonce != "n2" {
		t.Fatalf("SHA-256 not chosen: %+v", got)
	}
}

// fakeFlexiAPI answers POST /api/push_notification like FlexiAPI: a 401 with
// MD5 and SHA-256 challenges, then checks the Digest response and the body.
type fakeFlexiAPI struct {
	t        *testing.T
	login    string
	password string
	status   int // after a good signature; 0 = 200

	mu     sync.Mutex
	bodies []map[string]string
	algos  []string
}

func (s *fakeFlexiAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != "/api/push_notification" {
		http.NotFound(w, r)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" {
		http.Error(w, "content-type and accept are required", http.StatusBadRequest)
		return
	}
	if r.Header.Get("From") != "sip:"+s.login+"@sip.linphone.org" {
		http.NotFound(w, r) // like FlexiAPI for an unknown account
		return
	}
	body, _ := io.ReadAll(r.Body)
	scheme, p := parseAuthParams(r.Header.Get("Authorization"))
	if scheme != "Digest" {
		w.Header().Add("WWW-Authenticate", `Digest realm=sip.linphone.org,qop=auth,algorithm=MD5,nonce="n-md5",opaque="op"`)
		w.Header().Add("WWW-Authenticate", `Digest realm=sip.linphone.org,qop=auth,algorithm=SHA-256,nonce="n-sha",opaque="op"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var newHash func() hash.Hash = md5.New
	if p["algorithm"] == "SHA-256" {
		newHash = sha256.New
	}
	h := func(s string) string {
		x := newHash()
		x.Write([]byte(s))
		return hex.EncodeToString(x.Sum(nil))
	}
	ha1 := h(p["username"] + ":" + p["realm"] + ":" + s.password)
	ha2 := h(r.Method + ":" + p["uri"])
	want := h(ha1 + ":" + p["nonce"] + ":" + p["nc"] + ":" + p["cnonce"] + ":" + p["qop"] + ":" + ha2)
	if p["username"] != s.login || p["uri"] != r.URL.Path || p["response"] != want || p["opaque"] != "op" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.mu.Lock()
	s.bodies = append(s.bodies, m)
	s.algos = append(s.algos, p["algorithm"])
	s.mu.Unlock()
	if s.status != 0 {
		w.WriteHeader(s.status)
	}
}

func TestFlexiAPIPush(t *testing.T) {
	api := &fakeFlexiAPI{t: t, login: "alice", password: `pa"ss\word`}
	srv := httptest.NewServer(api)
	defer srv.Close()
	f := newFlexiAPI(PushConfig{URL: srv.URL + "/api/", Login: "alice", Password: `pa"ss\word`})
	if err := f.push(context.Background(), iphonePush, "call", "mv-0011"); err != nil {
		t.Fatal(err)
	}
	if len(api.bodies) != 1 || api.algos[0] != "SHA-256" {
		t.Fatalf("pushes %v, algorithms %v", api.bodies, api.algos)
	}
	want := map[string]string{"pn_provider": "apns", "pn_param": "ABCD1234.org.linphone.phone.voip",
		"pn_prid": "0a1b2c3d4e5f", "type": "call", "call_id": "mv-0011"}
	for k, v := range want {
		if api.bodies[0][k] != v {
			t.Errorf("%s = %q, want %q", k, api.bodies[0][k], v)
		}
	}

	// The answers FlexiAPI gives on failure become readable errors.
	for _, tc := range []struct {
		name string
		f    *flexiAPI
		set  func()
		want string
	}{
		{"wrong password", newFlexiAPI(PushConfig{URL: srv.URL + "/api", Login: "alice", Password: "wrong"}), nil, "401"},
		{"no such account", newFlexiAPI(PushConfig{URL: srv.URL + "/api", Login: "nobody", Password: "x"}), nil, "404"},
		{"pusher failed", f, func() { api.status = http.StatusServiceUnavailable }, "503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.set != nil {
				tc.set()
			}
			err := tc.f.push(context.Background(), iphonePush, "call", "mv-0012")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %s", err, tc.want)
			}
		})
	}

	// Android: the project and the token go as they are.
	api.status = 0
	android := pushParams{User: "pixel", Instance: "urn:uuid:2", Provider: "fcm", Param: "123456789012", PRID: "dXyZ_1:APA91b-x_y"}
	if err := f.push(context.Background(), android, "call", "mv-0013"); err != nil {
		t.Fatal(err)
	}
	last := api.bodies[len(api.bodies)-1]
	want = map[string]string{"pn_provider": "fcm", "pn_param": "123456789012", "pn_prid": "dXyZ_1:APA91b-x_y", "type": "call", "call_id": "mv-0013"}
	for k, v := range want {
		if last[k] != v {
			t.Errorf("android %s = %q, want %q", k, last[k], v)
		}
	}
	if err := f.push(context.Background(), pushParams{Provider: "apns", Param: "T.org.linphone.phone.remote", PRID: "r:remote"}, "call", "mv-1"); err == nil {
		t.Fatal("a call push went to an iPhone without a VoIP token")
	}
}
