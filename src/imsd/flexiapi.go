package main

// Pushes through Belledonne's FlexiAPI (flexisip-account-manager, the server
// behind subscribe.linphone.org): POST /api/push_notification with type=call
// wakes Linphone on an iPhone through APNs (PushKit), or on Android through
// FCM, and names the Call-ID of the INVITE that follows (FINDINGS §104, §109,
// §114). The request is signed with a
// linphone.org account: HTTP Digest (RFC 7616, MD5 or SHA-256) with a From
// header naming the account. A user API key does not fit: FlexiAPI binds it
// to the IP that made it, and the router's address changes with the mobile
// network. Only the push token and the made-up Call-ID leave the router, not
// the caller's number.

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PushConfig is the linphone.org account that signs the pushes.
type PushConfig struct {
	URL      string `json:"url"`      // FlexiAPI base; empty = https://subscribe.linphone.org/api
	Domain   string `json:"domain"`   // SIP domain of the account; empty = sip.linphone.org
	Login    string `json:"login"`    // empty = no pushes
	Password string `json:"password"` // the account's password
}

const (
	defaultFlexiAPIURL    = "https://subscribe.linphone.org/api"
	defaultFlexiAPIDomain = "sip.linphone.org"
)

// pusher sends a push of a kind ("call") to a device.
type pusher interface {
	push(ctx context.Context, p pushParams, kind, callID string) error
}

type flexiAPI struct {
	base, domain, login, password string
	client                        *http.Client
}

func newFlexiAPI(c PushConfig) *flexiAPI {
	f := &flexiAPI{base: strings.TrimRight(c.URL, "/"), domain: c.Domain, login: c.Login, password: c.Password,
		client: &http.Client{Timeout: 10 * time.Second}}
	if f.base == "" {
		f.base = defaultFlexiAPIURL
	}
	if f.domain == "" {
		f.domain = defaultFlexiAPIDomain
	}
	return f
}

// canPush reports whether the device can be woken for a call: Linphone on an
// iPhone (APNs) with a VoIP token, or on Android (FCM). Linphone on Android
// keeps a service running and normally has a live connection; a push reaches
// it only when the system or a battery saver has stopped it.
func (p pushParams) canPush() bool {
	_, _, ok := p.callPush()
	return ok
}

// callPush returns pn_param and pn_prid of a call push for FlexiAPI.
func (p pushParams) callPush() (param, prid string, ok bool) {
	switch p.Provider {
	case "apns", "apns.dev":
		return p.apnsCall()
	case "fcm":
		return p.fcmCall()
	}
	return "", "", false
}

// unescapePN undoes the URI escaping of a push parameter.
func unescapePN(s string) string {
	if v, err := url.PathUnescape(s); err == nil {
		return v
	}
	return s
}

// fcmCall returns the Firebase project and the registration token of a push
// to Linphone on Android: it sends pn-param <project number> and pn-prid
// <FCM token> (the token itself holds a ':'); FlexiAPI's pusher turns them
// into a high-priority FCM data message.
func (p pushParams) fcmCall() (param, prid string, ok bool) {
	if p.Provider != "fcm" {
		return "", "", false
	}
	param, prid = unescapePN(p.Param), unescapePN(p.PRID)
	return param, prid, param != "" && prid != ""
}

// apnsCall returns the topic and the token of a PushKit (VoIP) push. Linphone
// sends pn-param TEAM.org.linphone.phone.voip&remote and pn-prid
// VOIPTOKEN:voip&REMOTETOKEN:remote; FlexiAPI takes one topic and one token.
// A single token without a service name serves the services of pn-param.
func (p pushParams) apnsCall() (param, prid string, ok bool) {
	if p.Provider != "apns" && p.Provider != "apns.dev" {
		return "", "", false
	}
	unq := unescapePN
	prefix, services, found := cutLast(unq(p.Param), ".")
	if !found || prefix == "" {
		return "", "", false
	}
	voipService := false
	for _, s := range strings.Split(services, "&") {
		voipService = voipService || s == "voip"
	}
	for _, part := range strings.Split(unq(p.PRID), "&") {
		tok, svc, named := strings.Cut(part, ":")
		if tok == "" {
			continue
		}
		if svc == "voip" || (!named && voipService) {
			return prefix + ".voip", tok, true
		}
	}
	return "", "", false
}

func cutLast(s, sep string) (before, after string, found bool) {
	i := strings.LastIndex(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

// newPushCallID makes the Call-ID of a pushed call; FlexiAPI accepts letters,
// digits, '-', '~', '@' and '.'.
func newPushCallID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "mv-" + hex.EncodeToString(b)
}

func (f *flexiAPI) push(ctx context.Context, p pushParams, kind, callID string) error {
	if kind != "call" {
		return fmt.Errorf("push of kind %q is not supported", kind)
	}
	param, prid, ok := p.callPush()
	if !ok {
		return errors.New("the device sent no push token for calls")
	}
	body, err := json.Marshal(map[string]string{"pn_provider": p.Provider, "pn_param": param, "pn_prid": prid,
		"type": kind, "call_id": callID})
	if err != nil {
		return err
	}
	res, err := f.post(ctx, body, "")
	if err != nil {
		return err
	}
	if res.status == http.StatusUnauthorized {
		ch, ok := pickDigest(res.challenges)
		if !ok {
			return errors.New("FlexiAPI: 401 without a usable Digest challenge")
		}
		auth, err := ch.authorization(f.login, f.password, http.MethodPost, f.path(), newCNonce())
		if err != nil {
			return err
		}
		if res, err = f.post(ctx, body, auth); err != nil {
			return err
		}
	}
	switch res.status {
	case http.StatusOK, http.StatusNoContent:
		return nil
	case http.StatusUnauthorized:
		return errors.New("FlexiAPI: 401, wrong linphone.org login or password")
	case http.StatusNotFound:
		return fmt.Errorf("FlexiAPI: 404, no account %s@%s", f.login, f.domain)
	case http.StatusServiceUnavailable:
		return errors.New("FlexiAPI: 503, its pusher failed (the token or the app did not match)")
	default:
		return fmt.Errorf("FlexiAPI: HTTP %d: %s", res.status, res.body)
	}
}

func (f *flexiAPI) path() string {
	u, err := url.Parse(f.base + "/push_notification")
	if err != nil || u.Path == "" {
		return "/api/push_notification"
	}
	return u.Path
}

type apiResponse struct {
	status     int
	body       string // the first 200 bytes, for the log
	challenges []string
}

func (f *flexiAPI) post(ctx context.Context, body []byte, auth string) (apiResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.base+"/push_notification", bytes.NewReader(body))
	if err != nil {
		return apiResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("From", "sip:"+f.login+"@"+f.domain)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	res, err := f.client.Do(req)
	if err != nil {
		return apiResponse{}, fmt.Errorf("FlexiAPI: %w", err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 200))
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	return apiResponse{status: res.StatusCode, body: strings.TrimSpace(string(b)),
		challenges: res.Header.Values("WWW-Authenticate")}, nil
}

// --- HTTP Digest (RFC 7616), the client side ---

type digestChallenge struct {
	realm, nonce, opaque, algorithm, qop string
}

// parseAuthParams reads an auth header value "Scheme k=v, k=\"v\", …"; values
// may be quoted or not (FlexiAPI sends realm=test,qop=auth,algorithm=MD5,
// nonce="…"). Names come back in lower case.
func parseAuthParams(v string) (string, map[string]string) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(v), " ")
	params := map[string]string{}
	for rest = strings.TrimSpace(rest); rest != ""; {
		k, r, ok := strings.Cut(rest, "=")
		if !ok {
			break
		}
		k, r = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(r)
		var val string
		if strings.HasPrefix(r, `"`) {
			var b strings.Builder
			i := 1
			for ; i < len(r) && r[i] != '"'; i++ {
				if r[i] == '\\' && i+1 < len(r) {
					i++
				}
				b.WriteByte(r[i])
			}
			val, r = b.String(), r[min(i+1, len(r)):]
		} else {
			val, r, _ = strings.Cut(r, ",")
			val, r = strings.TrimSpace(val), ","+r
		}
		params[k] = val
		_, rest, _ = strings.Cut(r, ",")
		rest = strings.TrimSpace(rest)
	}
	return scheme, params
}

// parseDigest reads one WWW-Authenticate value.
func parseDigest(v string) (digestChallenge, bool) {
	scheme, p := parseAuthParams(v)
	if !strings.EqualFold(scheme, "Digest") {
		return digestChallenge{}, false
	}
	c := digestChallenge{realm: p["realm"], nonce: p["nonce"], opaque: p["opaque"], algorithm: p["algorithm"], qop: p["qop"]}
	return c, c.nonce != ""
}

// pickDigest chooses SHA-256 over MD5 among the challenges.
func pickDigest(values []string) (digestChallenge, bool) {
	var best digestChallenge
	found := false
	for _, v := range values {
		c, ok := parseDigest(v)
		if !ok || c.hash() == nil {
			continue
		}
		if !found || strings.EqualFold(c.algorithm, "SHA-256") {
			best, found = c, true
		}
	}
	return best, found
}

func (c digestChallenge) hash() func() hash.Hash {
	switch strings.ToUpper(c.algorithm) {
	case "", "MD5":
		return md5.New
	case "SHA-256":
		return sha256.New
	}
	return nil
}

func newCNonce() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// authorization builds the Authorization header for one request (nc 1).
func (c digestChallenge) authorization(user, password, method, uri, cnonce string) (string, error) {
	newHash := c.hash()
	if newHash == nil {
		return "", fmt.Errorf("digest algorithm %q is not supported", c.algorithm)
	}
	h := func(s string) string {
		x := newHash()
		x.Write([]byte(s))
		return hex.EncodeToString(x.Sum(nil))
	}
	ha1 := h(user + ":" + c.realm + ":" + password)
	ha2 := h(method + ":" + uri)
	qop := ""
	for _, q := range strings.Split(c.qop, ",") {
		if strings.TrimSpace(q) == "auth" {
			qop = "auth"
		}
	}
	const nc = "00000001"
	var response string
	if qop != "" {
		response = h(ha1 + ":" + c.nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
	} else {
		response = h(ha1 + ":" + c.nonce + ":" + ha2)
	}
	q := func(s string) string { return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"` }
	parts := []string{"username=" + q(user), "realm=" + q(c.realm), "nonce=" + q(c.nonce), "uri=" + q(uri)}
	if c.algorithm != "" {
		parts = append(parts, "algorithm="+c.algorithm)
	}
	parts = append(parts, "response="+q(response))
	if qop != "" {
		parts = append(parts, "qop="+qop, "nc="+nc, "cnonce="+q(cnonce))
	}
	if c.opaque != "" {
		parts = append(parts, "opaque="+q(c.opaque))
	}
	return "Digest " + strings.Join(parts, ", "), nil
}
