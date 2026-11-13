package main

// Server-side SIP digest authentication (RFC 2617/3261, MD5, qop=auth) for
// the phones in the LAN. Stateless nonces: the issue time plus an HMAC over it
// and the client IP under a random per-process secret (an intercepted header
// cannot be replayed from another address); a nonce lives nonceTTL. A header
// read off the Wi-Fi (a phone on UDP) cannot be replayed from the phone's own
// address either: the nonce count of each nonce must grow, and the uri of
// the header must name the target of the request. Password guessing is cut
// off per IP, and only a response to a nonce issued to that IP counts as a
// guess: the source of a UDP packet can be forged, and a failure without our
// nonce would let anyone on the Wi-Fi lock a phone out. The failure map is
// cleaned up when it grows (a scan from many addresses does not eat up the
// memory).

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

const (
	nonceTTL       = time.Hour
	authFailLimit  = 10               // this many failures in a row from one IP…
	authFailWindow = 5 * time.Minute  // …within this window
	authBlockFor   = 10 * time.Minute // → blocked for this long
	authFailsMax   = 1000             // more per-IP entries than this: purge the expired ones
	nonceSeenMax   = 4096             // nonces with a count on record; more: purge the expired ones
)

type authFails struct {
	count        int
	first        time.Time
	blockedUntil time.Time
}

// failLimiter counts failures per address: authFailLimit within
// authFailWindow, and the address is blocked for authBlockFor. The zero value
// is ready to use.
type failLimiter struct {
	mu    sync.Mutex
	fails map[string]*authFails
	now   func() time.Time // nil — time.Now
}

func (l *failLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

type digestAuth struct {
	realm  string
	secret []byte
	users  map[string]string

	failLimiter

	// seen is the highest nonce count accepted under each nonce: a request
	// that does not count up is a replay (RFC 2617 §3.2.2).
	seenMu sync.Mutex
	seen   map[string]uint32
}

func newDigestAuth(realm string, accounts []SIPAccount) *digestAuth {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		panic(err)
	}
	users := make(map[string]string, len(accounts))
	for _, a := range accounts {
		users[a.User] = a.Password
	}
	return &digestAuth{realm: realm, secret: secret, users: users, failLimiter: failLimiter{now: time.Now}}
}

func (a *digestAuth) nonceMAC(id, ip string) string {
	m := hmac.New(sha256.New, a.secret)
	m.Write([]byte(id))
	m.Write([]byte{0})
	m.Write([]byte(ip))
	return hex.EncodeToString(m.Sum(nil)[:12])
}

// newNonce makes a nonce for a challenge to ip: the issue time, a random
// part (every challenge gets a nonce of its own, so that two requests under
// one nonce are one client counting up) and the signature over both.
func (a *digestAuth) newNonce(ip string) string {
	var r [4]byte
	if _, err := rand.Read(r[:]); err != nil {
		panic(err)
	}
	id := strconv.FormatInt(a.now().Unix(), 16) + "." + hex.EncodeToString(r[:])
	return id + "." + a.nonceMAC(id, ip)
}

// checkNonce reports valid when the signature is ours and was issued to this
// IP, and stale when the signature is ours but has expired.
func (a *digestAuth) checkNonce(n, ip string) (valid, stale bool) {
	i := strings.LastIndexByte(n, '.')
	if i < 0 {
		return false, false
	}
	id, mac := n[:i], n[i+1:]
	if !hmac.Equal([]byte(mac), []byte(a.nonceMAC(id, ip))) {
		return false, false
	}
	sec, err := nonceTime(id)
	if err != nil {
		return false, false
	}
	if a.now().Sub(time.Unix(sec, 0)) > nonceTTL {
		return true, true
	}
	return true, false
}

// nonceTime returns the issue time (Unix seconds) in a nonce or its id.
func nonceTime(n string) (int64, error) {
	ts, _, _ := strings.Cut(n, ".")
	return strconv.ParseInt(ts, 16, 64)
}

func (a *digestAuth) challenge(stale bool, ip string) string {
	s := fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=MD5, qop="auth"`, a.realm, a.newNonce(ip))
	if stale {
		s += ", stale=true"
	}
	return s
}

// verify checks an Authorization/Proxy-Authorization value for method from a
// client at address ip, sent to requestURI. An unknown login goes through the
// same computation as a known one (with an empty password), so that the list
// of logins cannot be enumerated by response timing. stale asks the client
// for a retry with a fresh nonce: the header has no nonce we issued to ip,
// the nonce has expired, or the request does not count up under it (a
// replay, or a client that started the count over); none of these counts as
// a failure.
func (a *digestAuth) verify(method, header, ip, requestURI string) (user string, ok, stale bool) {
	scheme, rest, _ := strings.Cut(strings.TrimSpace(header), " ")
	if !strings.EqualFold(scheme, "Digest") {
		return "", false, true
	}
	p := parseDigestParams(rest)
	user = p["username"]
	pass, known := a.users[user]
	valid, isStale := a.checkNonce(p["nonce"], ip)
	if !valid {
		// Not our nonce for this address: most often one from a previous daemon
		// process (the phone came back with the old one after a restart). The
		// password cannot be checked here, and so cannot be guessed either: ask
		// for a retry with a fresh nonce (stale) and do not count it as a
		// failure. Before every other check, or a packet with a forged source
		// address and a bad header would count against that address.
		return user, false, true
	}
	if p["realm"] != a.realm || p["uri"] == "" || p["response"] == "" {
		return user, false, false
	}
	// The uri is what the response was computed for: a header taken from a
	// request to one number must not open a request to another.
	if !sameURI(p["uri"], requestURI) {
		return user, false, false
	}
	if alg := p["algorithm"]; alg != "" && !strings.EqualFold(alg, "MD5") {
		return user, false, false
	}
	ha1 := md5hex(user + ":" + a.realm + ":" + pass)
	ha2 := md5hex(method + ":" + p["uri"])
	// Only the qop=auth form the challenge asks for: without qop (RFC 2069)
	// a response has no nonce count, so a copy of it could be sent again for
	// as long as the nonce lives. Every SIP app of the last twenty years
	// answers with qop=auth when it is offered.
	if p["qop"] != "auth" {
		return user, false, false
	}
	want := md5hex(ha1 + ":" + p["nonce"] + ":" + p["nc"] + ":" + p["cnonce"] + ":auth:" + ha2)
	if subtle.ConstantTimeCompare([]byte(want), []byte(strings.ToLower(p["response"]))) != 1 || !known {
		return user, false, false
	}
	if isStale {
		// The password is right but the nonce has expired: ask for a retry with a fresh one.
		return user, false, true
	}
	if !a.countUp(p["nonce"], p["nc"]) {
		// The same header again: a replay of a request read off the Wi-Fi, or a
		// client that counts from one for every request. A fresh nonce settles both.
		return user, false, true
	}
	return user, true, false
}

// countUp records the nonce count of an accepted response and reports
// whether it is higher than every count seen under that nonce.
func (a *digestAuth) countUp(nonce, ncs string) bool {
	nc, err := strconv.ParseUint(ncs, 16, 32)
	if err != nil {
		return false
	}
	a.seenMu.Lock()
	defer a.seenMu.Unlock()
	if last, ok := a.seen[nonce]; ok && uint32(nc) <= last {
		return false
	}
	if a.seen == nil {
		a.seen = map[string]uint32{}
	}
	if len(a.seen) >= nonceSeenMax {
		a.gcSeenLocked()
	}
	a.seen[nonce] = uint32(nc)
	return true
}

// gcSeenLocked forgets the nonces that have expired (their issue time is in
// them); if all are fresh, arbitrary ones down to half the limit.
func (a *digestAuth) gcSeenLocked() {
	now := a.clock()
	for n := range a.seen {
		if sec, err := nonceTime(n); err != nil || now.Sub(time.Unix(sec, 0)) > nonceTTL {
			delete(a.seen, n)
		}
	}
	for n := range a.seen {
		if len(a.seen) <= nonceSeenMax/2 {
			break
		}
		delete(a.seen, n)
	}
}

// sameURI reports whether the uri of a Digest response names the target of
// the request (RFC 3261 §22.4): the user and the host of the Request-URI.
// The port and the parameters may differ in how a phone writes them.
func sameURI(a, b string) bool {
	var ua, ub sip.Uri
	if sip.ParseUri(a, &ua) != nil || sip.ParseUri(b, &ub) != nil {
		return strings.TrimSpace(a) == strings.TrimSpace(b)
	}
	return ua.User == ub.User && strings.EqualFold(ua.Host, ub.Host)
}

func md5hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// parseDigestParams parses comma-separated k=v and k="v"; commas inside
// quotes do not split.
func parseDigestParams(s string) map[string]string {
	out := map[string]string{}
	for len(s) > 0 {
		s = strings.TrimLeft(s, " ,\t")
		eq := strings.IndexByte(s, '=')
		if eq < 0 {
			break
		}
		key := strings.ToLower(strings.TrimSpace(s[:eq]))
		s = strings.TrimLeft(s[eq+1:], " \t")
		var val string
		if strings.HasPrefix(s, `"`) {
			end := 1
			for end < len(s) && s[end] != '"' {
				if s[end] == '\\' {
					end++
				}
				end++
			}
			if end > len(s) {
				end = len(s)
			}
			val = strings.ReplaceAll(s[1:min(end, len(s))], `\"`, `"`)
			if end < len(s) {
				s = s[end+1:]
			} else {
				s = ""
			}
		} else {
			comma := strings.IndexByte(s, ',')
			if comma < 0 {
				val, s = strings.TrimSpace(s), ""
			} else {
				val, s = strings.TrimSpace(s[:comma]), s[comma:]
			}
		}
		out[key] = val
	}
	return out
}

// blocked reports whether ip is blocked for guessing.
func (a *failLimiter) blocked(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.fails[ip]
	return f != nil && a.clock().Before(f.blockedUntil)
}

// fail records a failure; it returns true when the IP has just been blocked.
func (a *failLimiter) fail(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.clock()
	f := a.fails[ip]
	if f == nil || now.Sub(f.first) > authFailWindow {
		if f == nil && len(a.fails) >= authFailsMax {
			a.gcLocked(now)
		}
		if a.fails == nil {
			a.fails = map[string]*authFails{}
		}
		f = &authFails{first: now}
		a.fails[ip] = f
	}
	f.count++
	if f.count >= authFailLimit {
		f.blockedUntil = now.Add(authBlockFor)
		f.count = 0
		f.first = now
		return true
	}
	return false
}

// gcLocked removes the entries whose block and counting window have both
// expired; if all of them are fresh (a real storm from a thousand addresses),
// it sacrifices arbitrary ones down to half the limit.
func (a *failLimiter) gcLocked(now time.Time) {
	for ip, f := range a.fails {
		if now.After(f.blockedUntil) && now.Sub(f.first) > authFailWindow {
			delete(a.fails, ip)
		}
	}
	for ip := range a.fails {
		if len(a.fails) <= authFailsMax/2 {
			break
		}
		delete(a.fails, ip)
	}
}

func (a *failLimiter) success(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.fails, ip)
}
