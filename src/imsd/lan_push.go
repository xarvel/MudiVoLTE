package main

// Push parameters of the phones (RFC 8599, the way Linphone sends them): the
// Contact of a REGISTER carries pn-provider, pn-param and pn-prid, which name
// the push service, the app and the device. iOS stops Linphone in the
// background, Android may stop it too, and then only a push from the app's
// vendor (Belledonne's Flexisip, then APNs or FCM) wakes it for a call. The
// parameters are kept per device
// (+sip.instance) in a file, so that they outlive the binding and a restart;
// the file is written only when they change (the router's flash).

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

type pushParams struct {
	User     string    `json:"user"`
	Instance string    `json:"instance,omitempty"`
	Provider string    `json:"provider"`
	Param    string    `json:"param,omitempty"`
	PRID     string    `json:"prid"`
	Updated  time.Time `json:"updated"`
}

type pushStore struct {
	mu    sync.Mutex
	path  string // empty = memory only
	byKey map[string]pushParams
}

// newPushStore loads the saved parameters from path (a missing or broken file
// starts empty).
func newPushStore(path string) *pushStore {
	s := &pushStore{path: path, byKey: map[string]pushParams{}}
	if path == "" {
		return s
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return s
	}
	var saved []pushParams
	if json.Unmarshal(raw, &saved) != nil {
		return s
	}
	for _, p := range saved {
		s.byKey[pushKey(p.User, p.Instance, p.PRID)] = p
	}
	return s
}

// pushKey names a device: by its +sip.instance, or by its token when the
// phone sent no instance.
func pushKey(user, instance, prid string) string {
	if instance != "" {
		return user + "|" + instance
	}
	return user + "|prid:" + prid
}

// uriParam is a URI parameter by name, case-insensitively (RFC 3261 §19.1.4).
func uriParam(u sip.Uri, name string) string {
	for _, kv := range u.UriParams {
		if strings.EqualFold(kv.K, name) {
			return kv.V
		}
	}
	return ""
}

// contactPush reads the push parameters of a Contact URI; ok is false when it
// has none.
func contactPush(u sip.Uri) (pushParams, bool) {
	p := pushParams{Provider: uriParam(u, "pn-provider"), Param: uriParam(u, "pn-param"), PRID: uriParam(u, "pn-prid")}
	return p, p.Provider != "" && p.PRID != ""
}

// remember keeps the push parameters of the device's Contact; it reports
// whether they changed (and so were written).
func (s *pushStore) remember(user, instance string, contact sip.Uri, now time.Time) (bool, error) {
	p, ok := contactPush(contact)
	if !ok {
		return false, nil
	}
	key := pushKey(user, instance, p.PRID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.byKey[key]; ok && old.Provider == p.Provider && old.Param == p.Param && old.PRID == p.PRID {
		return false, nil
	}
	p.User, p.Instance, p.Updated = user, instance, now.UTC()
	s.byKey[key] = p
	return true, s.saveLocked()
}

// forUser returns the devices of a login that can be woken by a push.
func (s *pushStore) forUser(user string) []pushParams {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []pushParams
	for _, p := range s.byKey {
		if p.User == user {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Updated.After(out[j].Updated) })
	return out
}

// all returns every saved device.
func (s *pushStore) all() []pushParams {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]pushParams, 0, len(s.byKey))
	for _, p := range s.byKey {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].User+out[i].Instance < out[j].User+out[j].Instance })
	return out
}

// forget honors an explicit sign-out, not ordinary binding expiry (sleep).
// all removes all devices of a login; otherwise only this Contact's device.
func (s *pushStore) forget(user, instance string, contact sip.Uri, all bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := pushKey(user, instance, uriParam(contact, "pn-prid"))
	changed := false
	for k, p := range s.byKey {
		if p.User == user && (all || k == key) {
			delete(s.byKey, k)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.saveLocked()
}

// keepOnly drops the devices of logins that are no longer configured (a
// removed phone restarts the service).
func (s *pushStore) keepOnly(accounts []SIPAccount) error {
	users := map[string]bool{}
	for _, a := range accounts {
		users[a.User] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for k, p := range s.byKey {
		if !users[p.User] {
			delete(s.byKey, k)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.saveLocked()
}

func (s *pushStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	saved := make([]pushParams, 0, len(s.byKey))
	for _, p := range s.byKey {
		saved = append(saved, p)
	}
	sort.Slice(saved, func(i, j int) bool {
		if saved[i].User != saved[j].User {
			return saved[i].User < saved[j].User
		}
		return saved[i].Instance < saved[j].Instance
	})
	return writeJSONAtomic(s.path, saved)
}
