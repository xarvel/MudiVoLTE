package main

// Registrar of the LAN phones: who is online now and from where. An INVITE to
// a phone goes to the address the REGISTER came from (source), not to the
// Contact: that way both the phone's TCP connection and the random port of
// its UDP work.
//
// With the persist file, bindings survive a daemon restart: otherwise an
// incoming call has nowhere to go until the phone re-registers (up to an
// hour, §87). A UDP phone listens on the same port, so the old binding is
// enough; TCP bindings are useless without the connection and are not saved.
//
// One device, one binding: a phone that restarted its app comes from a new
// port, and the old binding would hang around for up to an hour, with calls
// going to the dead address as well (a rejection on the live one would wait
// for the timeout of the dead branch). The device is recognised by the
// +sip.instance in the Contact (RFC 5626 §6).

import (
	"encoding/json"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emiago/sipgo/sip"
)

const (
	regDefaultExpires = 3600
	regMinExpires     = 60
	regMaxExpires     = 3600
)

type binding struct {
	user      string
	contact   sip.Uri
	source    string // host:port the REGISTER came from
	transport string // udp | tcp | tls
	instance  string // +sip.instance without quotes and brackets; empty if the phone did not send one
	expires   time.Time
}

type registrar struct {
	mu      sync.Mutex
	byKey   map[string]*binding
	now     func() time.Time
	persist string // bindings file; empty = memory only
}

type savedBinding struct {
	User     string    `json:"user"`
	Contact  string    `json:"contact"`
	Source   string    `json:"source"`
	Instance string    `json:"instance,omitempty"`
	Expires  time.Time `json:"expires"`
}

// load restores the saved UDP bindings (expired ones are dropped).
func (r *registrar) load(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.persist = path
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	var saved []savedBinding
	if json.Unmarshal(raw, &saved) != nil {
		return 0
	}
	now := r.now()
	for _, s := range saved {
		var u sip.Uri
		if !now.Before(s.Expires) || sip.ParseUri(s.Contact, &u) != nil {
			continue
		}
		b := &binding{user: s.User, contact: u, source: s.Source, transport: "udp", instance: s.Instance, expires: s.Expires}
		r.byKey[bindingKey(b.user, b.contact)] = b
	}
	return len(r.byKey)
}

// saveLocked writes the UDP bindings; called with r.mu held.
func (r *registrar) saveLocked() {
	if r.persist == "" {
		return
	}
	saved := []savedBinding{}
	for _, b := range r.byKey {
		if b.transport == "udp" {
			saved = append(saved, savedBinding{User: b.user, Contact: b.contact.String(), Source: b.source, Instance: b.instance, Expires: b.expires})
		}
	}
	sort.Slice(saved, func(i, j int) bool { return saved[i].User+saved[i].Source < saved[j].User+saved[j].Source })
	_ = writeJSONAtomic(r.persist, saved)
}

func newRegistrar() *registrar {
	return &registrar{byKey: map[string]*binding{}, now: time.Now}
}

func bindingKey(user string, contact sip.Uri) string {
	return user + "|" + contact.Host + "|" + strconv.Itoa(contact.Port) + "|" + contact.User
}

// update stores a binding; earlier bindings of the same device (same login
// and +sip.instance, another address) are removed. It returns how many were
// removed.
func (r *registrar) update(b binding) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	nb := b
	key := bindingKey(b.user, b.contact)
	replaced := 0
	if b.instance != "" {
		for k, old := range r.byKey {
			if k != key && old.user == b.user && old.instance == b.instance {
				delete(r.byKey, k)
				replaced++
			}
		}
	}
	r.byKey[key] = &nb
	r.saveLocked()
	return replaced
}

// contactInstance returns the +sip.instance of a Contact: `"<urn:uuid:…>"` → `urn:uuid:…`.
func contactInstance(ch *sip.ContactHeader) string {
	v, ok := ch.Params.Get("+sip.instance")
	if !ok {
		return ""
	}
	return strings.ToLower(strings.Trim(strings.TrimSpace(v), `"<>`))
}

func (r *registrar) remove(user string, contact sip.Uri) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byKey, bindingKey(user, contact))
	r.saveLocked()
}

func (r *registrar) removeAll(user string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, b := range r.byKey {
		if b.user == user {
			delete(r.byKey, k)
		}
	}
	r.saveLocked()
}

// users returns the logins with live bindings, without duplicates.
func (r *registrar) users() []string {
	out := []string{}
	for _, b := range r.active() {
		if len(out) == 0 || out[len(out)-1] != b.user {
			out = append(out, b.user)
		}
	}
	return out
}

// secureUsers returns the logins with live bindings over TLS.
func (r *registrar) secureUsers() []string {
	out := []string{}
	for _, b := range r.active() {
		if b.transport == "tls" && (len(out) == 0 || out[len(out)-1] != b.user) {
			out = append(out, b.user)
		}
	}
	return out
}

// active returns the live bindings (expired ones are purged) in a stable order.
func (r *registrar) active() []binding {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	out := make([]binding, 0, len(r.byKey))
	for k, b := range r.byKey {
		if !now.Before(b.expires) {
			delete(r.byKey, k)
			continue
		}
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].user != out[j].user {
			return out[i].user < out[j].user
		}
		return out[i].source < out[j].source
	})
	return out
}

// forUser returns the live bindings of one login (for the reply to a REGISTER).
func (r *registrar) forUser(user string) []binding {
	var out []binding
	for _, b := range r.active() {
		if b.user == user {
			out = append(out, b)
		}
	}
	return out
}

func clampExpires(e int) int {
	if e <= 0 {
		return 0
	}
	if e < regMinExpires {
		return regMinExpires
	}
	if e > regMaxExpires {
		return regMaxExpires
	}
	return e
}
