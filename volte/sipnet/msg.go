package sipnet

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
)

// Request is an outgoing request kept as ordered header lines, so the wire
// text is exactly what we build (IMS networks are picky about header shape).
type Request struct {
	Method  string
	URI     string
	headers [][2]string
	Body    []byte
}

func NewRequest(method, uri string) *Request { return &Request{Method: method, URI: uri} }

// Add appends a header line.
func (r *Request) Add(name, value string) *Request {
	r.headers = append(r.headers, [2]string{name, value})
	return r
}

// Set replaces every header with this name by one line (appended if absent).
func (r *Request) Set(name, value string) *Request {
	out := r.headers[:0]
	done := false
	for _, h := range r.headers {
		if strings.EqualFold(h[0], name) {
			if !done {
				out = append(out, [2]string{name, value})
				done = true
			}
			continue
		}
		out = append(out, h)
	}
	r.headers = out
	if !done {
		r.Add(name, value)
	}
	return r
}

// Get returns the first value of a header.
func (r *Request) Get(name string) string {
	for _, h := range r.headers {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

// Branch returns the branch parameter of the top Via.
func (r *Request) Branch() string {
	for _, p := range strings.Split(r.Get("Via"), ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.EqualFold(k, "branch") {
			return v
		}
	}
	return ""
}

// Bytes renders the request; Content-Length is always added (RFC 3261 §18.3).
func (r *Request) Bytes() []byte {
	var b strings.Builder
	b.WriteString(r.Method + " " + r.URI + " SIP/2.0\r\n")
	for _, h := range r.headers {
		if strings.EqualFold(h[0], "Content-Length") {
			continue
		}
		b.WriteString(h[0] + ": " + h[1] + "\r\n")
	}
	b.WriteString("Content-Length: " + strconv.Itoa(len(r.Body)) + "\r\n\r\n")
	b.Write(r.Body)
	return []byte(b.String())
}

// NewBranch returns an RFC 3261 §8.1.1.7 branch with the magic cookie.
func NewBranch() string { return "z9hG4bK" + Token(10) }

// Token returns n random bytes as lowercase hex (tags, Call-ID, cnonce).
func Token(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
