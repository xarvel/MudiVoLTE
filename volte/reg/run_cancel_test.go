package reg

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xarvel/MudiVoLTE/volte/sim"
)

// cancellingSIM answers the first AKA; at the second one, the re-registration
// that follows a lost connection, the service stops (ctx ends).
type cancellingSIM struct {
	fakeSIM
	nmu    sync.Mutex
	n      int
	cancel func()
}

func (s *cancellingSIM) Authenticate(ctx context.Context, r, a [16]byte) (sim.AuthResult, error) {
	s.nmu.Lock()
	s.n++
	n := s.n
	s.nmu.Unlock()
	if n == 2 {
		s.cancel()
		<-ctx.Done()
		return sim.AuthResult{}, ctx.Err()
	}
	return s.fakeSIM.Authenticate(ctx, r, a)
}

// Run must leave nothing in the kernel and no sockets when ctx ends, also when
// it ends during the registration that replaces one we hold.
func TestRunCancelledDuringReregistration(t *testing.T) {
	f, r := newFakePCSCF(t), &fakeRunner{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newClient(t, f, &cancellingSIM{cancel: cancel}, r)
	statuses := make(chan Status, 16)
	done := make(chan struct{})
	go func() {
		c.Run(ctx, func(s Status, _ error) { statuses <- s })
		close(done)
	}()
	for s := range statuses {
		if s == StatusRegistered {
			break
		}
	}
	f.mu.Lock()
	conn := f.lastConn
	f.mu.Unlock()
	conn.Close() // the P-CSCF drops the protected connection: Run re-registers

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	t.Logf("SA adds=%d deletes=%d policy adds=%d deletes=%d", r.count("xfrm state add"), r.count("xfrm state delete"),
		r.count("xfrm policy add"), r.count("xfrm policy delete"))
	if adds, dels := r.count("xfrm state add"), r.count("xfrm state delete"); adds != dels {
		t.Errorf("SAs left in the kernel after Run: adds=%d deletes=%d", adds, dels)
	}
	if adds, dels := r.count("xfrm policy add"), r.count("xfrm policy delete"); adds != dels {
		t.Errorf("policies left in the kernel after Run: adds=%d deletes=%d", adds, dels)
	}
	c.mu.Lock()
	ln, s := c.ln, c.s
	c.mu.Unlock()
	if ln != nil {
		t.Errorf("listener on port-s %s still open after Run", ln.Addr())
	}
	if s != nil {
		t.Errorf("session still held after Run (connection err: %v)", s.conn.Err())
	}
}

// With the access network gone a de-REGISTER reaches nobody and no answer to
// it can come. Told so by the cause of the cancellation, Run sends none and
// returns at once instead of waiting 5 s for the answer; the SAs and the
// sockets go as ever. Any other cause still de-registers.
func TestRunAccessLost(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		dereg bool
	}{
		{"access lost", ErrAccessLost, false},
		{"access lost, wrapped", fmt.Errorf("the PDN was dropped: %w", ErrAccessLost), false},
		{"another cause", errors.New("the service stops"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, r := newFakePCSCF(t), &fakeRunner{}
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			c := newClient(t, f, &fakeSIM{}, r)
			statuses := make(chan Status, 16)
			done := make(chan struct{})
			go func() {
				c.Run(ctx, func(s Status, _ error) { statuses <- s })
				close(done)
			}()
			// Registered and subscribed: from here on the client is silent
			// until a refresh is due.
			deadline := time.Now().Add(10 * time.Second)
			for subscribed := false; !subscribed; {
				f.mu.Lock()
				subscribed = len(f.subs) > 0
				f.mu.Unlock()
				if time.Now().After(deadline) {
					t.Fatal("no registration with its subscription in 10 s")
				}
				time.Sleep(5 * time.Millisecond)
			}
			f.set(func() { f.lost = !tc.dereg })

			start := time.Now()
			cancel(tc.cause)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return")
			}
			if took := time.Since(start); took > 2*time.Second {
				t.Errorf("Run took %s to return", took.Round(time.Millisecond))
			}
			f.mu.Lock()
			sent, last := f.afterLoss, f.lastExpires
			f.mu.Unlock()
			if tc.dereg && last != "0" {
				t.Errorf("no de-REGISTER, last Expires=%q", last)
			}
			if !tc.dereg && len(sent) != 0 {
				t.Errorf("sent into the lost access network: %v", sent)
			}
			if adds, dels := r.count("xfrm state add"), r.count("xfrm state delete"); adds != 4 || dels != 4 {
				t.Errorf("SA adds=%d deletes=%d, want 4/4", adds, dels)
			}
			if adds, dels := r.count("xfrm policy add"), r.count("xfrm policy delete"); adds != 8 || dels != 8 {
				t.Errorf("policy adds=%d deletes=%d, want 8/8", adds, dels)
			}
			c.mu.Lock()
			ln, s := c.ln, c.s
			c.mu.Unlock()
			if ln != nil || s != nil {
				t.Errorf("after Run: listener %v, session %v", ln != nil, s != nil)
			}
			closed := false
			for len(statuses) > 0 {
				closed = <-statuses == StatusClosed
			}
			if !closed {
				t.Error("the last status is not closed")
			}
		})
	}
}

// logBuffer keeps what a slog handler writes, for checks after the fact.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// A stop while the first SUBSCRIBE of a registration waits for its answer
// cuts the SUBSCRIBE short, and that is no failure of the subscription: Run
// neither warns that it will try again nor tries. A SUBSCRIBE the network
// refuses still gets the warning.
func TestRunStoppedDuringTheFirstSubscribe(t *testing.T) {
	const warning = `msg="reg-event subscription failed, will try again"`
	for _, tc := range []struct {
		name    string
		cause   error // of the stop
		refused bool  // the network refuses the SUBSCRIBE instead of leaving it unanswered
	}{
		{"access lost", ErrAccessLost, false},
		{"the service stops", errors.New("the service stops"), false},
		{"refused", errors.New("the service stops"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, r := newFakePCSCF(t), &fakeRunner{}
			if tc.refused {
				f.subFail = 1
			} else {
				f.subMute = true
			}
			c := newClient(t, f, &fakeSIM{}, r)
			book := &logBuffer{}
			c.cfg.Log = slog.New(slog.NewTextHandler(book, nil))
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			done := make(chan struct{})
			go func() {
				c.Run(ctx, nil)
				close(done)
			}()
			// The network has the SUBSCRIBE; a refused one has reached Run.
			for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
				f.mu.Lock()
				n := len(f.subs)
				f.mu.Unlock()
				if n > 0 && (!tc.refused || strings.Contains(book.String(), warning)) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("no SUBSCRIBE in 10 s; the log:\n%s", book)
				}
			}

			start := time.Now()
			cancel(tc.cause)
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Run did not return")
			}
			if took := time.Since(start); took > 2*time.Second {
				t.Errorf("Run took %s to return", took.Round(time.Millisecond))
			}
			f.mu.Lock()
			subs := len(f.subs)
			f.mu.Unlock()
			if warned := strings.Contains(book.String(), warning); subs != 1 || warned != tc.refused {
				t.Errorf("%d SUBSCRIBE requests, warned %v; the log:\n%s", subs, warned, book)
			}
		})
	}
}
