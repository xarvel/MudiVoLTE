package reg

import (
	"testing"

	"github.com/emiago/sipgo/sip"

	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// FakeNetwork lends the fake P-CSCF of these tests to the external ones
// (package reg_test), which run calls of package call over a registration;
// package call imports this one, so they cannot live here.
type FakeNetwork struct{ f *fakePCSCF }

func NewFakeNetwork(t *testing.T) *FakeNetwork { return &FakeNetwork{newFakePCSCF(t)} }

// Client registers through n; inbound gets the requests of the network.
func (n *FakeNetwork) Client(t *testing.T, inbound sipnet.Handler) *Client {
	c := newClient(t, n.f, &fakeSIM{}, &fakeRunner{})
	c.inbound = inbound
	t.Cleanup(c.teardown)
	return c
}

// Challenge makes the network answer every REGISTER over SAs with a 401.
func (n *FakeNetwork) Challenge(on bool) { n.f.set(func() { n.f.reauth = on }) }

// Refuse makes the network answer a REGISTER over SAs that answers no
// challenge with status; 0 accepts it.
func (n *FakeNetwork) Refuse(status int) { n.f.set(func() { n.f.refuse = status }) }

// OnRequest gets what the UE sends the network other than REGISTER and
// SUBSCRIBE.
func (n *FakeNetwork) OnRequest(h func(*sipnet.Conn, *sip.Request)) {
	n.f.set(func() { n.f.other = h })
}

// Registers is how many REGISTER requests the network has seen, and how many
// of them it challenged.
func (n *FakeNetwork) Registers() (all, challenged int) {
	for _, r := range n.f.seen() {
		all++
		if r.status == 401 {
			challenged++
		}
	}
	return all, challenged
}
