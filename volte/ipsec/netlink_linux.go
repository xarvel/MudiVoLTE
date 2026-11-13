package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/vishvananda/netlink"
)

// Netlink applies the changes through the kernel's XFRM netlink socket
// (github.com/vishvananda/netlink, Apache-2.0): no iproute2 process, and
// the keys of the SAs never pass through a command line that every process
// on the system can read while ip runs. Each op maps to the same message
// iproute2 would send for its rendering in op.args.
type Netlink struct{}

// Default is the Runner for this system: on Linux, netlink.
func Default() Runner { return Netlink{} }

// Run is here for the Runner interface only; the changes come through apply.
func (Netlink) Run(context.Context, ...string) error {
	return errors.New("ipsec: Netlink applies operations, not ip arguments")
}

func (Netlink) apply(_ context.Context, o op) error {
	switch o.kind {
	case stateAdd:
		return netlink.XfrmStateAdd(xfrmState(o))
	case stateDel:
		return netlink.XfrmStateDel(xfrmState(o))
	case policyAdd:
		return netlink.XfrmPolicyAdd(xfrmPolicy(o))
	case policyUpdate:
		return netlink.XfrmPolicyUpdate(xfrmPolicy(o))
	case policyDel:
		return netlink.XfrmPolicyDel(xfrmPolicy(o))
	}
	return errors.New("ipsec: unknown operation")
}

// xfrmState is the SA of a state op: `ip xfrm state add src dst proto esp
// spi reqid mode transport replay-window 32 auth-trunc ALG KEY 96 enc ALG
// KEY`. A delete names the SA by addresses, protocol and SPI; the
// algorithms are not looked at.
func xfrmState(o op) *netlink.XfrmState {
	st := &netlink.XfrmState{
		Src: o.sa.Src.AsSlice(), Dst: o.sa.Dst.AsSlice(),
		Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TRANSPORT,
		Spi: int(o.sa.SPI), Reqid: int(OwnerReqID),
	}
	if o.kind == stateAdd {
		st.ReplayWindow = replayWindow
		st.Auth = &netlink.XfrmStateAlgo{Name: o.alg, Key: o.ik, TruncateLen: 96}
		// The null cipher has a key of zero bits, as ip sends it for `enc cipher_null ""`.
		st.Crypt = &netlink.XfrmStateAlgo{Name: o.ealg, Key: o.ck}
	}
	return st
}

// xfrmPolicy is the selector and the template of a policy op. A delete
// names the policy by its selector and direction alone.
func xfrmPolicy(o op) *netlink.XfrmPolicy {
	p := o.policy
	pol := &netlink.XfrmPolicy{
		Src: hostNet(p.Src), Dst: hostNet(p.Dst), Proto: ipProto(o.proto),
		SrcPort: int(p.SrcPort), DstPort: int(p.DstPort), Dir: netlink.XFRM_DIR_OUT,
	}
	if p.Dir == "in" {
		pol.Dir = netlink.XFRM_DIR_IN
	}
	if o.kind != policyDel {
		t := netlink.XfrmPolicyTmpl{Src: p.SA.Src.AsSlice(), Dst: p.SA.Dst.AsSlice(),
			Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TRANSPORT, Reqid: int(OwnerReqID)}
		if !o.anySA {
			t.Spi = int(p.SA.SPI)
		}
		pol.Tmpls = []netlink.XfrmPolicyTmpl{t}
	}
	return pol
}

// RemoveOwned deletes only the XFRM entries carrying OwnerReqID. Policies go
// first so no selector can refer to a state after that state has gone. The
// operation is idempotent and best effort: every matching entry is attempted.
func RemoveOwned(ctx context.Context) (states, policies int, err error) {
	var errs []error
	pols, listErr := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if listErr != nil {
		return 0, 0, fmt.Errorf("list XFRM policies: %w", listErr)
	}
	policiesClean := true
	for i := range pols {
		if !ownedPolicy(pols[i]) {
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			errs = append(errs, ctxErr)
			policiesClean = false
			break
		}
		if delErr := netlink.XfrmPolicyDel(&pols[i]); delErr != nil {
			if !isNotFound(delErr) {
				errs = append(errs, fmt.Errorf("delete XFRM policy: %w", delErr))
				policiesClean = false
			}
			continue
		}
		policies++
	}
	if !policiesClean {
		// Keep every state while one of its policies may still refer to it.
		return 0, policies, errors.Join(errs...)
	}

	sts, listErr := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if listErr != nil {
		errs = append(errs, fmt.Errorf("list XFRM states: %w", listErr))
	} else {
		for i := range sts {
			if !ownedState(sts[i]) {
				continue
			}
			if ctxErr := ctx.Err(); ctxErr != nil {
				errs = append(errs, ctxErr)
				break
			}
			if delErr := netlink.XfrmStateDel(&sts[i]); delErr != nil {
				if !isNotFound(delErr) {
					errs = append(errs, fmt.Errorf("delete XFRM state: %w", delErr))
				}
				continue
			}
			states++
		}
	}
	return states, policies, errors.Join(errs...)
}

func ownedState(st netlink.XfrmState) bool {
	return st.Reqid == int(OwnerReqID) && st.Proto == netlink.XFRM_PROTO_ESP && st.Mode == netlink.XFRM_MODE_TRANSPORT
}

func ownedPolicy(pol netlink.XfrmPolicy) bool {
	for _, tmpl := range pol.Tmpls {
		if tmpl.Reqid == int(OwnerReqID) && tmpl.Proto == netlink.XFRM_PROTO_ESP && tmpl.Mode == netlink.XFRM_MODE_TRANSPORT {
			return true
		}
	}
	return false
}

// hostNet is the /32 (or /128) of one address, as `src A/32` in a selector.
func hostNet(a netip.Addr) *net.IPNet {
	return &net.IPNet{IP: a.AsSlice(), Mask: net.CIDRMask(a.BitLen(), a.BitLen())}
}

func ipProto(name string) netlink.Proto {
	if name == "udp" {
		return netlink.Proto(syscall.IPPROTO_UDP)
	}
	return netlink.Proto(syscall.IPPROTO_TCP)
}
