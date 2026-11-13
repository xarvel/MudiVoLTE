package ipsec

import (
	"bytes"
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
)

func init() { kernelRunners["netlink"] = Netlink{} }

// The netlink messages carry what the ip rendering of the same op says.
func TestNetlinkMapping(t *testing.T) {
	s := liveSet()
	ops, err := s.stateOps()
	if err != nil {
		t.Fatal(err)
	}
	ue, pcscf := net.IP(s.UE.Addr.AsSlice()), net.IP(s.PCSCF.Addr.AsSlice())
	st := xfrmState(ops[0]) // UE client → P-CSCF server, the P-CSCF's spi-s
	if !st.Src.Equal(ue) || !st.Dst.Equal(pcscf) ||
		st.Proto != netlink.XFRM_PROTO_ESP || st.Mode != netlink.XFRM_MODE_TRANSPORT ||
		st.Spi != 0x2001 || st.Reqid != int(OwnerReqID) || st.ReplayWindow != replayWindow {
		t.Fatalf("state: %+v", st)
	}
	if st.Auth == nil || st.Auth.Name != "hmac(md5)" || st.Auth.TruncateLen != 96 || !bytes.Equal(st.Auth.Key, s.IK) {
		t.Fatalf("auth: %+v", st.Auth)
	}
	if st.Crypt == nil || st.Crypt.Name != "cipher_null" || len(st.Crypt.Key) != 0 {
		t.Fatalf("crypt: %+v", st.Crypt)
	}
	del := xfrmState(s.stateDeletes()[0])
	if del.Spi != 0x2001 || del.Auth != nil || del.Crypt != nil {
		t.Fatalf("state delete: %+v", del)
	}

	pols := s.policyOps()
	out := xfrmPolicy(pols[0]) // out, tcp: UE client port → P-CSCF server port
	ones, bits := out.Src.Mask.Size()
	if out.Dir != netlink.XFRM_DIR_OUT || out.Proto != netlink.Proto(syscall.IPPROTO_TCP) ||
		!out.Src.IP.Equal(ue) || ones != 32 || bits != 32 ||
		out.SrcPort != 5100 || out.DstPort != 9900 || len(out.Tmpls) != 1 ||
		out.Tmpls[0].Spi != 0x2001 || out.Tmpls[0].Reqid != int(OwnerReqID) || out.Tmpls[0].Mode != netlink.XFRM_MODE_TRANSPORT ||
		!out.Tmpls[0].Dst.Equal(pcscf) {
		t.Fatalf("outbound policy: %+v", out)
	}
	in := xfrmPolicy(pols[5]) // in, udp, loose source port
	if in.Dir != netlink.XFRM_DIR_IN || in.Proto != netlink.Proto(syscall.IPPROTO_UDP) || in.SrcPort != 0 || in.DstPort != 5101 {
		t.Fatalf("inbound policy: %+v", in)
	}

	beside, err := nextSet().besideOps(s)
	if err != nil {
		t.Fatal(err)
	}
	any := xfrmPolicy(beside[6]) // the shared inbound selector takes either SA
	if any.Tmpls[0].Spi != 0 || any.Tmpls[0].Reqid != int(OwnerReqID) || any.DstPort != 5101 {
		t.Fatalf("policy for either SA: %+v", any)
	}
	gone := xfrmPolicy(s.removeOps()[0])
	if gone.Tmpls != nil || gone.SrcPort != 5100 || gone.DstPort != 9900 {
		t.Fatalf("policy delete: %+v", gone)
	}
}

// RemoveOwned removes every MudiVoLTE entry and leaves a foreign XFRM state
// and policy intact, even when both live in the same network namespace.
func TestKernelRemoveOwned(t *testing.T) {
	kernelTest(t)
	ctx := context.Background()
	foreignState := &netlink.XfrmState{
		Src: net.ParseIP("203.0.113.1").To4(), Dst: net.ParseIP("203.0.113.2").To4(),
		Proto: netlink.XFRM_PROTO_ESP, Mode: netlink.XFRM_MODE_TRANSPORT,
		Spi: 0x7701, Reqid: 77, ReplayWindow: replayWindow,
		Auth:  &netlink.XfrmStateAlgo{Name: "hmac(md5)", Key: bytes.Repeat([]byte{0x77}, 16), TruncateLen: 96},
		Crypt: &netlink.XfrmStateAlgo{Name: "cipher_null"},
	}
	foreignPolicy := &netlink.XfrmPolicy{
		Src: hostNet(liveSet().UE.Addr), Dst: hostNet(liveSet().PCSCF.Addr),
		Proto: netlink.Proto(syscall.IPPROTO_TCP), SrcPort: 5770, DstPort: 5771, Dir: netlink.XFRM_DIR_OUT,
		Tmpls: []netlink.XfrmPolicyTmpl{{
			Src: foreignState.Src, Dst: foreignState.Dst, Proto: netlink.XFRM_PROTO_ESP,
			Mode: netlink.XFRM_MODE_TRANSPORT, Spi: foreignState.Spi, Reqid: foreignState.Reqid,
		}},
	}
	if err := netlink.XfrmStateAdd(foreignState); err != nil {
		t.Fatal(err)
	}
	if err := netlink.XfrmPolicyAdd(foreignPolicy); err != nil {
		_ = netlink.XfrmStateDel(foreignState)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = netlink.XfrmPolicyDel(foreignPolicy)
		_ = netlink.XfrmStateDel(foreignState)
	})

	if err := liveSet().Install(ctx, Netlink{}); err != nil {
		t.Fatal(err)
	}
	states, policies, err := RemoveOwned(ctx)
	if err != nil || states != 4 || policies != 8 {
		t.Fatalf("removed %d states and %d policies: %v", states, policies, err)
	}
	sts, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil || len(sts) != 1 || sts[0].Reqid != foreignState.Reqid {
		t.Fatalf("foreign state was not left alone: %+v, %v", sts, err)
	}
	pols, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil || len(pols) != 1 || len(pols[0].Tmpls) != 1 || pols[0].Tmpls[0].Reqid != foreignState.Reqid {
		t.Fatalf("foreign policy was not left alone: %+v, %v", pols, err)
	}
	if states, policies, err = RemoveOwned(ctx); err != nil || states != 0 || policies != 0 {
		t.Fatalf("second removal: %d states and %d policies: %v", states, policies, err)
	}
}
