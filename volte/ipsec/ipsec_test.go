package ipsec

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func liveSet() Set {
	return Set{
		UE:    Endpoint{Addr: netip.MustParseAddr("198.51.100.26"), SPIc: 0x1000, SPIs: 0x1001, PortC: 5100, PortS: 5101},
		PCSCF: Endpoint{Addr: netip.MustParseAddr("192.0.2.20"), SPIc: 0x2000, SPIs: 0x2001, PortC: 9950, PortS: 9900},
		Alg:   "hmac-md5-96", Ealg: "null",
		IK: bytes.Repeat([]byte{0x11}, 16), CK: bytes.Repeat([]byte{0x22}, 16),
		LooseInboundSrcPort: true,
	}
}

// Each SA must carry the SPI chosen by its receiver (TS 33.203 §7.1).
func TestSASPIsFollowReceiver(t *testing.T) {
	s := liveSet()
	ucToPs, usToPc, pcToUs, psToUc := s.SAs()
	if ucToPs.SPI != s.PCSCF.SPIs || usToPc.SPI != s.PCSCF.SPIc || pcToUs.SPI != s.UE.SPIs || psToUc.SPI != s.UE.SPIc {
		t.Fatal("wrong SPI mapping")
	}
	if ucToPs.Dst != s.PCSCF.Addr || pcToUs.Dst != s.UE.Addr {
		t.Fatal("wrong direction")
	}
}

func TestPolicyArgs(t *testing.T) {
	s := liveSet()
	got := s.PolicyArgs()
	if len(got) != 8 {
		t.Fatalf("%d policies, want 8", len(got))
	}
	first := strings.Join(got[0], " ")
	want := "xfrm policy add dir out src 198.51.100.26/32 dst 192.0.2.20/32 proto tcp sport 5100 dport 9900 tmpl src 198.51.100.26 dst 192.0.2.20 proto esp spi 0x00002001 reqid " + reqid() + " mode transport"
	if first != want {
		t.Fatalf("\n got %s\nwant %s", first, want)
	}
	in := strings.Join(got[4], " ")
	if strings.Contains(in, " sport ") || !strings.Contains(in, "dir in") || !strings.Contains(in, "dport 5101") {
		t.Fatalf("loose inbound policy: %s", in)
	}
	s.LooseInboundSrcPort = false
	if in := strings.Join(s.PolicyArgs()[4], " "); !strings.Contains(in, " sport 9950 ") {
		t.Fatalf("strict inbound policy: %s", in)
	}
}

func TestStateArgsNullCipher(t *testing.T) {
	st, err := liveSet().StateArgs()
	if err != nil {
		t.Fatal(err)
	}
	a := st[0]
	if a[len(a)-2] != "cipher_null" || a[len(a)-1] != "" {
		t.Fatalf("enc args %q", a[len(a)-3:])
	}
	line := strings.Join(a, " ")
	if !strings.Contains(line, " reqid "+reqid()+" mode transport ") {
		t.Fatalf("owner reqid is missing: %s", line)
	}
	if !strings.Contains(line, "auth-trunc hmac(md5) 0x11111111111111111111111111111111 96") {
		t.Fatal(a)
	}
}

func TestValidate(t *testing.T) {
	s := liveSet()
	s.UE.SPIc = 5
	if s.Validate() == nil {
		t.Error("reserved SPI accepted")
	}
	s = liveSet()
	s.PCSCF.Addr = netip.MustParseAddr("2001:db8::1")
	if s.Validate() == nil {
		t.Error("family mismatch accepted")
	}
}

// nextSet is what an authenticated re-registration adds to liveSet: new
// SPIs on both sides and a new UE client port; the server ports stay, and
// so does the client port of this P-CSCF.
func nextSet() Set {
	s := liveSet()
	s.UE.SPIc, s.UE.SPIs, s.UE.PortC = 0x3000, 0x3001, 5200
	s.PCSCF.SPIc, s.PCSCF.SPIs = 0x4000, 0x4001
	return s
}

func joined(cmds [][]string) []string {
	out := make([]string, len(cmds))
	for i, c := range cmds {
		out[i] = strings.Join(c, " ")
	}
	return out
}

// New SAs go in beside the old ones (TS 33.203 §7.4.1a): the selectors of
// the new client port get policies of their own, the inbound selector of
// the server port takes either SA, and its outbound one stays with the old
// SA until the UE moves over.
func TestBesideArgs(t *testing.T) {
	old, next := liveSet(), nextSet()
	cmds, err := next.BesideArgs(old)
	if err != nil {
		t.Fatal(err)
	}
	got := joined(cmds)
	want := []string{
		"xfrm policy add dir out src 198.51.100.26/32 dst 192.0.2.20/32 proto tcp sport 5200 dport 9900 tmpl src 198.51.100.26 dst 192.0.2.20 proto esp spi 0x00004001 reqid " + reqid() + " mode transport",
		"xfrm policy add dir out src 198.51.100.26/32 dst 192.0.2.20/32 proto udp sport 5200 dport 9900 tmpl src 198.51.100.26 dst 192.0.2.20 proto esp spi 0x00004001 reqid " + reqid() + " mode transport",
		"xfrm policy update dir in src 192.0.2.20/32 dst 198.51.100.26/32 proto tcp dport 5101 tmpl src 192.0.2.20 dst 198.51.100.26 proto esp reqid " + reqid() + " mode transport",
		"xfrm policy update dir in src 192.0.2.20/32 dst 198.51.100.26/32 proto udp dport 5101 tmpl src 192.0.2.20 dst 198.51.100.26 proto esp reqid " + reqid() + " mode transport",
		"xfrm policy add dir in src 192.0.2.20/32 dst 198.51.100.26/32 proto tcp dport 5200 tmpl src 192.0.2.20 dst 198.51.100.26 proto esp spi 0x00003000 reqid " + reqid() + " mode transport",
		"xfrm policy add dir in src 192.0.2.20/32 dst 198.51.100.26/32 proto udp dport 5200 tmpl src 192.0.2.20 dst 198.51.100.26 proto esp spi 0x00003000 reqid " + reqid() + " mode transport",
	}
	if len(got) != 4+len(want) {
		t.Fatalf("%d commands, want %d: %q", len(got), 4+len(want), got)
	}
	for i, w := range want {
		if got[4+i] != w {
			t.Errorf("command %d\n got %s\nwant %s", 4+i, got[4+i], w)
		}
	}
	for _, c := range got[:4] {
		if !strings.HasPrefix(c, "xfrm state add ") {
			t.Errorf("want the states first: %s", c)
		}
	}

	moved := joined(next.SupersedeArgs(old))
	if len(moved) != 2 || moved[0] != "xfrm policy update dir out src 198.51.100.26/32 dst 192.0.2.20/32 proto tcp sport 5101 dport 9950 tmpl src 198.51.100.26 dst 192.0.2.20 proto esp spi 0x00004000 reqid "+reqid()+" mode transport" {
		t.Errorf("moving to the new SAs: %q", moved)
	}
}

// Removing one of two sets leaves the other as Install would have made it:
// the policies both have are pinned to the SAs of the one that stays.
func TestRemoveBesideArgs(t *testing.T) {
	old, next := liveSet(), nextSet()
	for _, tc := range []struct {
		name       string
		gone, stay Set
	}{{"old set", old, next}, {"new set", next, old}} {
		got := joined(tc.gone.RemoveBesideArgs(tc.stay))
		if len(got) != 12 {
			t.Fatalf("%s: %d commands: %q", tc.name, len(got), got)
		}
		installed := map[string]bool{}
		for _, c := range joined(tc.stay.PolicyArgs()) {
			installed[strings.Replace(c, "xfrm policy add", "xfrm policy update", 1)] = true
		}
		updates, deletes := 0, 0
		for _, c := range got[:8] {
			switch {
			case strings.HasPrefix(c, "xfrm policy update "):
				updates++
				if !installed[c] {
					t.Errorf("%s: not a policy of the set that stays: %s", tc.name, c)
				}
			case strings.HasPrefix(c, "xfrm policy delete "):
				deletes++
				if strings.Contains(c, "port 5101") {
					t.Errorf("%s: policy of the server port deleted: %s", tc.name, c)
				}
				if !strings.Contains(c, "port "+strconv.Itoa(int(tc.gone.UE.PortC))) {
					t.Errorf("%s: policy of another client port deleted: %s", tc.name, c)
				}
			}
		}
		if updates != 4 || deletes != 4 {
			t.Errorf("%s: %d updates, %d deletes: %q", tc.name, updates, deletes, got)
		}
		for _, c := range got[8:] {
			if !strings.HasPrefix(c, "xfrm state delete ") || strings.Contains(c, spiArg(tc.stay.UE.SPIc)) ||
				strings.Contains(c, spiArg(tc.stay.UE.SPIs)) || strings.Contains(c, spiArg(tc.stay.PCSCF.SPIc)) || strings.Contains(c, spiArg(tc.stay.PCSCF.SPIs)) {
				t.Errorf("%s: %s", tc.name, c)
			}
		}
	}
}

// Sets that share no selector are independent: a P-CSCF that moves its
// client port and pins it in the inbound policy, or another P-CSCF.
func TestBesideWithoutSharedSelectors(t *testing.T) {
	old, next := liveSet(), nextSet()
	old.LooseInboundSrcPort, next.LooseInboundSrcPort = false, false
	next.PCSCF.PortC = 9951
	cmds, err := next.BesideArgs(old)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range joined(cmds) {
		if want := "xfrm state add "; i >= 4 {
			want = "xfrm policy add "
			if !strings.HasPrefix(c, want) || !strings.Contains(c, " spi ") {
				t.Errorf("command %d: %s", i, c)
			}
		} else if !strings.HasPrefix(c, want) {
			t.Errorf("command %d: %s", i, c)
		}
	}
	if len(cmds) != 12 || len(next.SupersedeArgs(old)) != 0 {
		t.Errorf("%d commands to install, %d to move", len(cmds), len(next.SupersedeArgs(old)))
	}
	if got, want := joined(next.RemoveBesideArgs(old)), joined(next.RemoveArgs()); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("removal differs from Remove:\n%q\n%q", got, want)
	}
}

// A failed InstallBeside takes back what it added and hands the shared
// policies back to the set in use.
func TestInstallBesideRollsBack(t *testing.T) {
	f := &fakeRunner{failAt: 8}
	if err := nextSet().InstallBeside(context.Background(), f, liveSet()); err == nil {
		t.Fatal("expected error")
	}
	if len(f.calls) != 8+12 || f.calls[8] != "xfrm policy delete" || f.calls[10] != "xfrm policy update" || f.calls[len(f.calls)-1] != "xfrm state delete" {
		t.Fatalf("%d calls: %v", len(f.calls), f.calls)
	}
}

type fakeRunner struct {
	calls  []string
	failAt int
}

func (f *fakeRunner) Run(_ context.Context, args ...string) error {
	f.calls = append(f.calls, strings.Join(args[:3], " "))
	if len(f.calls) == f.failAt {
		return errors.New("boom")
	}
	return nil
}

func TestInstallRollsBack(t *testing.T) {
	f := &fakeRunner{failAt: 6}
	if err := liveSet().Install(context.Background(), f); err == nil {
		t.Fatal("expected error")
	}
	// 4 states + 2 policies attempted, then 8 policy + 4 state deletes.
	if len(f.calls) != 6+12 || f.calls[6] != "xfrm policy delete" || f.calls[len(f.calls)-1] != "xfrm state delete" {
		t.Fatalf("%d calls: %v", len(f.calls), f.calls)
	}
}

func TestRedact(t *testing.T) {
	if r := redact([]string{"spi", "0x00002001", "auth-trunc", "hmac(md5)", "0x1111111111111111", "96"}); strings.Contains(r, "1111111111") || !strings.Contains(r, "0x00002001") {
		t.Fatal(r)
	}
}

// kernelRunners are the runners the kernel tests go through: ip everywhere,
// netlink on Linux (netlink_linux_test.go). ip also reads the result back.
var kernelRunners = map[string]Runner{"ip": ExecRunner{}}

// kernelTest skips unless the test runs in a throwaway network namespace:
// VOLTE_XFRM_TEST=1 under `unshare -rn` (or as root in a netns).
func kernelTest(t *testing.T) {
	t.Helper()
	if os.Getenv("VOLTE_XFRM_TEST") != "1" {
		t.Skip("set VOLTE_XFRM_TEST=1 inside an isolated netns")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("no ip binary")
	}
}

// TestKernelInstall installs the set into a throwaway network namespace.
func TestKernelInstall(t *testing.T) {
	kernelTest(t)
	for name, r := range kernelRunners {
		t.Run(name, func(t *testing.T) {
			s, ctx := liveSet(), context.Background()
			if err := s.Install(ctx, r); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("ip", "xfrm", "state", "count").CombinedOutput()
			if err != nil || !strings.Contains(string(out), "4") {
				t.Fatalf("state count: %s %v", out, err)
			}
			if err := s.Remove(ctx, r); err != nil {
				t.Fatal(err)
			}
			out, _ = exec.Command("ip", "xfrm", "policy", "count").CombinedOutput()
			if !strings.Contains(string(out), " 0") {
				t.Fatalf("policies left: %s", out)
			}
			if err := s.Remove(ctx, r); err != nil {
				t.Fatalf("removing what is gone already must pass: %v", err)
			}
		})
	}
}

// kernelPolicies lists the policies in the kernel, one line each, sorted.
func kernelPolicies(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("ip", "-o", "xfrm", "policy", "list").CombinedOutput()
	if err != nil {
		t.Fatalf("ip xfrm policy: %v %s", err, out)
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.Join(strings.Fields(strings.ReplaceAll(l, `\`, " ")), " "); l != "" {
			lines = append(lines, l)
		}
	}
	slices.Sort(lines)
	return lines
}

func kernelStates(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("ip", "xfrm", "state", "count").CombinedOutput()
	if err != nil {
		t.Fatalf("ip xfrm state: %v %s", err, out)
	}
	return strings.TrimSpace(string(out))
}

// serverPortPolicies are the policies of the UE server port 5101.
func serverPortPolicies(lines []string) (in, out []string) {
	for _, l := range lines {
		switch {
		case strings.Contains(l, "dport 5101 ") && strings.Contains(l, "dir in "):
			in = append(in, l)
		case strings.Contains(l, "sport 5101 ") && strings.Contains(l, "dir out "):
			out = append(out, l)
		}
	}
	return in, out
}

// TestKernelBeside walks a re-authentication through the kernel: the new set
// goes in beside the old one and takes over what the UE sends; whichever of
// the two goes, the other is left as Install alone would have made it.
func TestKernelBeside(t *testing.T) {
	kernelTest(t)
	for name, r := range kernelRunners {
		t.Run(name, func(t *testing.T) { kernelBeside(t, r) })
	}
}

func kernelBeside(t *testing.T, r Runner) {
	old, next, ctx := liveSet(), nextSet(), context.Background()
	alone := map[string][]string{}
	for name, s := range map[string]Set{"old": old, "next": next} {
		if err := s.Install(ctx, r); err != nil {
			t.Fatal(err)
		}
		alone[name] = kernelPolicies(t)
		if err := s.Remove(ctx, r); err != nil {
			t.Fatal(err)
		}
	}

	if err := old.Install(ctx, r); err != nil {
		t.Fatal(err)
	}
	beside := func() {
		t.Helper()
		if err := next.InstallBeside(ctx, r, old); err != nil {
			t.Fatal(err)
		}
		got := kernelPolicies(t)
		in, out := serverPortPolicies(got)
		if len(got) != 12 || kernelStates(t) != "SAD count 8" || len(in) != 2 || len(out) != 2 {
			t.Fatalf("two sets: %s\n%s", kernelStates(t), strings.Join(got, "\n"))
		}
		for _, l := range in {
			if strings.Contains(l, " spi ") || !strings.Contains(l, "reqid "+reqid()+" ") {
				t.Errorf("inbound policy of the server port takes one SA only: %s", l)
			}
		}
		for _, l := range out {
			if !strings.Contains(l, "spi 0x00002000 ") {
				t.Errorf("outbound policy of the server port left the old SA early: %s", l)
			}
		}
	}

	// The new set is given up: the old one is as it was.
	beside()
	if err := next.RemoveBeside(ctx, r, old); err != nil {
		t.Fatal(err)
	}
	if got := kernelPolicies(t); !slices.Equal(got, alone["old"]) || kernelStates(t) != "SAD count 4" {
		t.Fatalf("after giving the new set up:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(alone["old"], "\n"))
	}

	// The new set takes over, then the old one goes.
	beside()
	if err := next.Supersede(ctx, r, old); err != nil {
		t.Fatal(err)
	}
	_, out := serverPortPolicies(kernelPolicies(t))
	for _, l := range out {
		if !strings.Contains(l, "spi 0x00004000 ") {
			t.Errorf("outbound policy of the server port not on the new SA: %s", l)
		}
	}
	if err := old.RemoveBeside(ctx, r, next); err != nil {
		t.Fatal(err)
	}
	if got := kernelPolicies(t); !slices.Equal(got, alone["next"]) || kernelStates(t) != "SAD count 4" {
		t.Fatalf("after the old set went:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(alone["next"], "\n"))
	}
	if err := next.Remove(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got := kernelPolicies(t); len(got) != 0 || kernelStates(t) != "SAD count 0" {
		t.Fatalf("left: %s %q", kernelStates(t), got)
	}
}
