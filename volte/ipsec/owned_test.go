package ipsec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// policyListing is `ip -o xfrm policy list` of iproute2 6.15: a policy of
// someone else (reqid 77), two of ours, one of them printed the way newer
// versions do with -s (the hex after the reqid), and a socket policy.
const policyListing = `src 10.0.0.1/32 dst 10.0.0.2/32 proto tcp sport 5770 dport 5771 \	dir out priority 0 ptype main \	tmpl src 10.0.0.1 dst 10.0.0.2\		proto esp spi 0x00001002 reqid 77 mode transport\
src 10.0.0.2/32 dst 10.0.0.1/32 proto udp dport 5101 \	dir in priority 0 ptype main \	tmpl src 10.0.0.2 dst 10.0.0.1\		proto esp reqid 1297433673 mode transport\
src 10.0.0.1/32 dst 10.0.0.2/32 proto tcp sport 5100 dport 9900 \	dir out priority 0 ptype main \	tmpl src 10.0.0.1 dst 10.0.0.2\		proto esp spi 0x00001001 reqid 1297433673 (0x4d554449) mode transport\
src 0.0.0.0/0 dst 0.0.0.0/0 \	socket in priority 0 ptype main \
`

// fakeIP is an ip that prints listing for the policies and states for the
// states of ours, and logs every call. A policy delete fails with
// failDelete, if it is set.
func fakeIP(t *testing.T, listing, states, failDelete string) (ExecRunner, func() []string) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh to play ip")
	}
	dir := t.TempDir()
	for name, text := range map[string]string{"policies": listing, "states": states} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(dir, "log")
	fail := ""
	if failDelete != "" {
		fail = "echo '" + failDelete + "' >&2; exit 2"
	}
	script := "#!/bin/sh\necho \"$*\" >> '" + log + "'\ncase \"$*\" in\n" +
		"'-o xfrm policy list') cat '" + filepath.Join(dir, "policies") + "' ;;\n" +
		"'-o xfrm state list proto esp reqid 1297433673 mode transport') cat '" + filepath.Join(dir, "states") + "' ;;\n" +
		"'xfrm policy delete '*) " + fail + " ;;\n" +
		"esac\n"
	bin := filepath.Join(dir, "ip")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return ExecRunner{Path: bin}, func() []string {
		raw, _ := os.ReadFile(log)
		return strings.Split(strings.TrimSpace(string(raw)), "\n")
	}
}

// With ipsec_tool "ip" the sweep goes through ip as well: it deletes our
// policies by their selectors, then our states with a filtered deleteall,
// and leaves the rest alone.
func TestRemoveOwnedThroughIP(t *testing.T) {
	states := "src 10.0.0.1 dst 10.0.0.2\\\tproto esp spi 0x00001001 reqid 1297433673 mode transport\\\n" +
		"src 10.0.0.2 dst 10.0.0.1\\\tproto esp spi 0x00001003 reqid 1297433673 mode transport\\\n"
	r, calls := fakeIP(t, policyListing, states, "")
	n, p, err := RemoveOwnedWith(context.Background(), r)
	if err != nil || n != 2 || p != 2 {
		t.Fatalf("removed %d states and %d policies: %v", n, p, err)
	}
	want := []string{
		"-o xfrm policy list",
		"xfrm policy delete dir in ptype main src 10.0.0.2/32 dst 10.0.0.1/32 proto udp dport 5101",
		"xfrm policy delete dir out ptype main src 10.0.0.1/32 dst 10.0.0.2/32 proto tcp sport 5100 dport 9900",
		"-o xfrm state list proto esp reqid 1297433673 mode transport",
		"xfrm state deleteall proto esp reqid 1297433673 mode transport",
	}
	if got := calls(); !slices.Equal(got, want) {
		t.Fatalf("ip calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A policy that cannot be deleted keeps every state: it may refer to one.
// Nothing left of ours is no error and runs no deleteall.
func TestRemoveOwnedThroughIPKeepsStatesOnFailure(t *testing.T) {
	r, calls := fakeIP(t, policyListing, "", "RTNETLINK answers: Operation not permitted")
	if _, p, err := RemoveOwnedWith(context.Background(), r); err == nil || p != 0 {
		t.Fatalf("a failed delete passed: %d policies, %v", p, err)
	}
	for _, c := range calls() {
		if strings.Contains(c, "state") {
			t.Errorf("states touched after a failed policy delete: %s", c)
		}
	}
	r, calls = fakeIP(t, "", "", "")
	if n, p, err := RemoveOwnedWith(context.Background(), r); err != nil || n != 0 || p != 0 {
		t.Fatalf("nothing to remove: %d states, %d policies, %v", n, p, err)
	}
	if got := calls(); slices.ContainsFunc(got, func(c string) bool { return strings.Contains(c, "deleteall") }) {
		t.Errorf("deleteall with nothing of ours: %v", got)
	}
}

// The kernel tests of the sweep: whichever tool sweeps, it removes all of
// ours and nothing else (TestKernelRemoveOwned covers netlink alone with a
// foreign state and policy in place).
func TestKernelRemoveOwnedWith(t *testing.T) {
	kernelTest(t)
	for name, r := range kernelRunners {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			ip := func(args ...string) {
				t.Helper()
				if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
					t.Fatalf("ip %s: %v %s", strings.Join(args, " "), err, out)
				}
			}
			ip("xfrm", "state", "add", "src", "203.0.113.1", "dst", "203.0.113.2", "proto", "esp", "spi", "0x00007701",
				"reqid", "77", "mode", "transport", "auth-trunc", "hmac(md5)", "0x77777777777777777777777777777777", "96",
				"enc", "cipher_null", "")
			ip("xfrm", "policy", "add", "dir", "out", "src", "203.0.113.1/32", "dst", "203.0.113.2/32", "proto", "tcp",
				"sport", "5770", "dport", "5771", "tmpl", "src", "203.0.113.1", "dst", "203.0.113.2", "proto", "esp",
				"spi", "0x00007701", "reqid", "77", "mode", "transport")
			t.Cleanup(func() {
				_ = exec.Command("ip", "xfrm", "policy", "delete", "dir", "out", "src", "203.0.113.1/32", "dst",
					"203.0.113.2/32", "proto", "tcp", "sport", "5770", "dport", "5771").Run()
				_ = exec.Command("ip", "xfrm", "state", "delete", "src", "203.0.113.1", "dst", "203.0.113.2",
					"proto", "esp", "spi", "0x00007701").Run()
			})
			if err := liveSet().Install(ctx, r); err != nil {
				t.Fatal(err)
			}
			states, policies, err := RemoveOwnedWith(ctx, r)
			if err != nil || states != 4 || policies != 8 {
				t.Fatalf("removed %d states and %d policies: %v", states, policies, err)
			}
			if got := kernelPolicies(t); len(got) != 1 || !strings.Contains(got[0], "reqid 77 ") {
				t.Fatalf("policies left: %v", got)
			}
			if got := kernelStates(t); !strings.Contains(got, " 1") {
				t.Fatalf("states left: %s", got)
			}
			if states, policies, err = RemoveOwnedWith(ctx, r); err != nil || states != 0 || policies != 0 {
				t.Fatalf("second removal: %d states and %d policies: %v", states, policies, err)
			}
		})
	}
}

// What a dead predecessor leaves cannot keep a new registration out for
// more than one attempt, even should its selectors come again: the kernel
// refuses the policy (EEXIST), and the rollback of the failed Install
// deletes by selector, the stale policy as well. A new registration takes
// fresh random ports besides, so its selectors rarely meet the old ones.
func TestKernelInstallOverLeftovers(t *testing.T) {
	kernelTest(t)
	for name, r := range kernelRunners {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			dead := liveSet()
			if err := dead.Install(ctx, r); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _, _, _ = RemoveOwnedWith(context.Background(), ExecRunner{}) })
			next := liveSet()
			next.UE.SPIc, next.UE.SPIs, next.PCSCF.SPIc, next.PCSCF.SPIs = 0x3000, 0x3001, 0x4000, 0x4001
			err := next.Install(ctx, r)
			if err == nil {
				t.Fatal("a policy with the selector of a stale one went in")
			}
			if !errors.Is(err, syscall.EEXIST) && !strings.Contains(err.Error(), "File exists") {
				t.Fatalf("not the refusal of a duplicate: %v", err)
			}
			if err := next.Install(ctx, r); err != nil {
				t.Fatalf("the second attempt failed as well: %v", err)
			}
		})
	}
}
