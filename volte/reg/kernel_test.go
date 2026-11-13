package reg

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xarvel/MudiVoLTE/volte/ipsec"
	"github.com/xarvel/MudiVoLTE/volte/sipnet"
)

// kernelNetns readies loopback for XFRM. The kernel tests run inside a
// throwaway netns:
//
//	go test -c -o /tmp/reg.test ./reg && VOLTE_XFRM_TEST=1 unshare -rn /tmp/reg.test -test.run Kernel -test.v
func kernelNetns(t *testing.T) {
	t.Helper()
	if os.Getenv("VOLTE_XFRM_TEST") != "1" {
		t.Skip("set VOLTE_XFRM_TEST=1 inside an isolated netns")
	}
	if out, err := exec.Command("ip", "link", "set", "lo", "up").CombinedOutput(); err != nil {
		t.Fatalf("lo up: %v %s", err, out)
	}
	// Loopback bypasses XFRM by default (disable_xfrm/disable_policy = 1).
	for _, k := range []string{"disable_xfrm", "disable_policy"} {
		if err := os.WriteFile("/proc/sys/net/ipv4/conf/lo/"+k, []byte("0"), 0o644); err != nil {
			t.Fatalf("enable xfrm on lo: %v", err)
		}
	}
}

// mirror makes the fake P-CSCF send from its port sport to the UE port dport
// through the SA with spi. It shares the kernel with the UE, so the states of
// the UE serve both ends and only these outbound policies are its own.
func mirror(t *testing.T, sport, dport uint16, spi uint32) {
	for _, proto := range []string{"tcp", "udp"} {
		err := ipsec.ExecRunner{}.Run(context.Background(), "xfrm", "policy", "update", "dir", "out",
			"src", "127.0.0.1/32", "dst", "127.0.0.1/32", "proto", proto,
			"sport", strconv.Itoa(int(sport)), "dport", strconv.Itoa(int(dport)),
			"tmpl", "src", "127.0.0.1", "dst", "127.0.0.1", "proto", "esp", "spi", "0x"+strconv.FormatUint(uint64(spi), 16),
			"reqid", strconv.FormatUint(uint64(ipsec.OwnerReqID), 10), "mode", "transport")
		if err != nil {
			t.Errorf("mirror policy: %v", err)
		}
	}
}

func xfrmDump() string {
	stat, _ := os.ReadFile("/proc/net/xfrm_stat")
	st, _ := exec.Command("ip", "-s", "xfrm", "state").CombinedOutput()
	pol, _ := exec.Command("ip", "-s", "xfrm", "policy").CombinedOutput()
	return string(st) + "\n" + string(pol) + "\n" + string(stat)
}

// TestKernelRegister runs registration with real kernel SAs on loopback.
func TestKernelRegister(t *testing.T) {
	kernelNetns(t)
	f := newFakePCSCF(t)
	f.mirror = func(ue ipsecPorts) {
		mirror(t, f.prt.Addr().Port(), ue.portC, ue.spiC)
		mirror(t, 9950, ue.portS, ue.spiS)
	}
	c := newClient(t, f, &fakeSIM{}, nil)
	c.cfg.IPsec = ipsec.ExecRunner{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := c.Register(ctx); err != nil {
		t.Fatalf("%v\n%s", err, xfrmDump())
	}
	if _, err := c.Subscribe(ctx); err != nil {
		t.Fatal(err)
	}
	if n := espBytes(7002); n == 0 {
		t.Fatalf("no ESP traffic on spi 7002 (UE→P-CSCF):\n%s", xfrmDump())
	}
	if err := c.Deregister(ctx); err != nil {
		t.Fatal(err)
	}
	if out, _ := exec.Command("ip", "xfrm", "state", "count").CombinedOutput(); !strings.Contains(string(out), " 0") {
		t.Errorf("states left: %s", out)
	}
}

// TestKernelReauthentication takes a re-authentication through real ESP:
// what the network has open to the server port keeps working while it
// still sends over the old SAs, after it moves to the new ones and after
// the old ones are gone; the UE sends over the new SAs from the 200 on.
func TestKernelReauthentication(t *testing.T) {
	kernelNetns(t)
	f := newFakePCSCF(t)
	var sets []ipsecPorts // the UE half of every challenge, in order
	f.mirror = func(ue ipsecPorts) {
		// The answer to the challenge comes back to the new client port at once;
		// the server port is left to the test.
		mirror(t, f.prt.Addr().Port(), ue.portC, ue.spiC)
		sets = append(sets, ue)
	}
	set := func(i int) ipsecPorts {
		f.mu.Lock()
		defer f.mu.Unlock()
		if len(sets) <= i {
			t.Fatalf("%d challenges, want %d", len(sets), i+1)
		}
		return sets[i]
	}
	c := newClient(t, f, &fakeSIM{}, nil)
	c.cfg.IPsec = ipsec.ExecRunner{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	defer c.teardown()
	if _, err := c.Register(ctx); err != nil {
		t.Fatalf("%v\n%s", err, xfrmDump())
	}
	first := set(0)
	mirror(t, 9950, first.portS, first.spiS)
	nc, err := sipnet.Dial(ctx, netip.MustParseAddrPort("127.0.0.1:9950"), netip.MustParseAddrPort(serverPort(c)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	reach(t, nc, c)

	old := c.current()
	f.set(func() { f.reauth = true })
	if _, err := c.Refresh(ctx); err != nil {
		t.Fatalf("%v\n%s", err, xfrmDump())
	}
	second := set(1)
	if second.portS != first.portS || second.portC == first.portC {
		t.Fatalf("ports %+v after %+v", second, first)
	}
	// The network still sends over the old SAs; our answer leaves over the new.
	before := espBytes(first.spiS)
	reach(t, nc, c)
	if espBytes(first.spiS) <= before || espBytes(7003) == 0 {
		t.Errorf("server port: %d bytes in over the old SA, %d out over the new:\n%s", espBytes(first.spiS)-before, espBytes(7003), xfrmDump())
	}
	// The network moves to the new SAs.
	mirror(t, 9950, second.portS, second.spiS)
	reach(t, nc, c)
	if espBytes(second.spiS) == 0 || espBytes(7004) == 0 {
		t.Errorf("new SAs unused: server port %d bytes in, client port %d bytes out:\n%s", espBytes(second.spiS), espBytes(7004), xfrmDump())
	}
	// The old SAs come to the end of their lifetime.
	c.expire(old)
	reach(t, nc, c)
	if _, err := c.Subscribe(ctx); err != nil {
		t.Fatalf("SUBSCRIBE over the new SAs: %v\n%s", err, xfrmDump())
	}
	if out, _ := exec.Command("ip", "xfrm", "state", "count").CombinedOutput(); !strings.Contains(string(out), " 4") {
		t.Errorf("states: %s", out)
	}
	if err := c.Deregister(ctx); err != nil {
		t.Fatal(err)
	}
	if out, _ := exec.Command("ip", "xfrm", "state", "count").CombinedOutput(); !strings.Contains(string(out), " 0") {
		t.Errorf("states left: %s", out)
	}
}

// TestKernelRefusedRefresh: after a refused re-REGISTER the registration
// starts unprotected at the same server port. The SAs in use serve until the
// new ones stand, then both ends drop them (TS 33.203 §7.4.2a), and what the
// network has open to the server port goes on over the new SAs.
func TestKernelRefusedRefresh(t *testing.T) {
	kernelNetns(t)
	f := newFakePCSCF(t)
	var sets []ipsecPorts
	f.mirror = func(ue ipsecPorts) {
		mirror(t, f.prt.Addr().Port(), ue.portC, ue.spiC)
		sets = append(sets, ue)
	}
	c := newClient(t, f, &fakeSIM{}, nil)
	c.cfg.IPsec = ipsec.ExecRunner{}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	defer c.teardown()
	if _, err := c.Register(ctx); err != nil {
		t.Fatalf("%v\n%s", err, xfrmDump())
	}
	f.mu.Lock()
	first := sets[0]
	f.mu.Unlock()
	mirror(t, 9950, first.portS, first.spiS)
	nc, err := sipnet.Dial(ctx, netip.MustParseAddrPort("127.0.0.1:9950"), netip.MustParseAddrPort(serverPort(c)), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer nc.Close()
	reach(t, nc, c)

	f.set(func() { f.refuse = 500 })
	if _, err := c.Refresh(ctx); err != nil {
		t.Fatalf("%v\n%s", err, xfrmDump())
	}
	f.mu.Lock()
	second := sets[len(sets)-1]
	f.mu.Unlock()
	if second.portS != first.portS {
		t.Fatalf("server port %d, was %d", second.portS, first.portS)
	}
	mirror(t, 9950, second.portS, second.spiS)
	reach(t, nc, c)
	if espBytes(second.spiS) == 0 || nc.Err() != nil {
		t.Errorf("network connection over the new SAs: %d bytes, %v\n%s", espBytes(second.spiS), nc.Err(), xfrmDump())
	}
	if out, _ := exec.Command("ip", "xfrm", "state", "count").CombinedOutput(); !strings.Contains(string(out), " 4") {
		t.Errorf("states: %s", out)
	}
}

var stateRe = regexp.MustCompile(`(?s)spi (0x[0-9a-f]+).*?lifetime current:\s+(\d+)\(bytes\)`)

// espBytes is how many bytes the SA with spi has carried.
func espBytes(spi uint32) int {
	out, _ := exec.Command("ip", "-s", "xfrm", "state").CombinedOutput()
	for _, m := range stateRe.FindAllStringSubmatch(string(out), -1) {
		if v, _ := strconv.ParseUint(m[1], 0, 32); uint32(v) == spi {
			n, _ := strconv.Atoi(m[2])
			return n
		}
	}
	return 0
}
