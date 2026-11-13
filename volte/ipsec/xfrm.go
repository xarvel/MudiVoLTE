package ipsec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"github.com/xarvel/MudiVoLTE/volte/auth"
)

// Runner applies the changes to the kernel's SAD and SPD. ExecRunner runs
// iproute2 for each one; Netlink (Linux) talks to the kernel itself, so the
// keys never pass through a command line that the whole system can read
// while it runs. Default returns the one for this system.
type Runner interface {
	// Run executes one `ip` invocation (args exclude the binary name).
	Run(ctx context.Context, args ...string) error
}

// applier is a Runner that takes the operations themselves instead of their
// rendering as ip arguments.
type applier interface {
	apply(ctx context.Context, o op) error
}

// ExecRunner runs iproute2 directly, without a shell.
type ExecRunner struct{ Path string }

func (r ExecRunner) Run(ctx context.Context, args ...string) error {
	_, err := r.output(ctx, args...)
	return err
}

// output runs ip and returns what it printed.
func (r ExecRunner) output(ctx context.Context, args ...string) ([]byte, error) {
	path := r.Path
	if path == "" {
		path = "ip"
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("ip %s: %w: %s", redact(args), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Kernel names of the TS 33.203 algorithms (Linux crypto API).
var (
	kernelAuth = map[string]string{"hmac-md5-96": "hmac(md5)", "hmac-sha-1-96": "hmac(sha1)"}
	kernelEnc  = map[string]string{"": "cipher_null", "null": "cipher_null", "aes-cbc": "cbc(aes)", "des-ede3-cbc": "cbc(des3_ede)"}
)

var protos = []string{"tcp", "udp"}

// replayWindow is the anti-replay window of every SA, in packets.
const replayWindow = 32

// OwnerReqID marks every XFRM state and policy installed by MudiVoLTE. It is
// the ASCII word "MUDI" as a uint32: a stable owner tag lets a new process
// remove entries left by a predecessor that could not run its teardown.
const OwnerReqID uint32 = 0x4d554449

func reqid() string { return strconv.FormatUint(uint64(OwnerReqID), 10) }

func spiArg(spi uint32) string { return fmt.Sprintf("0x%08x", spi) }

func prefix(a netip.Addr) string { return netip.PrefixFrom(a, a.BitLen()).String() }

// opKind is what an op does to the kernel.
type opKind int

const (
	stateAdd opKind = iota
	stateDel
	policyAdd
	policyUpdate
	policyDel
)

// op is one change to the kernel's SAD (a state) or SPD (a policy): what
// `ip xfrm state add`, `ip xfrm policy update` and the like do. Runners
// either render it (args) or apply it themselves.
type op struct {
	kind opKind
	// sa is the state of stateAdd and stateDel.
	sa        SA
	alg, ealg string // kernel names of the algorithms (stateAdd)
	ik, ck    []byte // the keys (stateAdd); ck is nil for the null cipher
	// policy and proto name the selector of the policy ops; the template is
	// policy.SA, or any ESP SA between its addresses with anySA (the inbound
	// selectors two sets share, TS 33.203 §7.4.1a).
	policy Policy
	proto  string
	anySA  bool
}

// args renders the op as the arguments of ip.
func (o op) args() []string {
	switch o.kind {
	case stateAdd:
		return []string{"xfrm", "state", "add",
			"src", o.sa.Src.String(), "dst", o.sa.Dst.String(),
			"proto", "esp", "spi", spiArg(o.sa.SPI), "reqid", reqid(),
			"mode", "transport", "replay-window", strconv.Itoa(replayWindow),
			"auth-trunc", o.alg, hexKey(o.ik), "96",
			"enc", o.ealg, hexKey(o.ck),
		}
	case stateDel:
		return []string{"xfrm", "state", "delete",
			"src", o.sa.Src.String(), "dst", o.sa.Dst.String(), "proto", "esp", "spi", spiArg(o.sa.SPI)}
	case policyDel:
		return append([]string{"xfrm", "policy", "delete"}, o.policy.selector(o.proto)...)
	}
	verb := "add"
	if o.kind == policyUpdate {
		verb = "update"
	}
	args := append([]string{"xfrm", "policy", verb}, o.policy.selector(o.proto)...)
	args = append(args, "tmpl", "src", o.policy.SA.Src.String(), "dst", o.policy.SA.Dst.String(), "proto", "esp")
	if !o.anySA {
		args = append(args, "spi", spiArg(o.policy.SA.SPI))
	}
	args = append(args, "reqid", reqid())
	return append(args, "mode", "transport")
}

func render(ops []op) [][]string {
	out := make([][]string, len(ops))
	for i, o := range ops {
		out[i] = o.args()
	}
	return out
}

// stateOps adds the four SAs.
func (s Set) stateOps() ([]op, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	ik, _ := auth.IntegrityKey(s.Alg, s.IK)
	ck, _ := auth.EncryptionKey(s.Ealg, s.CK)
	a, b, c, d := s.SAs()
	var out []op
	for _, sa := range []SA{a, b, c, d} {
		out = append(out, op{kind: stateAdd, sa: sa, alg: kernelAuth[s.Alg], ealg: kernelEnc[s.Ealg], ik: ik, ck: ck})
	}
	return out, nil
}

// StateArgs renders `ip xfrm state add` for every SA.
func (s Set) StateArgs() ([][]string, error) {
	ops, err := s.stateOps()
	if err != nil {
		return nil, err
	}
	return render(ops), nil
}

func (p Policy) selector(proto string) []string {
	args := []string{"dir", p.Dir, "src", prefix(p.Src), "dst", prefix(p.Dst), "proto", proto}
	if p.SrcPort != 0 {
		args = append(args, "sport", strconv.Itoa(int(p.SrcPort)))
	}
	return append(args, "dport", strconv.Itoa(int(p.DstPort)))
}

// policyOp is an add or update of the policy for one selector and protocol.
// The template names the SA of p; with anySA it takes every ESP transport
// SA between the two addresses.
func policyOp(kind opKind, p Policy, proto string, anySA bool) op {
	return op{kind: kind, policy: p, proto: proto, anySA: anySA}
}

// policyOps adds every selector and protocol, each pinned to its SA.
func (s Set) policyOps() []op {
	var out []op
	for _, p := range s.Policies() {
		for _, proto := range protos {
			out = append(out, policyOp(policyAdd, p, proto, false))
		}
	}
	return out
}

// PolicyArgs renders `ip xfrm policy add` for every selector and protocol.
func (s Set) PolicyArgs() [][]string { return render(s.policyOps()) }

// shared finds the policy of other with the selector of p, if it has one.
// Two sets of one registration share the selectors of the ports that stay:
// the UE server port always, the P-CSCF client port when the P-CSCF keeps it.
func shared(p Policy, other Set) (Policy, bool) {
	for _, o := range other.Policies() {
		if o.Dir == p.Dir && o.Src == p.Src && o.Dst == p.Dst && o.SrcPort == p.SrcPort && o.DstPort == p.DstPort {
			return o, true
		}
	}
	return Policy{}, false
}

// besideOps installs s while old stays in use: the states, a new policy for
// every selector old does not have, and for the inbound selectors both have
// a template that takes either SA. The outbound selectors both have stay
// with old until supersedeOps.
func (s Set) besideOps(old Set) ([]op, error) {
	out, err := s.stateOps()
	if err != nil {
		return nil, err
	}
	for _, p := range s.Policies() {
		_, both := shared(p, old)
		for _, proto := range protos {
			switch {
			case !both:
				out = append(out, policyOp(policyAdd, p, proto, false))
			case p.Dir == "in":
				out = append(out, policyOp(policyUpdate, p, proto, true))
			}
		}
	}
	return out, nil
}

// BesideArgs renders besideOps as ip commands.
func (s Set) BesideArgs(old Set) ([][]string, error) {
	ops, err := s.besideOps(old)
	if err != nil {
		return nil, err
	}
	return render(ops), nil
}

// supersedeOps sends the outbound traffic of the selectors s shares with old
// through the SAs of s.
func (s Set) supersedeOps(old Set) []op {
	var out []op
	for _, p := range s.Policies() {
		if _, both := shared(p, old); !both || p.Dir != "out" {
			continue
		}
		for _, proto := range protos {
			out = append(out, policyOp(policyUpdate, p, proto, false))
		}
	}
	return out
}

// SupersedeArgs renders supersedeOps as ip commands.
func (s Set) SupersedeArgs(old Set) [][]string { return render(s.supersedeOps(old)) }

// removeBesideOps removes s and leaves other whole: the policies both have
// are handed to the SAs of other, the rest of s goes.
func (s Set) removeBesideOps(other Set) []op {
	var out []op
	for _, p := range s.Policies() {
		o, both := shared(p, other)
		for _, proto := range protos {
			if both {
				out = append(out, policyOp(policyUpdate, o, proto, false))
			} else {
				out = append(out, op{kind: policyDel, policy: p, proto: proto})
			}
		}
	}
	return append(out, s.stateDeletes()...)
}

// RemoveBesideArgs renders removeBesideOps as ip commands.
func (s Set) RemoveBesideArgs(other Set) [][]string { return render(s.removeBesideOps(other)) }

// removeOps deletes everything Install creates.
func (s Set) removeOps() []op {
	var out []op
	for _, p := range s.Policies() {
		for _, proto := range protos {
			out = append(out, op{kind: policyDel, policy: p, proto: proto})
		}
	}
	return append(out, s.stateDeletes()...)
}

// RemoveArgs renders removeOps as ip commands.
func (s Set) RemoveArgs() [][]string { return render(s.removeOps()) }

func (s Set) stateDeletes() []op {
	var out []op
	a, b, c, d := s.SAs()
	for _, sa := range []SA{a, b, c, d} {
		out = append(out, op{kind: stateDel, sa: sa})
	}
	return out
}

// run applies one op through r: as it is when r takes ops, else as ip
// arguments.
func run(ctx context.Context, r Runner, o op) error {
	if a, ok := r.(applier); ok {
		return a.apply(ctx, o)
	}
	return r.Run(ctx, o.args()...)
}

// Install adds states, then policies. On failure it removes what it added.
func (s Set) Install(ctx context.Context, r Runner) error {
	ops, err := s.stateOps()
	if err != nil {
		return err
	}
	for _, o := range append(ops, s.policyOps()...) {
		if err := run(ctx, r, o); err != nil {
			return errors.Join(err, s.Remove(context.WithoutCancel(ctx), r))
		}
	}
	return nil
}

// Remove deletes policies and states, best effort; "not found" is ignored
// so it is safe after a partial Install.
func (s Set) Remove(ctx context.Context, r Runner) error {
	return runAll(ctx, r, s.removeOps())
}

// InstallBeside adds s next to old, which keeps carrying the traffic: an
// authentication makes new SAs while the UE still uses the ones it has
// (TS 33.203 §7.4.1a). Until Supersede s serves the connections of its own
// client port and whatever the P-CSCF sends over it. On failure it removes
// what it added.
func (s Set) InstallBeside(ctx context.Context, r Runner, old Set) error {
	ops, err := s.besideOps(old)
	if err != nil {
		return err
	}
	for _, o := range ops {
		if err := run(ctx, r, o); err != nil {
			return errors.Join(err, s.RemoveBeside(context.WithoutCancel(ctx), r, old))
		}
	}
	return nil
}

// Supersede makes s the set for everything the UE sends: old only receives
// from here on, until RemoveBeside takes it away.
func (s Set) Supersede(ctx context.Context, r Runner, old Set) error {
	return runAll(ctx, r, s.supersedeOps(old))
}

// RemoveBeside deletes s and leaves other installed as Install would have
// made it. Best effort like Remove.
func (s Set) RemoveBeside(ctx context.Context, r Runner, other Set) error {
	return runAll(ctx, r, s.removeBesideOps(other))
}

func runAll(ctx context.Context, r Runner, ops []op) error {
	var errs []error
	for _, o := range ops {
		if err := run(ctx, r, o); err != nil && !isNotFound(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// isNotFound recognises a delete of something that is not there: the errno
// from netlink, or what ip prints.
func isNotFound(err error) bool {
	if errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ESRCH) {
		return true
	}
	m := err.Error()
	return strings.Contains(m, "No such process") || strings.Contains(m, "No such file")
}

// redact hides key material in error messages (SPIs are 10 chars, keys longer).
func redact(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		if strings.HasPrefix(a, "0x") && len(a) > 10 {
			out[i] = "0x<key>"
			continue
		}
		out[i] = a
	}
	return strings.Join(out, " ")
}
