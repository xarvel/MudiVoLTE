package ipsec

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// RemoveOwnedWith is RemoveOwned through the tool r stands for: iproute2
// for an ExecRunner, the kernel's XFRM netlink socket otherwise. ip is the
// fallback for a firmware where netlink misbehaves, so with it the sweep
// does not go through netlink either.
func RemoveOwnedWith(ctx context.Context, r Runner) (states, policies int, err error) {
	switch e := r.(type) {
	case ExecRunner:
		return e.removeOwned(ctx)
	case *ExecRunner:
		return e.removeOwned(ctx)
	}
	return RemoveOwned(ctx)
}

// removeOwned does what RemoveOwned does, with ip: the policies with a
// template that carries OwnerReqID first, each deleted by its selector, then
// the states. Their deleteall takes the protocol, the reqid and the mode as
// a filter and leaves every other state alone; the policies have no such
// filter. A state outlives a policy that could not be deleted, so that no
// policy is left referring to a state that is gone.
func (r ExecRunner) removeOwned(ctx context.Context) (states, policies int, err error) {
	out, err := r.output(ctx, "-o", "xfrm", "policy", "list")
	if err != nil {
		return 0, 0, fmt.Errorf("list XFRM policies: %w", err)
	}
	var errs []error
	for _, line := range strings.Split(string(out), "\n") {
		if !ownedPolicyLine(line) {
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			errs = append(errs, ctxErr)
			break
		}
		args, parseErr := policyDeleteArgs(line)
		if parseErr != nil {
			errs = append(errs, parseErr)
			continue
		}
		if delErr := r.Run(ctx, args...); delErr != nil {
			if !isNotFound(delErr) {
				errs = append(errs, fmt.Errorf("delete XFRM policy: %w", delErr))
			}
			continue
		}
		policies++
	}
	if len(errs) > 0 {
		return 0, policies, errors.Join(errs...)
	}

	filter := []string{"proto", "esp", "reqid", reqid(), "mode", "transport"}
	// Only to count them: the lines hold the keys, so they go nowhere else.
	out, err = r.output(ctx, append([]string{"-o", "xfrm", "state", "list"}, filter...)...)
	if err != nil {
		return 0, policies, fmt.Errorf("list XFRM states: %w", err)
	}
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	if n == 0 {
		return 0, policies, nil
	}
	if err := r.Run(ctx, append([]string{"xfrm", "state", "deleteall"}, filter...)...); err != nil {
		return 0, policies, fmt.Errorf("delete XFRM states: %w", err)
	}
	return n, policies, nil
}

// policyFields splits a line of `ip -o xfrm policy list` into its words; -o
// puts a backslash where the line would break, at times with no space
// before it ("dst 192.0.2.1\").
func policyFields(line string) []string {
	return strings.Fields(strings.ReplaceAll(line, `\`, " "))
}

// ownedPolicyLine tells whether a policy has a template of ours: ESP in
// transport mode with OwnerReqID, as ownedPolicy does for netlink. ip prints
// the reqid in decimal, newer versions with the hex in brackets after it.
func ownedPolicyLine(line string) bool {
	f := policyFields(line)
	for i := 0; i < len(f); i++ {
		if f[i] != "tmpl" {
			continue
		}
		var proto, id, mode string
		for j := i + 1; j < len(f) && f[j] != "tmpl"; j++ {
			if j+1 >= len(f) {
				break
			}
			switch f[j] {
			case "proto":
				proto = f[j+1]
			case "reqid":
				id = f[j+1]
			case "mode":
				mode = f[j+1]
			}
		}
		if proto == "esp" && id == reqid() && mode == "transport" {
			return true
		}
	}
	return false
}

// policyDeleteArgs renders the delete of the policy on line: its direction,
// its type and its selector, which name it as well as its index would.
func policyDeleteArgs(line string) ([]string, error) {
	f := policyFields(line)
	sel := []string{}
	i := 0
	for ; i < len(f) && f[i] != "dir"; i += 2 {
		switch f[i] {
		case "src", "dst", "proto", "sport", "dport", "type", "code", "dev":
		default:
			return nil, fmt.Errorf("delete XFRM policy: %q in its selector is not known here", f[i])
		}
		if i+1 >= len(f) {
			return nil, fmt.Errorf("delete XFRM policy: no value for %q in its selector", f[i])
		}
		sel = append(sel, f[i], f[i+1])
	}
	if i+1 >= len(f) || len(sel) == 0 {
		return nil, errors.New("delete XFRM policy: no direction or selector in the listing")
	}
	args := []string{"xfrm", "policy", "delete", "dir", f[i+1]}
	for j := i + 2; j+1 < len(f) && f[j] != "tmpl"; j++ {
		if f[j] == "ptype" {
			args = append(args, "ptype", f[j+1])
			break
		}
	}
	return append(args, sel...), nil
}
