//go:build !linux

package ipsec

import (
	"context"
	"errors"
)

// Default is the Runner for this system. XFRM through netlink exists on
// Linux only; elsewhere (development machines) the commands go to ip, which
// is not there either, but the rendering can be looked at.
func Default() Runner { return ExecRunner{} }

// RemoveOwned is unavailable without the Linux XFRM netlink interface.
func RemoveOwned(context.Context) (states, policies int, err error) {
	return 0, 0, errors.New("ipsec: removing owned XFRM entries requires Linux")
}
