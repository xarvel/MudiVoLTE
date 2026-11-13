//go:build !linux

package main

import "fmt"

// bindToDevice exists only on Linux (SO_BINDTODEVICE). The daemon runs on the
// router; on other systems only the tests build, and they bind to no device.
func bindToDevice(_ uintptr, iface string) error {
	return fmt.Errorf("binding a socket to %s is supported on linux only", iface)
}
