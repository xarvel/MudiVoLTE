package main

import "syscall"

// bindToDevice ties a socket to one interface (SO_BINDTODEVICE), so that
// packets leave through it whatever the routing table says.
func bindToDevice(fd uintptr, iface string) error {
	return syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
}
