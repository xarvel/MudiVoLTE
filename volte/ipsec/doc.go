// Package ipsec builds and installs the IMS access security associations
// of 3GPP TS 33.203 §7.1: two ESP transport-mode SA pairs between the UE's
// protected client/server ports and the P-CSCF's, keyed from CK/IK (§6.1).
//
// The kernel does ESP (Linux XFRM); after Install the SIP stack uses plain
// sockets bound to the protected ports.
package ipsec
