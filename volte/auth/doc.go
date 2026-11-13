// Package auth implements the UE side of IMS access authentication:
// HTTP Digest AKA (RFC 3310 over RFC 2617) and the SIP security mechanism
// agreement for ipsec-3gpp (RFC 3329, 3GPP TS 33.203 §7.2, Annex H).
//
// The SIM computes RES/CK/IK; this package only parses challenges,
// builds Authorization headers and derives SA keys from CK/IK.
package auth
