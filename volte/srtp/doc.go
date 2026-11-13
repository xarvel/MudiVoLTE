// Package srtp protects RTP packets with SRTP (RFC 3711) and carries the keys
// in SDP with SDES (RFC 4568, the "a=crypto" attribute).
//
// Crypto suites: AES_CM_128_HMAC_SHA1_80 and _32 (RFC 4568 §6.2) and
// AES_256_CM_HMAC_SHA1_80 and _32 (RFC 6188). The key derivation rate is 0,
// there is no MKI, and only RTP is protected: the users of this package send
// no RTCP and drop the RTCP they receive, so SRTCP (RFC 3711 §3.4) is left out.
//
// A Context serves one direction of one media stream: the sender protects with
// its own master key, the receiver unprotects with the key the other side
// announced. The receiver keeps the rollover counter (RFC 3711 §3.3.1,
// Appendix A) and a 64-packet replay window (§3.3.2) per SSRC.
package srtp
