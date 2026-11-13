# PROVENANCE: where the code of volte comes from

The library is written from the open specifications of the protocols and from
what the live network does.

## Rules

1. **Behaviour comes from the specifications and our own observations:**
   - 3GPP TS 24.229 (IMS SIP), TS 33.203 (IMS access security), TS 24.341 (SMS
     over IP), TS 26.114 (MTSI media), TS 24.011 / 23.040 (SMS PDUs);
   - IETF RFC 3261, 3262, 3311, 3310, 2617, 3329, 3312, 3680, 4867, 4733, 3550;
   - `FINDINGS.md` (the internal engineering log of the MudiVoLTE project, not
     published), live captures and logs (not published), the modem's AT
     responses.
2. Every package names the specifications it is written from in the header of
   its `doc.go`.

## Third-party dependencies

| Component | License | Purpose |
|---|---|---|
| github.com/emiago/sipgo | BSD-2-Clause | SIP parser, transactions, transport |
| github.com/damonto/wwan-go | MIT | AT/SIM transport (AT+CSIM) |
| github.com/vishvananda/netlink (with github.com/vishvananda/netns) | Apache-2.0 | XFRM states and policies through netlink |
| opencore-amr, vo-amrwbenc | Apache-2.0 | AMR-WB decoder and encoder |

## Log

- 2026-11-03: skeleton created; `auth` (AKA Digest, sec-agree, keys) and
  `ipsec` (4 SAs and policies, rendered as `ip xfrm`) written from RFC
  3310/2617/3329 and TS 33.203 §6.1, §7.1, §7.4.
- 2026-11-03: `sipnet` (TCP framing RFC 3261 §18.3, keep-alive RFC 5626,
  transaction matching §17.1.3, our own ports for sec-agree), `sim` (the AKA
  interface, TS 31.102/33.102), `reg` (TS 24.229 §5.1.1: initial and protected
  REGISTER, AUTS resync, refresh §5.1.1.4.1, de-REGISTER, reg-event RFC 3680).
  Only the `sip` package (parsing) of sipgo is used.
- 2026-11-03: `call` (TS 24.229 §5.1.3–5.1.4, RFC 3261 §12–§17, RFC 3262, 3264,
  3311, RFC 4566/4867 for SDP; GSMA IR.92). The sample offer
  `call/testdata/live_offer.sdp` comes from our own live capture (network
  side), with the addresses replaced by documentation ones (RFC 5737). `tools/pcapsip.py` is our own parser of pcaps with ESP-null.
- 2026-11-03: `media`: RTP per RFC 3550, AMR-WB payload per RFC 4867 (BE and
  OA, storage format §5.3), frame sizes per TS 26.201, G.711 per ITU-T G.711 and
  the G.191 algorithm, DTMF per RFC 4733, WAV. `media/amrwb` is a cgo binding to
  the system libopencore-amrwb and libvo-amrwbenc (Apache-2.0); the E_IF_* and
  D_IF_* prototypes are declared by hand from their public headers. The G.711
  decoding tables in `media/testdata` were generated with ffmpeg.
- 2026-11-03: `sms`: TS 24.341 §5.3 (MESSAGE, the report to the SMSC by
  P-Asserted-Identity with In-Reply-To), TS 24.011 §7.3/§8.2 (RP-DATA, RP-ACK,
  RP-ERROR, causes), TS 23.040 §9.2 (SMS-DELIVER and SMS-SUBMIT, concatenation
  UDH), TS 23.038 §6.2 (GSM 7-bit with the extension table, UCS-2). The
  reference PDUs in the tests are well-known textbook examples.
- 2026-11-04: `media/g722`: G.722 at 64 kbit/s (SB-ADPCM, mode 1) in pure Go
  instead of `gotranspile/g722` (that translated code has no license). Written
  from the text of ITU-T G.722 (11/88) from itu.int: the QMF from §5 (Table 11),
  the ADPCM sub-blocks of §6.2 bit-exact (Tables 13–21). The code of other
  implementations (gotranspile/g722, spandsp, ffmpeg, the ITU reference code)
  was not opened; ffmpeg 7.1 serves only as a black box in the tests, and the
  vectors in `media/g722/testdata` were generated with it. Where ffmpeg differs
  from the text: in the QMF (the arithmetic is up to the implementation, §5.2
  note 1) we follow ffmpeg, 16 bits in and out, XL/XH without the 15-bit
  LOWT/HIGHT limit; in the ADPCM we keep to §6.2, while ffmpeg sums FILTEZ
  without intermediate saturation (visible only on artificial streams, test
  `TestFILTEZOrder`).
- 2026-11-06: the library's license is PolyForm Noncommercial 1.0.0 (the
  author's decision: open, noncommercial). The text in `LICENSE` is verbatim
  from the polyformproject/polyform-licenses repository (tag 1.0.0), the
  `Required Notice` line is in `NOTICE`. The dependencies under BSD-2-Clause,
  MIT and Apache-2.0 are compatible with it: they keep their own licenses, and
  none of their code is in this repository.
- 2026-11-06: `reg` and `ipsec`: re-registration per the text of TS 33.203
  V19.1.0 (§7.1, §7.4.0, §7.4.1a, §7.4.2a) and TS 24.229 V19.7.0
  (§5.1.1.4–§5.1.1.6), archives from 3gpp.org: new SPIs and a new port-c in
  every REGISTER sent over the SAs in use, re-authentication with the new SAs
  beside the old ones (XFRM policies with shared selectors, from the iproute2
  documentation and tests in a network namespace), initial registration on the
  old server port. `tools/secagree.py` is our own, modelled on
  `tools/pcapsip.py`.
- 2026-11-07: `srtp`: SRTP per RFC 3711 (AES-CM §4.1.1, HMAC-SHA1 §4.2, key
  derivation §4.3, the index estimate of Appendix A, the replay window of
  §3.3.2), the AES-256 suites of RFC 6188 and the SDES attribute of RFC 4568.
  The tests use the vectors of RFC 3711 Appendix B.2 and B.3 and the byte
  values of the reference packets in libsrtp's `test/srtp_driver.c`
  (BSD-3-Clause); no libsrtp code. Outside this repository the package was
  cross-checked against pion/srtp (MIT) packet by packet; it is not a
  dependency.
- 2026-11-08: `ipsec` installs the SAs and policies through the XFRM netlink
  socket with `github.com/vishvananda/netlink` (Apache-2.0) instead of
  running `ip xfrm`: the keys no longer pass through a command line. The
  rendering as `ip xfrm` commands stays as the fallback and in the tests; the
  netlink messages are mapped from the same operations.
- 2026-11-13: `reg`: `Run` leaves without a de-REGISTER when its context is
  cancelled with the cause `ErrAccessLost`, per the text of TS 24.229 V19.7.0
  (the same archive): §5.1.1.6.1 (the UE can de-register, over the SAs of the
  contact), annex L.2.2.1B (a new initial registration after the bearer for
  SIP signalling is lost), §5.4.1.2.1, §5.4.1.2.2 and §5.4.2.1.2 (the new
  registration replaces the old one in the S-CSCF).
