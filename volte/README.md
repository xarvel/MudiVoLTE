# volte: a host-side VoLTE client (IMS UE) for MudiVoLTE

`volte` is the library under `mudi-imsd`, the daemon of MudiVoLTE. It is written
from the 3GPP and IETF specifications and covers one scenario only: **the SIM is
in a Quectel modem in External VoLTE Stack mode, the host brings up the IMS PDN,
and the whole IMS client runs on Linux (OpenWrt on the GL.iNet Mudi 7)**.

Copyright holder: Arthur Valiullin. License: PolyForm Noncommercial 1.0.0
(`LICENSE`, `NOTICE`): use, change and redistribution are allowed for
noncommercial purposes; commercial use needs a separate license from the
copyright holder.

## What is in and what is not

| In | Out (not part of the current scope) |
|---|---|
| IMS AKA through the SIM (AKAv1-MD5, AUTS) | VoWiFi (ePDG, IKEv2, EAP-AKA) |
| sec-agree and IPsec ESP in transport mode | ESP and TCP/IP in userspace: both are the kernel's |
| REGISTER, re-REGISTER, de-REGISTER, reg-event | Operator entitlement (TS.43) |
| Incoming and outgoing calls, PRACK, UPDATE | QMI/MBIM PDN adapters (the daemon brings the PDN up itself) |
| RTP and AMR-WB (RFC 4867), DTMF | AMR-NB, EVS, USSD |
| SMS over IP (TS 24.341) | Profiles of other operators out of the box |

## Architecture

```
volte/
  auth/    IMS AKA Digest (RFC 3310/2617), sec-agree (RFC 3329), SA keys (TS 33.203 §6.1, §7)
  ipsec/   the set of 4 SAs and policies per TS 33.203 §7.1, installed in the kernel (XFRM)
  reg/     registration: initial -> 401 -> AKA -> SA -> protected REGISTER -> 200, timers, reg-event
  call/    INVITE UAS/UAC, 100rel/PRACK, UPDATE, BYE/CANCEL, SDP offer/answer
  media/   RTP/RTCP, AMR-WB payload RFC 4867 (octet-aligned and bandwidth-efficient), telephone-event
  sms/     MESSAGE application/vnd.3gpp.sms: RP/TP (TS 24.011, 23.040)
  sim/     the SIM interface (AUTHENTICATE); the AT+CSIM implementation lives in imsd
  srtp/    SRTP for the phones' media (RFC 3711, AES-CM + HMAC-SHA1) and SDES keys (RFC 4568)
```

Key decisions:

- **IPsec is left to the kernel.** The Mudi kernel has `CONFIG_XFRM_USER=y` and
  `CONFIG_INET_ESP=y`, and `ip xfrm` works (§62). The SAs and policies go in
  through the XFRM netlink socket (`github.com/vishvananda/netlink`,
  Apache-2.0), so the keys never pass through a command line; the rendering
  as `ip xfrm` commands stays as a fallback and for the tests. Once the SAs
  are installed, SIP runs over ordinary TCP/UDP sockets on the protected
  ports: no ESP or TCP stack of our own.
- **SIP parsing and transactions: `github.com/emiago/sipgo` (BSD-2-Clause).**
  imsd already uses it on the LAN side.
- **SIM: `github.com/damonto/wwan-go` (MIT).**
- **AMR-WB codec:** opencore-amr and vo-amrwbenc (Apache-2.0) through cgo
  (`media/amrwb`, enabled by importing it). Without it, G.711 works in pure Go;
  the tested network offers it too. By default the codec links against the system `.so.0`
  libraries (`link_shared.go`); with the tag `amrwb_static` it links statically
  (`link_static.go`: `-lopencore-amrwb -lvo-amrwbenc -lm`, the directory with
  the `.a` files goes in `CGO_LDFLAGS`). The static musl build for the Mudi is
  `scripts/build-static.sh` of the MudiVoLTE repository.

## Live network behaviour built in from the start

§N cites a section of the project's internal engineering log, which is not
published.

- The P-CSCF addresses come in the PCO after the DNS servers (§75). The first
  one in the list (192.0.2.20) sends from an unpredictable source port, so the
  inbound policies on `port-us` **do not pin the source port** (§81, §82).
- Signalling over TCP; sec-agree: `alg=hmac-md5-96; ealg=null; prot=esp; mod=trans`.
- A re-REGISTER and a de-REGISTER offer new SPIs and a new port-c in
  `Security-Client` (TS 33.203 §7.1, §7.4; TS 24.229 §5.1.1.4.2, §5.1.1.6.2):
  to an offer of the port-c in use the SBC answers
  `500 … "AKA IP+Port conflict"` (§93, §94). After a 401 challenge the new SAs
  are installed beside the old ones; the UE's server port (the Contact of the
  calls) does not change while the registration lasts.
- P-Access-Network-Info is mandatory; it is built from `AT+QENG="servingcell"`.

Where the code comes from: `PROVENANCE.md`.
