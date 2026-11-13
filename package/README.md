# mudi-volte package reference

This directory builds the OpenWrt package `mudi-volte`. Installation and
everyday use are described in the [README](../README.md) in the root of the
repository; this page is the complete reference.

## All commands

```
mudi-volte setup [-y] [--lte-only|--keep-3g] [--phone NAME] [--detach]
mudi-volte status
mudi-volte missed [clear]
mudi-volte sms [--json]
mudi-volte phone add NAME | del NAME | show NAME | list | url NAME | ext NAME NUMBER | screen NAME [SECONDS]
mudi-volte push [login NAME | off]
mudi-volte logs [-f | -a]
mudi-volte start | stop | restart
mudi-volte modem [status | builtin [-y] [--detach]]
mudi-volte uninstall [-y] [--keep-config]
mudi-volte version
```

| Command | What it does |
|---|---|
| `setup` | Checks the router, the modem and the SIM, creates a phone account, switches the modem to External VoLTE mode with voice over IMS only, turns off the router's sleep mode and restarts the router once. When the modem refuses a value, setup sets back what it wrote and fails: no restart, and the service and the sleep settings stay as they were. `-y` answers the question itself |
| `setup --lte-only` | Also keeps the modem on 4G/5G. Rarely needed: it costs the internet where only 3G reaches. `--keep-3g` is the default |
| `status` | Is the SIM registered, which phones are connected, how many calls were missed |
| `missed` | Incoming calls that no phone answered, newest first: time, number, reason |
| `missed clear` | Empty the list of missed calls |
| `sms` | SMS to the SIM, newest first: the ones the modem received (GL's smsd spool, `/etc/spool/sms/incoming`, which the SMS page of the GL admin panel shows) and the ones that came over IMS. `--json` is for the web page |
| `phone add NAME` / `del NAME` | Add or remove a phone account |
| `phone list` | Phone accounts with their short numbers, online or not |
| `phone show NAME` | The phone's QR code and its settings |
| `phone url NAME` | The phone's setup link alone |
| `phone ext NAME NUMBER` | Give a phone another short number (`-` removes it) |
| `phone screen NAME [SECONDS]` | The QR code on the router's display (90 s by default, then it closes by itself) |
| `push` | Pushes to sleeping phones: the linphone.org account and the phones that can be woken |
| `push login NAME` | Set the linphone.org account that signs the pushes; asks its password on the terminal (over SSH: `ssh -t`), stores it through `uci batch` from stdin, restarts the service |
| `push off` | Remove the account: iPhones get calls only while Linphone is open, Android phones while its service runs |
| `logs` / `logs -f` / `logs -a` | Service log: last lines / follow / all |
| `start` / `stop` / `restart` | Control the service |
| `modem status` | Modem settings, including the voice ones that setup changed |
| `modem builtin` | Give VoLTE back to the modem's own client, restore the sleep settings, switch the service off and restart the router; the package stays |
| `uninstall` | What `modem builtin` does, and also remove the package with its settings and phones. `--keep-config` keeps `/etc/config/mudi-volte`. Removing the package with `opkg remove` or in LuCI > System > Software does the same, except the restart |
| `version` | Package version |

## Settings

`/etc/config/mudi-volte` (UCI) explains every option in its comments: who may
call (`incoming`, `allow`), where the phones may call and send SMS (`dial`),
codecs, ring time, the echo test number, SMS on the phones (`sms`), the SIP
port, the QR setup port, encryption (`encryption`, `tls_port`, and `plain`:
whether UDP and TCP stay open next to TLS), the account for
pushes to sleeping phones (`push_login`, `push_password`; `push_url` and `push_domain`
only for another FlexiAPI server than subscribe.linphone.org) and the log level.
The web pages edit the same file. After `uci commit mudi-volte` run
`mudi-volte restart`.

## SMS on the phones

With `option sms '1'` (the default) the service reads GL's smsd spool (the
directories in `/tmp/smstools.cfg`) every 5 seconds and the SMS that came over
IMS, and sends each new SMS to every phone account as a SIP MESSAGE from the
sender's number. `/etc/mudi-volte/sms-phones.json` keeps which phones still
wait for which SMS, so a restart neither loses nor repeats them; a phone that
is away gets them when it registers again, for up to 7 days. On the first start
(no such file) the SMS already on the router are left out. Turning the option
off deletes the file.

A MESSAGE from a phone goes to the echo number (back to the sender), to
another phone (by name or short number), or out as an SMS: the number must pass
`dial`, the text may take up to 10 SMS. The SMS becomes a file in smsd's
`outgoing` directory with the headers GL's `sendsms` writes (`To`, `Alphabet`
UTF-8 or UCS, `Bus`, `Slot`, `To_TOA`); the phone gets `200` once smsd moves
it to `sent`, `500` when it lands in `failed`, and `202` when smsd has not
decided within 20 seconds (a later failure then comes to the phone as a
message). Typing notifications and delivery receipts are accepted and dropped;
files get `415`.

## QR codes and setup links

A phone's QR code links to `http://<router>:8060/p/<token>`, where the router
hands the phone its Linphone configuration. The link works only on the
router's own network, changes when the phone's password changes and stops
working when the phone is removed. The configuration behind it carries a hash
of the phone's password that works like the password itself, so do not share
the link. Ten wrong links from one address block that address for ten minutes.
`option provision_port '0'` turns the links off.

With `option encryption '1'` (the default) the link gives Linphone the account
over TLS on `tls_port` (5061) and sets in Linphone's `[sip]` section:
`media_encryption=srtp`, `media_encryption_mandatory=1`,
`verify_server_certs=0` and `verify_server_cn=0`. These entries apply to all
accounts of that Linphone; liblinphone has no per-account setting for them and
no way to trust one certificate from its configuration. With
`option encryption '0'` the link gives UDP and sets the four entries back to
Linphone's defaults (`none`, `0`, `1`, `1`), so a phone moved off TLS does not
refuse every call.

## Encryption towards the phones

The daemon listens for SIP over TLS (1.2 and 1.3) on `tls_port`, next to UDP
and TCP on `port`. With `option plain '0'` the UDP and TCP ports stay closed
and the phones come over TLS only: nothing a phone signs can then be read off
the Wi-Fi, but every phone must be set up by QR code. The certificate is self-signed, ECDSA P-256, for the LAN
address, valid for ten years: the daemon makes it at start in
`/etc/mudi-volte/tls.crt` and `tls.key` when they are missing, broken, for
another address or within 30 days of their end. The log line
`SIP: TLS for the phones` shows its SHA-256 fingerprint.

SRTP keys travel in the SDP (SDES, RFC 4568), so only inside TLS:

| The phone's offer | Over TLS | Over UDP or TCP |
|---|---|---|
| `RTP/SAVP` with `a=crypto` | SRTP, our own key for the suite and tag of the first line we support | `488` |
| `RTP/AVP` with `a=crypto` | SRTP in `RTP/AVP` | plain RTP |
| `RTP/AVP` | plain RTP | plain RTP |
| DTLS-SRTP (`UDP/TLS/RTP/SAVP`) | `488` | `488` |

Suites: `AES_CM_128_HMAC_SHA1_80`, `AES_CM_128_HMAC_SHA1_32`,
`AES_256_CM_HMAC_SHA1_80`, `AES_256_CM_HMAC_SHA1_32`; no MKI, key derivation
rate 0. Incoming calls offer a phone on TLS `RTP/SAVP` with
`AES_CM_128_HMAC_SHA1_80` and `AES_256_CM_HMAC_SHA1_80`, phones on UDP plain
RTP; a phone on TLS that answers without a key of ours gets a BYE. A re-INVITE
keeps the keys (a new key of the phone replaces its old one); one that drops
them gets `488`. RTCP is neither sent nor read, so SRTCP is not used.
Requests to a phone on TLS or TCP (INVITE, MESSAGE, BYE) go into the
connection it opened; when that connection is gone the phone counts as
offline instead of being dialled. `mudi-volte status` and `phone list` mark
phones on TLS as encrypted; `state.json` lists them in `phones_tls`.

## Pushes to sleeping phones

Linphone on iOS stops in the background and closes its connection; its
registration stays until it expires. Linphone on Android keeps a background
service and its connection (the QR code turns the service on), until the
system or a battery saver stops it. Each REGISTER carries the device's push
parameters in the Contact (RFC 8599: `pn-provider`, `pn-param`, `pn-prid`); the
daemon keeps them per device (`+sip.instance`) in `/etc/mudi-volte/push.json`,
writing the file only when they change, and drops the devices of removed
phones at start.

With `push_login` set, a call (from the network, or from another phone to this
one) goes at once to the devices with a live connection and, for each device
without one, to Belledonne's FlexiAPI: `POST https://subscribe.linphone.org/api/push_notification`
with `type=call`, a Call-ID of the daemon's own (`mv-` and 24 hex digits) and
the push parameters: for an iPhone (`pn-provider=apns`) the VoIP token and the
`.voip` topic (PushKit), for Android (`pn-provider=fcm`) the Firebase project
number and the FCM token as they are (a high-priority FCM message). FlexiAPI answers `401`
with Digest challenges (RFC 7616); the daemon signs the request with the
account (SHA-256, else MD5) and the header `From: sip:<login>@sip.linphone.org`.
The woken Linphone registers again over TLS, and right after the `200 OK` the
daemon sends it the INVITE with that Call-ID. A device that has not come back
after 3 s is pushed once more (iOS may have unloaded Linphone, and the first
push only starts it). A pushed device that comes back after the ringing is
over gets the INVITE and at once a CANCEL, within 25 s, so that Linphone closes
the call as missed. Any phone that registers while a call rings gets that call
too. The log shows `push sent to the phone` with the time FlexiAPI took and
`the phone came back, ringing it`; tokens are never logged.

`phone screen` stops the stock screen app while it draws the code and starts it
again afterwards. A tap closes the code early only if the display was already
awake: the touch panel reports only to the stock app.

## The daemon's own configuration

The init script turns the UCI settings into `/var/run/mudi-volte/imsd.json`
and starts `mudi-imsd -mode service -config` with it (`/etc/init.d/mudi-volte
json` prints the same; it holds the phones' passwords). The daemon reads a
few fields the package never writes. They serve development on a router
without phones, with a config of one's own and `-mode daemon` or `-mode
register-once` (the header of `src/imsd/main.go` lists the modes):

| Field | What it does |
|---|---|
| `record_dir` | A directory: an incoming call that the daemon answers itself, without the SIP bridge, is recorded there as a WAV file (16 kHz, mono). No effect while the `sip` block is present, as in the service the package runs |
| `play_file` | A WAV file (8 or 16 kHz, mono) played into such a call instead of silence; the same limits |
| `max_call_sec` | Hang up every call after this many seconds, bridged ones too; 0 = never |

Nothing in the package records calls: the service bridges the audio between
the network and the phones and keeps none of it.

## Files on the router

| Path | What it is |
|---|---|
| `/usr/sbin/mudi-imsd` | The VoLTE client and the SIP server for the phones, one static binary, run as the procd service `mudi-volte` |
| `/usr/sbin/mudi-volte` | Setup and management |
| `/etc/config/mudi-volte` | Settings and phone accounts |
| `/etc/mudi-volte/sms-inbox.jsonl` | SMS that came over IMS, one JSON object per line (the operator may deliver SMS this way instead of to the modem) |
| `/etc/mudi-volte/missed.jsonl` | Missed calls, one JSON object per line, with full numbers; past 64 KB it is cut to the newest 200 |
| `/etc/mudi-volte/sms-phones.json` | Which phones still wait for which SMS (hashes, times and phone names only) |
| `/etc/mudi-volte/push.json` | Push parameters of the phones (provider, app, token), by device; mode 0600 |
| `/etc/mudi-volte/tls.crt`, `tls.key` | The router's certificate for SIP over TLS |
| `/etc/mudi-volte/modem.orig`, `lpm.orig` | Modem and sleep settings from before setup; uninstall restores them |
| `/var/log/mudi-volte.log` | Service log (about the last day; the system log keeps only minutes) |
| `/www/views/gl-sdk4-ui-mudi-volte.common.js.gz`, `/usr/share/oui/menu.d/mudi-volte.json`, `/usr/lib/oui-httpd/rpc/mudi-volte` | The page in the GL admin panel (Applications > Calls & SMS): a Vue 2 component the panel loads by name, its menu entry and its RPC module (Lua). Only the panel's admin may call it |
| `/www/luci-static/resources/view/mudi-volte/`, `/usr/share/luci/menu.d/`, `/usr/share/rpcd/acl.d/luci-app-mudi-volte.json` | The page in LuCI (Services > Calls & SMS) |
| `/usr/share/nftables.d/chain-pre/input/20-mudi-volte.nft` | Two firewall rules that let the operator's IPsec traffic in on the IMS connection |
| `/usr/share/doc/mudi-volte/` | `LICENSE`, `NOTICE`, `THIRD_PARTY.md` and the third-party license texts |

The times of missed calls and of log lines are the router's clock at that
moment. After a boot the router starts its clock from the newest file under
`/etc`, at least as far behind as the router was off, and sets it right once it
reaches an NTP server; a call missed before that keeps the time the clock
showed. How long the service has been in its state (`status`, the web pages)
and the 7 days an SMS waits for a phone are counted on a clock that this
correction does not move.

## This directory

| Path | What it is |
|---|---|
| `VERSION` | Package version |
| `build.sh` | Builds `dist/`: the `.ipk`, `install.sh` and `SHA256SUMS`, from `build/static/mudi-imsd` (made by `scripts/build-static.sh`). `MUDI_VOLTE_BASE_URL` sets where `install.sh` downloads the package from |
| `install.sh.in` | The installer; `build.sh` fills in the version, the download address and the checksum |
| `control/` | opkg control files: package metadata and maintainer scripts |
| `files/` | Everything installed on the router except the binary and the license files; `build.sh` gzips `www/views/` as the GL admin panel expects |
| `tests/` | `run.sh`: the GL admin panel page with Vue 2 in node, and the LuCI page with LuCI's modules as stubs (needs node and npm) |
| `toolchain/` | musl toolchain and AMR-WB libraries for the static build, and the license collector |
| `THIRD_PARTY.md`, `licenses/` | Third-party components inside `mudi-imsd` and their license texts |
