# MudiVoLTE: calls and SMS on the GL.iNet Mudi 7

The GL.iNet Mudi 7 (GL-E5800) has a 5G modem, the Quectel RG650V, that officially
does data only: calls to its SIM go nowhere. MudiVoLTE turns the router into a
phone line for that SIM. Phones on the router's Wi-Fi run a free SIP app
(Linphone): they ring on incoming calls and place outgoing calls through the SIM,
with sound both ways, and get the SIM's SMS as chat messages, which they can
answer.

Everything runs on the router itself. It is one OpenWrt package, `mudi-volte`,
installed with one command.

**Tested:** Mudi 7 with GL firmware 4.10.0 and a European operator's SIM,
Linphone on Android and iPhone. Incoming and outgoing calls in wideband (AMR-WB
to the network, G.722 to the phone), calls between the phones, SMS both ways
between the network and a SIP phone, phone setup by QR code, encrypted calls
(SIP over TLS, SRTP), incoming calls on an iPhone with Linphone in the
background (push), a phone away from home over Tailscale (sign-in and the echo
test), web pages in the GL admin panel and LuCI, incoming calls with a second
SIM or the built-in eSIM active next to the SIM of the line.

> **Before you start.** Emergency numbers (112, 911, 999 and the like) are
> not guaranteed to work through MudiVoLTE: keep a phone with its own SIM for
> them. Running the operator's IMS client on a router may be against the
> terms of your mobile contract; check them. MudiVoLTE is a personal project,
> tested with one operator, and comes without any warranty (see
> [LICENSE](LICENSE)).

## What you need

- A GL.iNet Mudi 7 (GL-E5800) with GL firmware 4.x.
- A SIM in slot 1 from an operator that offers VoLTE on it. Tested with one
  European operator. Others should work if they allow VoLTE for the SIM; please
  open an issue and tell how it went. A second SIM or the built-in eSIM can stay
  in the router, but the phone line is always the SIM in slot 1 (see
  [Known limitations](#known-limitations)).
- A phone, tablet or computer with Linphone (free: Android, iPhone, macOS,
  Windows, Linux).
- Optionally: a free account at
  [subscribe.linphone.org](https://subscribe.linphone.org), so that calls ring
  on an iPhone while Linphone is in the background (see
  [Phones in the background](#phones-in-the-background)).
- A computer with SSH for the installation. SSH is built into macOS, Linux and
  Windows 10/11.

## Install

**1. Log in to the router.** Connect your computer to the router's Wi-Fi or LAN
port. Open a terminal (Terminal on macOS and Linux, PowerShell on Windows) and
run:

```sh
ssh root@192.168.8.1
```

The password is the router's admin password, the one you use for its web panel.

**2. Run the installer.**

```sh
wget -qO- https://github.com/xarvel/MudiVoLTE/releases/latest/download/install.sh | sh
```

The installer checks that the router is a Mudi 7, downloads the package, checks
its checksum, installs it and starts the setup. The setup checks the modem and
the SIM, creates a phone account named `phone` and asks:

```
Switch the modem and restart the router now? [Y/n]
```

Press Enter. The router restarts once: Wi-Fi and the internet are down for 2-3
minutes.

**3. Connect your phone.**

1. Connect the phone to the router's Wi-Fi (not to the guest network).
2. Install Linphone from Google Play or the App Store.
3. Log in to the router again (`ssh root@192.168.8.1`) and run
   `mudi-volte phone show phone`. A QR code appears right in the terminal.
4. In Linphone choose "Scan QR code" (in the assistant on the first start, or
   under "Fetch remote configuration") and scan the code. Linphone sets up the
   account by itself.

**4. Check that it works.** Call `600` from Linphone: you hear yourself. This
echo test does not use the mobile network. Then call the SIM's number from
another phone: Linphone rings. On the router, `mudi-volte status` shows the
state of the line:

```
# mudi-volte status
Service: online, registered for 2m0s
Number:  +447700900000
Network: LTE, IMS on rmnet_data1 (198.51.100.207), P-CSCF 192.0.2.28, 192.0.2.20
Phones:  phone
Modem:   External VoLTE mode
```

That's all. The service starts by itself whenever the router starts.

### Other ways to install

**No internet on the router.** On a computer, download `install.sh` and
`mudi-volte_<version>_aarch64_cortex-a53.ipk` from the
[releases page](https://github.com/xarvel/MudiVoLTE/releases). Copy both to
the router, log in and run the installer with the package file:

```sh
scp -O install.sh mudi-volte_*_aarch64_cortex-a53.ipk root@192.168.8.1:/tmp/
ssh root@192.168.8.1
sh /tmp/install.sh /tmp/mudi-volte_*_aarch64_cortex-a53.ipk
```

**Without SSH.** The `.ipk` also installs from the router's web interface: GL
admin panel > System > Advanced Settings (LuCI) > System > Software > Upload
Package. Then open Applications > Calls & SMS in the GL admin panel (or LuCI >
Services > Calls & SMS) and press "Set up and restart the router". Reload the
admin panel first if the new menu entry does not show. LuCI is not part of the
stock firmware; the Advanced Settings page of the GL admin panel offers to
install it. The same Software page removes the package again (see
[Uninstall](#uninstall)); restart the router afterwards.

## Phones

The QR code of a phone is on the web page (Applications > Calls & SMS in the GL
admin panel, or LuCI > Services > Calls & SMS; Phones > "Connect / QR code") and
in the terminal: `mudi-volte phone show NAME`.
`mudi-volte phone screen NAME` shows it on the router's own display for 90
seconds.

The code links to `http://192.168.8.1:8060/p/<token>`, where the router hands the
phone its account. Besides the account, the code switches on G.722 in Linphone
(Linphone ships with it off, so calls would be narrowband) and, on Android, the
keep-alive service, so that calls ring at once. The link works only on the
router's own network, changes when the phone's password changes and stops
working when the phone is removed. Do not share it: it signs a phone in.

The code also sets up encrypted calls: SIP over TLS (port 5061) and SRTP for
the sound (see [Encryption](#encryption)). A phone set up with an earlier
version calls without encryption until you scan its code again.

Other SIP apps, or Linphone set up by hand: add a SIP account with the settings
that `mudi-volte phone show NAME` prints, and enable the G.722 codec for wideband
sound. The app must sign in with Digest authentication in its `qop=auth` form,
as every current one does; the old form without `qop` is refused, because a
copy of such a sign-in could be sent again.

| Field | Value |
|---|---|
| Username | the phone's name, e.g. `phone` |
| Password | from `mudi-volte phone show NAME` |
| Domain | the router's address, `192.168.8.1` by default |
| Transport | UDP, or TLS on port 5061 with SRTP media encryption |

- **Android:** allow Linphone to run without battery restrictions, or incoming
  calls ring several seconds late or not at all. With a linphone.org account set
  on the router, a push wakes Linphone if the system stops it anyway.
- **iPhone:** iOS stops SIP apps in the background. With a linphone.org account
  set on the router, a push wakes Linphone for every call (see
  [Phones in the background](#phones-in-the-background)); without one, incoming
  calls ring only while Linphone is open. Outgoing calls work as usual.

More phones: `mudi-volte phone add NAME`. An incoming call rings all of them,
and the first to answer gets it. Phones call and message each other by name or
by short number (201, 202, ...; `mudi-volte phone list` shows them). Such calls
and messages stay on the router's Wi-Fi and cost nothing.

## Messages (SMS)

A new SMS to the SIM goes to every phone as a message: Linphone shows a
conversation with the sender's number. A reply in that conversation, or a new
message to any number, goes out as an SMS through the modem, to the numbers
that outgoing calls may reach (`dial`). A message to `600` comes straight back:
that checks the chat without the mobile network.

- A phone that is not connected gets the SMS when it connects again (within 7
  days). The SMS that were on the router before MudiVoLTE stay there.
- Only SMS to the SIM in slot 1 go to the phones. What a second SIM receives
  stays on the SMS page of the GL admin panel.
- Linphone marks a message as sent when the modem has sent the SMS, and as
  failed when it could not. If sending takes longer than 20 seconds, the
  message shows as sent, and a failure later arrives as a message in the same
  conversation.
- The SMS stay on the router as before: on the SMS page of the GL admin panel,
  on the MudiVoLTE web page and with `mudi-volte sms`.
- To keep SMS off the phones, turn off "SMS on the phones" on the web page, or
  `uci set mudi-volte.main.sms=0 && uci commit mudi-volte && mudi-volte restart`.

## Everyday commands

| Command | What it does |
|---|---|
| `mudi-volte status` | Is the SIM registered, which phones are connected |
| `mudi-volte missed` | Calls that no phone answered: time, number, reason |
| `mudi-volte sms` | SMS to the SIM, newest first |
| `mudi-volte phone list` | Phone accounts, online or not |
| `mudi-volte phone show NAME` | QR code and settings of a phone |
| `mudi-volte phone add NAME` / `del NAME` | Add or remove a phone |
| `mudi-volte phone ext NAME NUMBER` | Give a phone another short number (`-` removes it) |
| `mudi-volte push` / `push login NAME` / `push off` | Pushes to sleeping phones: state, set the linphone.org account (asks the password), turn off |
| `mudi-volte logs` / `logs -f` | Service log: last lines / follow |
| `mudi-volte restart` | Restart the service |
| `mudi-volte uninstall` | Remove everything and give VoLTE back to the modem |

The web page (Applications > Calls & SMS in the GL admin panel, the same in
LuCI > Services > Calls & SMS) shows the same: status, missed calls, SMS, phones
with their QR codes, settings and the log. A call that reached the router but that no phone answered
(none was connected, nobody picked up, the caller hung up first, the line was
busy) goes to the list of missed calls with the full number, so that you can
call back; `mudi-volte missed clear` or the button on the web page empties
it. Settings live in `/etc/config/mudi-volte`. Change them on the web page,
or with `uci` followed by `mudi-volte restart`:

```sh
# Ring the phones only for these callers, decline everyone else:
uci set mudi-volte.main.incoming=allow
uci add_list mudi-volte.main.allow='+447700900123'
# Outgoing calls only to the UK and France (the default '*' allows any number):
uci set mudi-volte.main.dial='+44 +33'
uci commit mudi-volte && mudi-volte restart
```

## When something does not work

- **`mudi-volte status` says "connecting" for more than 5 minutes.** Look at
  `mudi-volte logs`. `403` or `401` again and again means that the operator does
  not allow VoLTE for this SIM or this device.
- **Callers hear voicemail.** No phone is connected, or the router has no 4G at
  the moment: calls cannot reach it over 3G. The service brings the modem back
  to 4G by itself when it can.
- **The phone cannot register.** It is on the guest Wi-Fi, or its password
  differs from `mudi-volte phone show NAME`.
- **Linphone cannot download the configuration from the QR code.** The phone is
  not on the router's Wi-Fi, or the phone was removed or got a new password
  since the code was shown. Show the code again.
- **The phone shows "service unavailable" for a moment.** The router lost the
  IMS connection; the service restores it by itself, usually within a minute.
- **Setup stops with an error about the modem.** The modem refused one of the
  settings that calls need, or did not answer. Setup has put the modem's values
  back, left the service and the router's sleep settings alone and does not
  restart the router; the web page shows the same error. Run the setup again
  later.

## Uninstall

```sh
mudi-volte uninstall
```

This gives the modem its own VoLTE settings back, restores the router's sleep
settings, removes the package with its settings and phones, and restarts the
router. `mudi-volte uninstall --keep-config` keeps the settings, so that the
phones work again after a reinstall without new QR codes.

**Without SSH**, remove the package in LuCI > System > Software (the Installed
tab, Remove next to `mudi-volte`); `opkg remove mudi-volte` does the same. The
removal gives the modem its own VoLTE settings back, puts the router's sleep
settings back and deletes the package's settings and phones, as
`mudi-volte uninstall` does, but it does not restart the router: restart it
yourself once the removal is done (LuCI > System > Reboot). Until then no calls
reach the SIM.

When the modem does not answer or refuses one of its settings, the removal
stops with an error and the phone line keeps working: try again later.
`opkg remove --force-remove mudi-volte` removes the package anyway, but leaves
the modem in External VoLTE mode, where no calls reach the SIM, and the
router's sleep mode off. It keeps `/etc/config/mudi-volte` and
`/etc/mudi-volte`: installing the package again brings the phone line back, and
`mudi-volte uninstall` then gives the modem its own VoLTE back.

Reinstalling the same version with `install.sh` (or `opkg install
--force-reinstall`), upgrading and downgrading keep the modem settings, the
phones and the data.

## Encryption

Phones set up by QR code talk to the router over TLS, and the sound of their
calls goes as SRTP (AES in counter mode with HMAC-SHA1, keys exchanged inside
TLS). Someone else on your Wi-Fi, even one who knows its password, cannot read
the numbers, the messages or the calls. In Linphone the call shows as
encrypted with SRTP.

- The router makes its own certificate (`/etc/mudi-volte/tls.crt`): no public
  authority signs certificates for a home network address. Linphone cannot be
  told to trust one particular certificate, so the QR code turns off its check
  of server certificates. This protects against listening, not against someone
  on your Wi-Fi who actively poses as the router.
- Linphone keeps these settings for all its accounts: SRTP is required for
  every call, and server certificates are not checked. Use Linphone only for
  this router, or set it up by hand.
- The QR code link itself is plain HTTP, so set up a phone when no strangers
  are on your Wi-Fi.
- The router's admin panel answers on plain HTTP as well. Open it as
  `https://192.168.8.1` and accept the browser's warning about the certificate:
  over `http://` its pages, the SMS page included, can be read off the Wi-Fi.
- Phones set up by hand on UDP still work, without encryption. To turn
  encryption off: `uci set mudi-volte.main.encryption=0; uci commit mudi-volte;
  /etc/init.d/mudi-volte restart`, then scan the QR codes again.
- Once every phone is set up by QR code, close the unencrypted ports: turn
  off "SIP without encryption" on the web page, or `uci set
  mudi-volte.main.plain=0; uci commit mudi-volte; mudi-volte restart`. Then
  nothing a phone signs can be read off the Wi-Fi at all.
- Between the router and the operator nothing changes: the signalling has IPsec
  integrity protection and the radio link is encrypted, as on any VoLTE phone.
  Calls to ordinary numbers are never encrypted end to end.

## Phones in the background

iOS stops Linphone soon after it leaves the screen, and Android may stop it
too: a battery saver, or the phone maker's own power management, can kill its
background service. Then only a push from the app's makers (Belledonne
Communications, through Apple or Google) can wake it for a call. The router
asks their server, subscribe.linphone.org, to send that push: when a call comes
and a phone has no live connection, the router sends a push that names the
call, Linphone wakes up and signs in again within a few seconds, and the router
hands it the call right away. Measured: an incoming call rang on a locked
iPhone 1.8 seconds after it reached the router.

On Android, Linphone normally keeps running (the QR code turns on its
background service) and keeps its connection, so calls ring at once and no push
goes out; the push covers the times when the service has been stopped.

The router never closes a signed-in phone's connection for being silent. A
device on the Wi-Fi without a password cannot crowd the phones out with
connections either: the router takes at most 8 from one address and 128 in
all, keeps the last 32 for addresses a phone has signed in from, and closes a
connection on which nobody signs in within 30 seconds.

To turn it on, create a free account at
[subscribe.linphone.org](https://subscribe.linphone.org) and enter its login and
password on the web page (Applications > Calls & SMS > Push notifications; in
LuCI under Settings), or on the router:

```sh
mudi-volte push login NAME     # asks the password; the service restarts
mudi-volte push                # the account and the phones that can be woken
```

- The router learns a phone's push token when its Linphone signs in, so a phone
  can be woken once it has signed in at least once with this version. The token
  survives restarts (`/etc/mudi-volte/push.json`).
- Only the phone's push token and a random call ID leave the router, not the
  caller's number. The account signs the requests; the router keeps its password
  in `/etc/config/mudi-volte`, like the phones' passwords.
- If iOS has unloaded Linphone, the first push only starts it (Linphone shows a
  call from "unknown" for a moment); the router pushes once more after 3
  seconds, and the call comes with that one.
- If the caller hangs up, or another phone answers, before the phone wakes, the
  call shows as missed in Linphone.
- A push reaches a phone anywhere, the router only on its Wi-Fi or over
  Tailscale (see [Calls away from home](#calls-away-from-home)). An iPhone away
  from both shows the incoming call for about 20 seconds but cannot answer it.
- The push service is Belledonne's free service without guarantees; if it does
  not answer, iPhones get calls only while Linphone is open, as without an
  account, and Android phones only while Linphone's service runs.

## Calls away from home

The Mudi reaches the internet through the mobile network, behind the operator's
shared address, so nothing on the internet can connect to it. The phones can
still use it from anywhere through a private network that both sides join
themselves. GL firmware ships with Tailscale:

1. GL admin panel > Applications > Tailscale: turn it on, log in, and turn on
   "Allow Remote Access LAN".
2. In the Tailscale admin console, approve the route of the router's network
   (192.168.8.0/24 by default) and turn off key expiry for the router.
3. Install Tailscale on the phones, log in to the same network and keep the VPN
   on.

The phones then reach the router at the same address as at home: the QR code,
the encryption and the pushes stay as they are. The sound is as good as the path
Tailscale finds; when both ends are behind mobile networks it may go through a
relay, with more delay.

## Known limitations

- One call at a time, a call between phones included. A second incoming call
  gets "busy".
- One phone line: the SIM in slot 1. A second SIM or the eSIM can be active at
  the same time, but its calls do not reach the phones. Keep the internet on
  SIM 1: if you move it to the other SIM (SIM Card Switch in the GL admin
  panel), the line stays up but calls get short dropouts (in a test, 0.25-0.4 s
  about every 2.4 s), probably because the modem shares its radio between the
  SIMs. Automatic switching (SIM Failover) has not been tested.
- No voice over 5G standalone (VoNR). The line needs LTE; 5G NSA is fine, since
  calls go over its LTE anchor. On a network with 5G SA the line does not come
  up: turn SA off in the modem with `AT+QNWPREFCFG="nr5g_disable_mode",1` (the
  AT Command tool in the GL admin panel, SIM 1). We have no such network to
  test this on.
- On iPhone, incoming calls in the background need the push account (see
  [Phones in the background](#phones-in-the-background)). SMS to an iPhone still
  arrive only while Linphone is open. An iPhone set up on UDP cannot be woken
  while its last registration lasts (up to an hour): the router cannot tell it
  from a live one; set it up by QR code.
- Phones on UDP (set up by hand, or before encryption came) call without
  encryption, and the TLS certificate is not checked by Linphone (see
  [Encryption](#encryption)).
- SMS go to the phones and back as plain text: no MMS, no pictures, no group
  messages.
- The page in the GL admin panel relies on how firmware 4.x loads its own
  pages; a firmware update may change that. The LuCI page and the command line
  do not depend on it.
- A GL firmware update may remove the package. Install it again afterwards:
  until then the modem stays in External VoLTE mode and calls are not answered.
- Emergency calls are not guaranteed to work. No video, no conference calls.

## How it works

The RG650V has a mode that Quectel calls "External VoLTE Stack": the modem
switches off its own IMS client and hands the SIM and the operator's IMS
connection to the host. `mudi-imsd`, the daemon in this package, is that client.
It authenticates with the SIM (IMS AKA), registers with the operator over IPsec,
answers and places calls (SIP, AMR-WB and G.711) and bridges them to the
phones on the router's Wi-Fi (SIP, G.722 and G.711).

```
 Linphone ──── Wi-Fi: SIP, RTP ────> mudi-imsd ──── IMS: SIP over IPsec, RTP ────> operator
                                   (on the router)
                                         │ AT commands: SIM authentication, modem settings
                                   Quectel RG650V in External VoLTE mode
```

SMS take another way: the operator delivers them to the modem, and GL's SMS
daemon (smsd) stores each one on the router. `mudi-imsd` passes new ones to the
phones as SIP MESSAGE, from the sender's number; a phone's message to a number
goes back out as a file in smsd's outgoing queue, the way the GL admin panel
sends SMS.

A phone whose Linphone sleeps (an iPhone in the background, an Android phone
whose Linphone service was stopped) has no connection to the router. For it,
`mudi-imsd` sends a push through Belledonne's FlexiAPI (signed with HTTP
Digest by the linphone.org account) with a Call-ID of its own, waits for the
phone to sign in again and sends it the INVITE with that Call-ID, which
Linphone matches with the call it was woken for.

The connection to the operator's IMS is a data call of its own, next to the
one for the internet. `mudi-dsi-helper`, a small program in this package,
places it directly through the firmware's `libdsi_netctrl.so` API. No interactive
test tool or terminal is involved. The helper checks that the library loads and
exports the required functions, then checks the result of each call. A broken
installation, or a call that fails on the router rather than in the network,
is reported without restarting the modem's radio. This path has
been tested on GL firmware 4.10.0; other versions still need device validation.

During setup, `mudi-volte setup` switches the modem to this mode and makes
voice IMS-only, so that the network never moves a call to 3G, where the modem
has no voice. It also turns off the router's sleep mode: GL's power saving
puts the router to sleep when no device has been connected for 15 minutes,
and a phone line has to stay awake. Uninstall restores both.

The protocol details (modem modes, AT commands, IMS registration, calls, media)
are in [docs/PROTOCOLS.md](docs/PROTOCOLS.md).

## Build from source

The build runs on Debian 13 (trixie) on arm64; a Raspberry Pi 4 or 5 works.
Other systems were not tried. You need `gcc`, `make`, `curl`, `file` and
`python3` from Debian, and Go 1.24 or newer: Go fetches the exact toolchain
version by itself (that needs internet access). For development on macOS or
another system, `go vet` and `go test` work in `volte/` and `src/imsd/` too;
the few checks that need Linux (the data call through `mudi-dsi-helper` built
against a stand-in for the firmware's library, TCP keep-alive) are skipped
there. The tests of `mudi-dsi-helper` itself need Linux too.

```sh
git clone https://github.com/xarvel/MudiVoLTE
cd MudiVoLTE
scripts/build-static.sh   # the first run also builds the toolchain; tests; build/static/
package/build.sh          # dist/: the .ipk, install.sh and SHA256SUMS
```

`build-static.sh` builds `mudi-imsd` as a fully static binary with musl and
the AMR-WB codec inside, and `mudi-dsi-helper` linked against musl the dynamic
way: it has to load a library of the firmware. To install your own build, copy
`dist/install.sh` and the `.ipk` to the router as in "No internet on the
router" above. `scripts/build-imsd.sh` is a quicker build without the codec,
for development: its network side offers only G.711.

| Directory | Contents |
|---|---|
| `package/` | The OpenWrt package: `mudi-volte` command, procd service, pages for the GL admin panel and LuCI, firewall rule, installer; `package/tests/run.sh` tests both pages |
| `src/imsd/` | The daemon `mudi-imsd` (Go) |
| `src/dsi-helper/` | `mudi-dsi-helper` (C): places the data call to the operator's IMS through the firmware's library; `tests/helper.test.py` runs it against a stand-in for that library |
| `volte/` | The VoLTE client library under the daemon: IMS AKA, IPsec, registration, calls, media, SMS ([volte/README.md](volte/README.md)) |
| `scripts/` | Build scripts; `scripts/extvolte/` has tools that read packet captures |
| `docs/` | `PROTOCOLS.md`, the RFC that the AMR payload code follows and the Bitcoin QR code |

## Contributing

Reports from other operators and firmware versions are the most useful thing
you can send; patches are welcome too. [CONTRIBUTING.md](CONTRIBUTING.md)
says how to build, test and sign off a change, and
[SECURITY.md](SECURITY.md) how to report a security problem privately.
Comments in the code cite "§N": sections of the author's engineering log,
which is not published; [docs/PROTOCOLS.md](docs/PROTOCOLS.md) is the public
account of what was seen on the live network.

## Support

MudiVoLTE is a personal project. If it is useful to you, you can support its
development in Bitcoin:

**BTC:** `bc1qcentspekpn7vjfcsdgw05vy33vxu3878tmkr84`

![BTC QR code](docs/support-bitcoin.png)

## License

The source is available under the
[PolyForm Noncommercial License 1.0.0](LICENSE): use it, change it and pass it
on for any noncommercial purpose, keeping the license terms and the
`Required Notice` line of the [NOTICE](NOTICE) file with every copy. Commercial
use needs a separate license from the author, Arthur Valiullin
(<https://github.com/xarvel>).

The third-party components inside `mudi-imsd` keep their own licenses:
[package/THIRD_PARTY.md](package/THIRD_PARTY.md) lists them, and
`package/licenses/` holds the texts.
