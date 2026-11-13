# PROTOCOLS.md — MudiVoLTE protocol reference

A reference for developers who reproduce or maintain the host-side VoLTE client
on the GL.iNet Mudi 7 router (GL-E5800, Quectel RG650V modem, OpenWrt).
Only confirmed facts from the project's engineering log and the code.
§N cites a section of the project's internal engineering log, which is not published:
it names the source of a fact, not a document you can read.
Personal data (phone numbers, IMSI, IMEI, addresses, tokens) is replaced with `<...>`.
The addresses of the operator's network (P-CSCF, MSC, media gateway, our own address on
the IMS connection) are replaced with documentation addresses (RFC 5737): `192.0.2.x` for
the operator's side, `198.51.100.x` for ours.

---

## Contents

1. [Architecture overview](#1-architecture-overview)
2. [Quectel proprietary — External VoLTE Stack](#2-quectel-proprietary--external-volte-stack)
3. [GL.iNet proprietary — Mudi firmware](#3-glinet-proprietary--mudi-firmware)
4. [Standard protocols — implementation](#4-standard-protocols--implementation)
   - 4.1 [IMS registration (sec-agree, IPsec, AKA)](#41-ims-registration-sec-agree-ipsec-aka)
   - 4.2 [Incoming and outgoing calls](#42-incoming-and-outgoing-calls)
   - 4.3 [Media (RTP, AMR-WB, G.722, G.711, DTMF)](#43-media-rtp-amr-wb-g722-g711-dtmf)
   - 4.4 [SMS over IP](#44-sms-over-ip)
   - 4.5 [SIP bridge for LAN phones (Mudi Wi-Fi)](#45-sip-bridge-for-lan-phones-mudi-wi-fi)
5. [Known pitfalls](#5-known-pitfalls)
6. [References](#6-references)

---

## 1. Architecture overview

### Components

| Component | Role |
|-----------|------|
| **Quectel RG650V** | The 5G module of the GL-E5800. The router's Linux runs on the module's own application processor (AT port `/dev/smd11`; `AT+CFUN=1,1` reboots the whole router). In "External VoLTE Stack" mode the module hands the IMS PDN to the host and runs AKA on the SIM via `AT+CSIM`. Its own IMS client is off. |
| **OpenWrt (GL-E5800)** | Host of the `mudi-imsd` daemon. This is where `rmnet_dataN` with the IMS address, kernel XFRM/IPsec and nftables live. It is also the Wi-Fi access point for the phones. |
| **mudi-imsd** | Go daemon that implements a host-side IMS UE: registration, incoming/outgoing calls, SMS, SIP bridge for LAN phones. Static arm64 binary (~8 MB), no external dependencies (musl). |
| **P-CSCF** | The operator's proxy server (two addresses, obtained via `AT+CGCONTRDP`). SIP/TCP over the IMS PDN. The first P-CSCF may connect from a non-standard source port (§82, §81). |
| **S-CSCF / I-CSCF / IMS core** | The operator's standard IMS infrastructure. |
| **Phones on Wi-Fi** | Linphone (Android / iOS) or any SIP client. They connect to the `mudi-imsd` LAN registrar over SIP/UDP, SIP/TCP and SIP/TLS (SRTP media). |

### Data paths

```
  SIM (in the modem) ←── AT+CSIM (APDU) ──────────── mudi-imsd
                                                           │
  RG650V modem ───── AT via the GL ubus proxy ────────── mudi-imsd
        │
        ├── rmnet_data0   ← internet PDN (cid 1, default APN)
        │
        └── rmnet_data1/2 ← IMS PDN (cid 2, APN "ims")
                │                 [data call: mudi-dsi-helper, 2.2]
                │
                ├── IPsec ESP (kernel XFRM)     ← hmac-md5-96 / null
                │        │
                │    SIP/TCP → P-CSCF:5060 (initial) / port-s (protected)
                │
                └── RTP/UDP → operator media gateway
                         (SO_BINDTODEVICE to the IMS interface — §88)

  br-lan (192.168.8.1/24)
        │
        ├── SIP/UDP + SIP/TCP + SIP/TLS ← phones (Linphone on Pixel, iPhone)
        │        │ (LAN registrar + B2BUA in mudi-imsd)
        └── RTP or SRTP/UDP ← phones (ports 40000–40199)
```

### Modem operating modes (three states)

| Parameter | Mudi factory state | Modem's built-in voice | External VoLTE Stack (mudi-volte) |
|----------|--------------------------|-------------------------|----------------------------------|
| `AT+QCFG="ims"` | 0 (per MBN profile) | 1 (force enable) | 2 (force disable) |
| `AT+QCALLCFG="voice_disable"` | 3 (voice off) | 2 | 3 |
| `voice_domain` / `ue_usage_setting` | 3 / 0 | 3 / 0 | 1 / 1 |
| `AT+CGACT` for the IMS cid | — | 1 (held by the modem) | 0 until the host brings up the PDN |
| IMS PDN on the host | no | no | `rmnet_dataN` |
| Voice | no: the router is data-only | the modem handles calls itself; no audio on the router | `mudi-imsd` daemon → phones on Wi-Fi |
| SMS | modem (SMS page in the GL admin panel) | modem | on the tested network still delivered to the modem via SGs; the SMS over IP path is implemented but not confirmed live (§88) |

`mudi-volte setup` saves the original values in `/etc/mudi-volte/modem.orig`, and rollback
restores exactly those values, not the "factory" ones.

---

## 2. Quectel proprietary — External VoLTE Stack

### 2.1 Switching to external stack mode

Documented in "Quectel RG520N/RM5x0N External VoLTE Stack Application Note V1.0" (2023-12-21).
All commands go through the GL AT proxy with SUB1 selected explicitly (§69, §71).

#### Full enable procedure

```
# 1. Select SUB1 and write to NV
AT+QUIMSUB=1;+QCFG="ims",2
# Read back: expect +QCFG: "ims",2  (second field = VoLTE cap = still 0/1)

# 2. The modem's own voice is off (3 is the factory value; 2 enables the built-in voice)
AT+QUIMSUB=1;+QCALLCFG="voice_disable",3

# 3. Voice only over PS/IMS (no CS fallback)
AT+QUIMSUB=1;+QNWPREFCFG="voice_domain",1

# 4. Data-centric UE — the network does not pull the modem to 3G for voice
AT+QUIMSUB=1;+QNWPREFCFG="ue_usage_setting",1

# 5. Save NV to EFS (GL does this itself after every configuration write)
AT+QEFSSYNC=0

# 6. Reboot the modem (= reboot the router on the Mudi)
AT+CFUN=1,1
# The router comes back in ~128–180 s
```

**⚠️ Important (§71):** without `AT+QEFSSYNC=0` before `CFUN=1,1`, NV writes do not survive
a hard reset — both settings (`ims` and `voice_disable`) roll back to their old values.
GL itself sends `QEFSSYNC=0` after every UCI write; reverse engineering of `libcm_modem.so` confirmed this.
The RG650V AT manual (section 1.10) gives the reason: NV settings changed by an AT command are saved
to non-volatile memory after 90 seconds, and a power loss before that may lose them (2.9).

Check after boot:
```
AT+QUIMSUB=1;+QCFG="ims"       → +QCFG: "ims",2,0   (force disable, VoLTE cap off)
AT+QUIMSUB=1;+QIMSCFG="ims_enable"  → +QIMSCFG: "ims_enable",2,0,0  (disabled)
AT+CGACT?                       → +CGACT: 1,1  2,0   (cid2 not in use)
```

#### Rollback

`mudi-volte modem builtin` and `mudi-volte uninstall` restore the values saved during
setup in `/etc/mudi-volte/modem.orig`, and so does the package's `prerm` when opkg removes
the package (`opkg remove`, LuCI > System > Software), only without the restart. For a
router that used the modem's built-in voice before installation:

```
AT+QUIMSUB=1;+QCFG="ims",1
AT+QUIMSUB=1;+QCALLCFG="voice_disable",2
AT+QUIMSUB=1;+QNWPREFCFG="voice_domain",3
AT+QUIMSUB=1;+QNWPREFCFG="ue_usage_setting",0
AT+QEFSSYNC=0
AT+CFUN=1,1
```

Check after boot: `QCFG ims 1,1`, `ims_enable 1,0,1`, `CGACT 1,1 2,1`.
For a router in the factory state the original values are different: `ims` 0, `voice_disable` 3.

The values take effect when the modem restarts, so the service keeps running while they are
written. Once the modem took all of them they are committed at once with `AT+QEFSSYNC=0`:
after a removal by opkg the user restarts the router, from LuCI or by its power button,
perhaps within seconds, before the 90 s after which the modem would save them by itself. A modem that does not answer, or refuses one of them, stops the restore: the values
written so far are set back to the External VoLTE ones, and the service, the package, the
saved values and the phones' settings stay in place for a retry. The service is switched off
and the package removed only after the modem confirmed every value. A failed `prerm` makes
opkg keep the package; `opkg remove --force-remove` removes it anyway and leaves the modem in
External VoLTE mode, with `modem.orig` and the settings kept for a later restore.

opkg (opkg-lede) runs `prerm remove` and `postrm remove` also for
`opkg install --force-reinstall`, which removes the package before it installs it again;
`PKG_UPGRADE` is 0 then, as for a removal. An upgrade or a downgrade runs `prerm upgrade` and
`postrm upgrade` instead. A reinstall keeps the modem and the data: `install.sh` marks its
reinstall with `MUDI_VOLTE_REINSTALL=1`, and `prerm` also finds `--force-reinstall` on the
command line of the opkg that runs it. `mudi-volte uninstall` marks its own `opkg remove`
with `MUDI_VOLTE_UNINSTALL=1`: it has restored the modem already and removes the data
itself.

`mudi-volte setup` works the same way in the other direction. It reads each value before it
writes it (`ims`, `voice_disable`, `ue_usage_setting`, `voice_domain`, and `mode_pref` with
`--lte-only`) and goes on only when the modem has taken all of them: without `voice_domain` 1
the network may move a call to 3G, where a modem in External VoLTE mode has no voice. When the
modem refuses a value or does not answer, setup writes the values it read back, newest first,
and fails. It turns the router's sleep mode off (3.3), enables the service and restarts the
router only after the modem has taken every value, so a cancelled or failed setup leaves the
modem, the service and the sleep settings as they were. What stays is the phone account and
the country code, which setup creates before it asks, and `modem.orig` when the modem did not
take the old values back either: `mudi-volte modem builtin` restores from it.

The web pages run setup and the restore in the background (`--detach`): a request must wait
neither for a modem that does not answer (with its retries one AT query takes minutes then)
nor for the restart, and a web server that cuts a long request would stop the run between two
writes. The run writes its output to `/tmp/mudi-volte-setup.log`, and how it goes to
`/tmp/mudi-volte-setup.state`: `running` (then `running PID`), `restarting` just before the
restart, `exit CODE` at the end (0 for success). A wrapper process (`mudi-volte detached`)
writes the end, also when the run is killed. The pages poll both files every 3 seconds: a
failure shows the last error line of the log, and only `restarting` makes them announce the
restart. `--detach` refuses to start a second run while the PID of the first is alive.

#### QCFG "ims" parameters

| Value | Meaning |
|----------|-------|
| 0 | Automatic, per MBN profile |
| 1 | Force enable (the modem's built-in IMS is on) |
| 2 | Force disable (External VoLTE Stack) |

The second field of the response (`0` or `1`) = VoLTE-capable on the network; after switching to mode 2
it is always `0`.

#### QCALLCFG "voice_disable" parameters

| Value | Meaning (verified on RG650V, log §2) |
|----------|-------|
| 3 | Factory: the modem's own voice is off. External VoLTE Stack needs this same value |
| 2 | The modem's built-in voice is on: after a full reboot the modem registers with IMS by itself |
| 0 | Voice is still off (`ql_voice_dial` → `-1002`) |

#### voice_domain and ue_usage_setting

`AT+QNWPREFCFG="voice_domain",1` — "PS/IMS voice only": the network does not try to deliver
incoming calls via CS and does not move the modem to 3G for a call.  
`AT+QNWPREFCFG="ue_usage_setting",1` — "data centric": the modem tells the network that it does not
handle CS calls; it stays on 4G for data where voice is only available on 3G. (§90)

The previous factory values: `voice_domain 3`, `ue_usage 0`. They are saved in
`/etc/mudi-volte/modem.orig` for rollback. All values of both parameters, as given in the manual, are in 2.9.

### 2.2 IMS PDN: a data call through DSI

The IMS PDN has to come up through the modem's own data stack (Qualcomm DSI), so that
netmgrd configures the `rmnet_dataN` interface the daemon then talks over. The firmware has a
library for that, `/usr/lib/libdsi_netctrl.so`, and no headers for it; the library's only
client on the router is the interactive test tool `dsi_netctrl_test`. MudiVoLTE calls the
library directly through `mudi-dsi-helper`; there is no menu-driven fallback or backend selector.
The C client lives in `src/dsi-helper/mudi-dsi-helper.c`, its supervisor in
`src/imsd/datacall.go`.

The helper holds one call. The daemon keeps it running for as long as it wants the PDN,
and takes its end, or `DSI_EVT_NET_NO_NET` after connection, as the loss of the PDN (§81, §87).
On firmware 4.10.0 the helper reached `DSI_EVT_NET_IS_CONN` in 0.6–1.1 s, versus about
2.6 s for the former menu client (§131). These are data-call times, not IMS registration times.

#### The helper: mudi-dsi-helper

```
mudi-dsi-helper SUBSCRIPTION PROFILE FAMILY
mudi-dsi-helper check
```

`SUBSCRIPTION` is `1` or `2` (`0`: whichever subscription is the default for data), `PROFILE`
is the number of the modem profile (1 to 255; see "Finding the IMS profile number" below),
`FAMILY` is `ipv4v6` or `ipv4`. The daemon runs `mudi-dsi-helper 1 <profile> ipv4v6` and, when
that call does not come up, `mudi-dsi-helper 1 <profile> ipv4`.

The helper makes the calls that `dsi_netctrl_test` makes to create and start a legacy call, with the
same arguments, in the same order. They were read off the code of the tool and of the library
(§131); the names are those of Qualcomm's `dsi_netctrl.h`.

| # | Call | Arguments | Notes |
|---|---|---|---|
| 1 | `dsi_set_modem_subs_id(subs)` | `1` | Not made for subscription `0`. Without it the call goes up on the SIM that carries the internet (the DDS subscription), which GL can move to the other SIM (§117, §118) |
| 2 | `dsi_init(mode)` | `0` (`DSI_MODE_GENERAL`) | Returns before the library has heard from netmgrd |
| 3 | `dsi_get_data_srvc_hndl(callback, user_data)` | | Returns `NULL` until the library is ready. The helper asks again every 200 ms, for up to 15 s; on the device the second request gets the handle |
| 4 | `dsi_set_data_call_param(handle, 11, &value)` | `DSI_CALL_INFO_IP_VERSION`; `value.num_val` is `10` (IPv4v6) or `4` (IPv4) | 0 = accepted |
| 5 | `dsi_set_data_call_param(handle, 1, &value)` | `DSI_CALL_INFO_UMTS_PROFILE_IDX`; `value.num_val` is the profile number | 0 = accepted |
| 6 | `dsi_start_data_call(handle)` | | 0 = accepted; the outcome comes as an event |
| 7 | `callback(handle, user_data, event, payload)` | `1` = `DSI_EVT_NET_IS_CONN`, `2` = `DSI_EVT_NET_NO_NET` | Runs on a thread of the library; the helper only passes the event number to its main loop |
| 8 | `dsi_stop_data_call(handle)` | | To end the call. The helper then waits up to 2 s for `DSI_EVT_NET_NO_NET` |
| 9 | `dsi_rel_data_srvc_hndl(handle)` | | |

`value` is a `dsi_call_param_value_t`: `struct { char *buf_val; int num_val; }`, 16 bytes on
arm64; `buf_val` is not read for these two parameters.

Two things the tool does are left out on purpose:

- For "AUTOMATIC" the tool also sets a technology preference:
  `dsi_set_data_call_param(handle, 9, &value)` (`DSI_CALL_INFO_TECH_PREF`) with `num_val` 0.
  The library refuses that value (returns -1) and changes nothing, and the tool does not look at
  the result. "Automatic" is a preference that nobody set, so the helper sets none.
- The helper ends with `_exit` and never runs exit handlers. The library registers one that takes
  its state apart under locks its own threads may hold. The tool never runs it either: it is
  ended by a signal. The kernel closes the QMI sockets, and the modem drops what the handle held.

**Library loading.** The helper loads `/usr/lib/libdsi_netctrl.so` with
`dlopen(RTLD_NOW | RTLD_GLOBAL)` and resolves the seven functions above with `dlsym`.
There is no library hash allowlist: a rebuild of the same API does not require a new helper.
`mudi-dsi-helper check` loads the library and resolves the functions without calling them or
placing a data call. Success prints these two lines and exits with 0:

```
{"v":1,"event":"library"}
{"v":1,"event":"exiting","code":0}
```

A missing library or dependency produces `library_load`; a missing function produces
`library_symbol`. Both exit with 1 and put the loader's diagnostic on stderr. Library
constructors also write to stderr, not to the event stream. In `check` mode the helper leaves the
stop signals as it found them (by default they end it at once), so even a stuck loader can be
terminated without waiting for a call to stop, and a library that has not loaded within 10 s
counts as one that does not load (`library_load`): `mudi-volte setup` waits for this answer.

The declarations and values were verified against firmware 4.10.0 and Qualcomm's
`dsi_netctrl.h`. Symbol lookup is not an ABI-version test: a firmware that changes a signature
or structure layout needs verification and possibly updated declarations. The helper checks each
API return code and reports the actual connection outcome; other firmware versions have not yet
been validated on a device.

**Events.** One JSON object per line on stdout; `"v":1` is the version of this protocol.
Whatever the libraries print goes to stderr: the helper writes its events to a duplicate of its
stdout and points descriptor 1 at stderr before it loads the library, so that a library's print
cannot land inside an event line.

| Event | Meaning | The daemon |
|---|---|---|
| `{"v":1,"event":"library"}` | The library is loaded and has the functions: the answer to `check`, and for a call the first event, before step 1 | from here on a failure is the router's, not the installation's |
| `{"v":1,"event":"ready","pid":N,"subscription":1,"profile":2,"family":"ipv4v6","tries":2}` | The call is set up (steps 1–5); it starts now. `tries` counts the requests of step 3 | logs it; from here on the network has its say |
| `{"v":1,"event":"net_up"}` | `DSI_EVT_NET_IS_CONN`: the call is connected | goes on to 2.3 |
| `{"v":1,"event":"stopping","signal":N}` | The helper was asked to stop and stops the call now (step 8): by signal `N`, or by the end of its stdin when `N` is 0. The `net_down` that follows is this stop | when the daemon did not ask for it: the call was lost on the router, not in the network |
| `{"v":1,"event":"net_down"}` | `DSI_EVT_NET_NO_NET`: the network refused the call, or ended it | before `net_up`: tries the next IP family; after: the PDN is lost |
| `{"v":1,"event":"dsi_event","code":N}` | Any other event of the library, by its number. On firmware 4.10.0, 19 comes right before `net_up` and 20 right before `net_down` | logs it |
| `{"v":1,"event":"error","stage":"NAME","code":N}` | A step failed. `NAME` is the library function that failed (`dsi_set_data_call_param` adds `"param":N`), or `library_load`, `library_symbol` for a library the helper cannot use, or `setup` for a failure of its own | the call failed; who is to blame follows from the events before it (see "Failure handling") |
| `{"v":1,"event":"exiting","code":N}` | The last line; `N` is the exit status | |

Exit status: 0 = stopped on request, 1 = a step failed, 2 = usage, 3 = the network ended the call.

**Stopping.** SIGTERM (or SIGINT, SIGHUP), or the end of its stdin: the helper reports
`stopping`, stops the call (steps 8–9) and exits. The daemon holds a pipe to the helper's stdin
and closes it to stop the call. A daemon that dies closes that pipe as well, so the call does not
outlive the daemon; a helper that finds nobody reading its `ready` does not start the call at all.
With the daemon gone nobody reads the helper's events or stderr either. The helper holds SIGPIPE
back while it writes a line of its own, and once a line found no reader it points stdout and
stderr at `/dev/null`: neither it nor a thread of the library is killed half way through the stop.
Measured on the device (§131):

- stdin closed, or SIGTERM: the helper has exited and the IMS address is gone within 0.1 s;
- `kill -9` of the daemon: its helper is gone within 0.1 s;
- `kill -9` of the helper: the modem drops the call, the IMS address is gone within 0.3 s; the
  internet PDN stays up. The daemon notices at once, places the call again and registers (17 s
  from the kill to the registration, 5 s of them a wait for the answer to a de-REGISTER that the
  daemon no longer sends, see 4.1; the radio is not restarted);
- a second helper for the same profile gets `net_up` for the call that is already up, and the
  call stays up when the second one leaves: the first still holds it.

#### Failure handling

Who is to blame for a failed call follows from how far the helper got, not from the name of the
step that failed (`blame` in `src/imsd/datacall.go`):

| The helper got | A failure means | The session ends with | Radio restart |
|---|---|---|---|
| nowhere: missing, cannot execute, no `library` event (`library_load`, `library_symbol`, `setup`, a silent exit, a hang while loading, another protocol version) | the helper cannot work on this installation; the other IP family is not tried | `helper-unusable` | never |
| past `library`, not to `ready` (`dsi_init`, no handle, a parameter refused, a crash or hang in the library) | the call failed on the router; the other IP family is tried | `helper-failed` | never |
| past `ready`, with a word about the call (`dsi_start_data_call` failed, `net_down`, no reply) | the network had its say; the other IP family is tried | `pdn-failed` | on the second in a row |
| past `ready`, before or after `net_up`, also while the daemon waits for the address after it: a `stopping` the daemon did not ask for, or an exit without a word about the call | something on the router ended the call: a signal, `kill`, a crash | `helper-failed` | never |
| `net_up`, then `net_down` | the network ended the call | `pdn-lost`; `pdn-failed` while the address has not come yet | after a visit to 3G, or on the second drop within 15 min (§87); `pdn-failed`: on the second in a row |

When both IP families fail, the session counts as `helper-failed` only when neither got as far as
the network. `helper-unusable` and `helper-failed` never trigger a radio restart, and they do not
count towards one either: the first refusal after them is a first, not a second. Restarting the
radio cannot repair the router's side of the call and would interrupt the internet (§131).

"In a row" counts the failures the radio or the network had a say in (every end but
`helper-unusable` and `helper-failed`) since the last registration or radio restart: either one
starts the count anew, and so does a session that ran for 30 minutes. After a radio restart it
takes two more such failures for the next one, never more than 3 restarts an hour. A session
that ends with `rat-fallback` or `registration-failed` restarts the radio at once.

The daemon tries the next session after 5 s, 15 s, 30 s, 1 min, 2 min, and then every 5 min. This
wait counts every failed session in a row, registered or not, and a radio restart does not
shorten it: only a session that ran for 30 minutes starts it anew, so that a registration that
stands for seconds and goes again does not make the daemon register every 5 s. Code: `loop` in
`src/imsd/service.go`.

**Restarts after a crash.** procd starts a daemon that ended without a stop again 10 s later,
without a limit (`respawn 3600 10 0`), and each new process would place the data call and
register anew. `/var/run/mudi-volte/crashes.json` (tmpfs, next to the state file) tells the next
process whether the last one ended by its own choice (a stop, or an error it reported, such as a
bad `ims_profile`) or not (a panic, a kill, the OOM killer), and how many in a row did not. The
process that follows such ends waits before its first data call: not at all after the first,
then 10 s, 30 s, 1 min, 2 min, and 5 min from the sixth on in a row, with procd's 10 s on top.
The phones' SIP server is up meanwhile; their calls get 503. The count starts anew after a clean
stop (`/etc/init.d/mudi-volte stop` or `restart`, `uci commit mudi-volte`, an upgrade), after
30 minutes of running and with a reboot. The state file shows it as `crash_restarts` (0 again
after the 30 minutes) and the wait as `last_error`; `mudi-volte status` prints "Restarts of the
service after a crash: N in a row". Code: `src/imsd/crashes.go`.

`mudi-volte setup` checks the helper and DSI API before touching the modem
(`check_data_call` in `package/files/usr/sbin/mudi-volte`). There is no `data_call` option;
the daemon's optional `dsi_helper` configuration key overrides the helper's executable path.
The old `dsi_path` JSON key is ignored on upgrade. An `ims_profile` outside 0–255 ends the
service at its start, with the error in `mudi-volte status`: it is a mistake in the configuration,
not a failure of the call (procd starts the service again every 10 s, to the same end; such an
end does not count as a crash, it reaches no network).

On a successful call, `dsi event=net_up` precedes address discovery and registration.

When the service starts, `killStaleDSI` (`src/imsd/datacall.go`) stops leftover
`mudi-dsi-helper` or `dsi_netctrl_test` processes, and processes of the helper that `dsi_helper`
names (matched by its name and by the file they run, `/proc/PID/exe`). `dsi_netctrl_test` is
cleanup for old versions and manual tests, not a way to start a new call. The modem shares a
call among clients on the same profile, so a leftover client would keep the PDN alive after the
daemon stopped its own call.

#### Finding the IMS profile number

```
AT+CGDCONT?
# Find the line with APN "ims" → take the first field (cid, usually 2)
```

Code: `parseIMSProfile` in `src/imsd/pdn.go`.

### 2.3 AT+CGCONTRDP — IMS PDN parameters

After `DSI_EVT_NET_IS_CONN`, read the parameters:

```
AT+CGCONTRDP=2
```

Example of a live response (§75; the public DNS addresses are replaced with documentation ones):
```
+CGCONTRDP: 2,6,"ims","198.51.100.20",,"203.0.113.105","203.0.113.106","192.0.2.20","192.0.2.28"
```

Fields per TS 27.007 §10.1.23:
1. `cid` = 2
2. `bearer_id` = 6
3. APN = "ims"
4. PDN IP address (possibly with a mask; the separate mask field is empty)
5. gateway (empty — none)
6. DNS1
7. DNS2
8. **P-CSCF 1** ← first
9. **P-CSCF 2** ← second

**⚠️ Trap (§75):** the gateway is empty, and the P-CSCFs come AFTER the two DNS addresses — the parser must
count by position, not by content.
Code: `parseCGCONTRDP` in `src/imsd/pdn.go` (fields 8 and 9 = P-CSCF).

IMS interface: `rmnet_data*` with the address from field 4 of CGCONTRDP.  
**⚠️ Trap (§87):** the `rmnet_dataN` numbers of the internet PDN and the IMS PDN may swap
after a reconnect (for example, `rmnet_data1` ← internet after CFUN 4→1).
Code: `findIMSIface` in `src/imsd/pdn.go` — it looks for the interface with the IP from CGCONTRDP, not
for a fixed name.

### 2.4 AT+QIMSCFG="authenticate"

The command that runs AKA on the SIM (§72):

```
AT+QUIMSUB=1
AT+QIMSCFG="authenticate",11,"10<RAND_32hex>10<AUTN_32hex>"
```

- Context `11` = IMS AKA.
- `RAND` and `AUTN` are passed as a hex string, each prefixed with `10` (length 16 bytes = 0x10).
- Response on success: `+QIMSCFG: "authenticate",DB,<RES_hex>,<IK_hex>,<CK_hex>`
- Response on sync failure: `+QIMSCFG: "authenticate",DC,<AUTS_hex>`
- `AUTS` is used to resynchronize the SQN (a repeated REGISTER with `auts=`).

**Limitations (§72):**
- `QIMSCFG` (`authenticate` and others) does NOT work in a compound line after `QUIMSUB=1;`
  (ERROR). It needs a separate `AT+QUIMSUB=1` call, then the command right after it.
- A repeated call with the same AUTN → `DC` (the SIM consumes the SQN; a repeat is a normal reaction
  to a transaction retry, but the SIM will refuse it).
- **Never retry a successful AKA response** (§72, §74 — guard in `atproxy.go`).

**The daemon's working path is AT+CSIM (§74, §88):** `AT+CSIM` with the AUTHENTICATE APDU
(`00 88 00 81 ...`). This is a standard SIM command and does not need `QIMSCFG`;
`QIMSCFG "authenticate"` was used only in early manual tests (§72).
Implementation: `src/imsd/csim.go` (transport); the card's response is parsed by the wwan-go library.

### 2.5 QIMSCFG for reading identities

Readable once the SIM reports `+CPIN: READY`, both with the modem's built-in IMS and in External VoLTE mode (§71):

```
AT+QUIMSUB=1
AT+QIMSCFG="impi"     → IMPI (IMS Private Identity = <IMSI>@ims.mncXXX.mccYYY.3gppnetwork.org)
AT+QIMSCFG="impu"     → IMPU (sip:<IMSI>@ims.mncXXX...)
AT+QIMSCFG="domain"   → IMS home domain
AT+QIMSCFG="user_agent"
```

Without an ISIM, IMPI/IMPU are derived from the IMSI per TS 23.003 §13. If the SIM has an ISIM,
wwan-go `sim.Card` reads the real ISIM identities via `AT+CSIM` (§88).

### 2.6 AT+QENG — cell information for P-Access-Network-Info

```
AT+QENG="servingcell"
```

The response format varies (§77, §85):

- Single line: `+QENG: "servingcell","NOCONN","LTE","FDD",MCC,MNC,cellID,PCID,EARFCN,band,ULbw,DLbw,TAC,...`
- Multi-line (EN-DC, LTE+NR5G-NSA):
  ```
  +QENG: "servingcell","NOCONN"
  +QENG: "LTE","FDD",MCC,MNC,cellID,PCID,EARFCN,band,ULbw,DLbw,TAC,...
  +QENG: "NR5G-NSA",...
  ```

**⚠️ Trap (§85):** after the word `"LTE"` the fields are, in order:
`duplex, MCC, MNC, cellID, PCID, EARFCN, band, ULbw, DLbw, **TAC (+10)**`.
TAC is the **tenth** field, not the sixth (that one is EARFCN). The parser must count from the `"LTE"` token.
Code: `parseQENGANI` in `src/imsd/pdn.go`, with 3 retries and the raw response in the error.

P-Access-Network-Info format (TS 24.229 §7.2A.4):
```
3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=<PLMN><TAC4hex><ECI7hex>
# example (fictitious cell): 3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=001013C0D01A2B03
# PLMN=00101 (MCC=001, MNC=01: the 3GPP test network), TAC=3C0D, ECI=01A2B03
```

If the modem is on WCDMA (a transient state after the PDN comes up), do not build a PANI for E-UTRAN;
wait for LTE (§79).

The cell ID reveals the router's location to within hundreds of meters. Since 0.9.14 the daemon
logs only the PLMN (`…=00101…`) at info level; the full value is logged at debug level.
The cells in the examples of this document and in the tests are fictitious.

### 2.7 AT+CGSN — IMEI

```
AT+CGSN
```

Returns the 15-digit IMEI. Used in `+sip.instance` (RFC 7254: `urn:gsma:imei:...`).

### 2.8 AT+COPS / AT+CEREG

```
AT+COPS?   → MCC, MNC, current operator
AT+CEREG?  → LTE registration status (0,1 = registered home; 0,5 = registered roaming)
```

Expect `CEREG: 0,1` or `0,5` after `CFUN=1,1` and after `CFUN 4→1`.
Matching `"L"` in the response does not work because the ubus proxy escapes quotes (§87).

### 2.9 Cross-check against the RG650V AT manual

The commands in 2.1–2.8 were taken from documents for the neighboring RG520N/RM5x0N family and from experience.
"RG65xE&RG650V&RM550V&RM551E Series AT Commands Manual" V1.0 (Released, 2024-07-11) is
the manual for the module's own family; it was obtained on 2026-11-05. It confirms the common commands and does not describe
any of the commands of the external stack mode. Page numbers are the ones printed in the manual's page footer.

| Command | Section, page | What the manual says |
|---------|--------------|-----------------------|
| `AT+QNWPREFCFG="voice_domain"` | 5.22.7, p. 134 | 0 — CS only; 1 — IMS PS only; 2 — CS, IMS PS as fallback; 3 — IMS PS, CS as fallback. Takes effect immediately; saved automatically, with the delay from 1.10 |
| `AT+QNWPREFCFG="ue_usage_setting"` | 5.22.9, p. 136 | 0 — voice centric; 1 — data centric. Takes effect immediately; saved automatically, with the delay from 1.10 |
| `AT+QEFSSYNC` | 3.5, p. 54 | `=0` — save NV synchronously, `OK` after the write (longer than 300 ms); `=1` — asynchronously, `OK` immediately |
| NV write delay | 1.10, p. 14 | On modules with eMMC, NV settings changed by an AT command are saved 90 s after the command; a power loss before that may lose them. Save important settings with `AT+QEFSSYNC`, once after all writes |
| `AT+QENG="servingcell"` | 5.18, p. 102 | Response format for LTE, NR5G-SA and EN-DC |
| `AT+QUIMSLOT` | 4.15, p. 74 | SIM slot switching |
| `AT+CGSN`, `AT+CFUN`, `AT+CIMI`, `AT+CSIM`, `AT+COPS`, `AT+CREG`, `AT+CEREG`, `AT+CGDCONT`, `AT+CLCC`, `AT+CGACT` | pp. 20, 29, 55, 63, 75, 77, 81, 84, 159, 207 | Described |

The 3GPP TS 27.005 SMS commands are in the manual too (chapter 9, pp. 178–204; `AT+CGSMS` — 10.6, p. 213).
The project does not use them; for SMS see 4.4.

The commands that the external stack mode relies on are not in the manual. Checked by a text search
of the manual and of the other documents collected for the project:

| Command | Where it is described |
|---------|-------------|
| `AT+QCFG="ims"` | External VoLTE Stack Application Note (RG520N). In the RG650V manual the `AT+QCFG` section (3.3, p. 37) describes 12 subcommands, and `"ims"` is not one of them |
| `AT+QIMSCFG` | Only the External VoLTE Stack Application Note |
| `AT+CGCONTRDP` | 3GPP TS 27.007 §10.1.23 and the same Application Note |
| `AT+QCALLCFG="voice_disable"` | None of the documents; the values were established by experiment (2.1) |
| `AT+QUIMSUB` | None of the documents; the behavior was established by experiment (3.1, §69) |

---

## 3. GL.iNet proprietary — Mudi firmware

### 3.1 AT proxy via ubus

GL.iNet Mudi uses a ubus proxy for AT commands instead of direct `/dev/smdN` access:

```sh
ubus call modem.CPU.AT get_result_AT \
  '{"cmd":"AT+QCFG=\"ims\"","timeout":12,"sub_id":1}'
```

JSON response: the `data` field = the AT response lines (CR/LF).

Code in the daemon: `ubusAT` in `src/imsd/atproxy.go`; in the script: `at_raw()` in `package/files/usr/sbin/mudi-volte`.

#### SUB2 trap (§69) — MUST READ

GL's background poller (`libcm_modem.so`, function `quectel_set_slot_sub_id`) keeps
switching the AT port context between SUB1 (the slot with the SIM) and SUB2 (empty). A single
call with `sub_id:0` may land in the context of the empty SUB2.

With `sub_id` 1 or 2 the proxy sends `AT+QUIMSUB=<n>` itself, unless the slot it remembers is
already that one. It does not see an `AT+QUIMSUB` inside a command line, so such a line leaves
it remembering the wrong slot, and GL's own request for the other slot can be answered from ours
(§117). The daemon and the script call the proxy with `sub_id:1` and still put the selection
into the AT line.

**Symptom:** `QCFG ims` → `0,0` instead of `1,1` / `2,0`; `ims_enable` → `0,1,0`.

**Rule:** every AT line starts with `AT+QUIMSUB=1;` (this pins the slot). For compound
queries:
```
AT+QUIMSUB=1;+QUIMSUB?;+QCFG="ims"
```
The response must contain `+QUIMSUB: 1` — this confirms that the command ran in SUB1.

**Limitation (§72, §74):** `AT+QIMSCFG="authenticate"`, `AT+QIMSCFG="impu"` and the other
`QIMSCFG` subcommands do NOT work in a compound line (`AT+QUIMSUB=1;+QIMSCFG=...` →
ERROR). For them: a separate `AT+QUIMSUB=1`, then `AT+QIMSCFG=...` immediately after it.

**`AT+CSIM` goes in one line with the selection (`ATLink.csim`, §117):** with a live SIM in the
other slot an APDU sent there gets an ordinary reply, and nothing shows that it reached the
wrong card. Measured with two SIMs (§118): selection and command as two proxy calls, 7 of 120
answers came from the other SIM; in one line, none of 60.

**Race in service mode (§90):** if two processes select SUB1 at the same time (the daemon +
`mudi-volte status`), one of them loses the context. Solution: the AT primitives are serialized by
a mutex in `ATLink`; the `mudi-volte` script has a separate `at()` with retries.

#### ATLink retries

`ATLink.command()` / `ATLink.query()` / `ATLink.csim()` in `src/imsd/atproxy.go`:
- Up to 4 attempts (`Retries: 4` in `main.go`).
- What triggers a retry: `CME ERROR`, `No Service`, `ERROR` → `wrongContext()` → retry.
- **Exception:** a successful `+CSIM:` in the response is never retried (SQN protection).

### 3.2 fw4 (OpenWrt nftables)

The IMS interface (`rmnet_dataN`) is not in any fw4 zone. Without an explicit rule, incoming
ESP traffic from the P-CSCF is rejected as "new" once the conntrack entry for
generic protocol 50 expires (~200 s, §87).

Persistent rule: `/usr/share/nftables.d/chain-pre/input/20-mudi-volte.nft`:

```nft
# mudi-volte: let the operator's IMS core reach the VoLTE client.
iifname "rmnet_data*" meta l4proto esp counter accept  comment "mudi-volte: IMS ESP in"
iifname "rmnet_data*" meta ipsec exists counter accept comment "mudi-volte: IMS IPsec in"
```

First rule: lets encrypted ESP through to XFRM decapsulation.  
Second rule (`meta ipsec exists`, a synonym of `meta secpath` in nft 1.0.8+): lets through
the decrypted TCP/UDP from the P-CSCF after the kernel has decapsulated it.

`iifname "rmnet_data*"` covers all numbers (1, 2, …); `rmnet_data0` (internet)
has no IMS SA, so incoming ESP on it will not pass the XFRM crypto check.

fw4 includes `chain-pre/input/*.nft` automatically on every `fw4 reload`
(WAN restart, hotplug). The rule goes before `ct state established,related accept`.

**⚠️ Trap (§88):** the first rule alone is not enough. Once the kernel has taken the ESP
off, the TCP from the P-CSCF to port-s comes to the input chain again as a plain packet
from a WAN interface, and without the second rule (`meta ipsec`) it ends in fw4's reject.

### 3.3 Mudi firmware specifics (GL-E5800)

- **No `setsid`** (only `nohup`) — background start: `nohup "$0" ... &` (§89, `mudi-volte detach`).
- **No `logread` history** older than ~5 min (kernel buffer ~256 KB, heavily filled by ql_ril).
  The daemon writes to `/var/log/mudi-volte.log` (1 MB + rotation to `.1`). The time zone is taken from
  `system.@system[0].zonename`; the zone database is built into the binary. The file is on `tmpfs` and does not survive a reboot.
- **procd** is the init system. The `mudi-volte` service is in `/etc/init.d/mudi-volte` (rc.common,
  `USE_PROCD=1`): `respawn` without a limit, `term_timeout 30`, restart on `uci commit mudi-volte`.
  After each crash in a row the daemon waits longer before its first data call (2.2).
- **fw4 check** is not available on some firmware versions (§89).
- **`/etc/rc.common` START=99** — the service starts last, after the network and LAN.
- **The overlay differs from regular OpenWrt** (`/lib/preinit/80_mount_root`, the `e5800` branch):
  the eMMC partition `systemrw` (ext4) is mounted at `/overlay`, the upper layer is
  `/overlay/rootfs-upper`, the work directory is `/overlay/.rootfs-work`; the read-only root
  is in `system` / `system_b` (A/B update slots).
- **`firstboot -y` erases nothing here** (verified 2026-11-05): `jffs2reset` expects
  a `rootfs_data` partition, which the E5800 does not have. After `firstboot -y; reboot` the router
  boots with all its settings and packages.
- **Factory reset by the GL firmware** (the Reset Firmware button, RPC `reset_firmware`
  in `/usr/lib/oui-httpd/rpc/system`): `set_modem_cfun0`, then
  `atcmd 'AT+QCFG="ResetFactory"'` (modem reset) and the same `firstboot -y; reboot`.
  We have not pressed the button: what remains of the package and of the modem settings after it is not verified.
- **Manual reset of the router settings** (done 2026-11-05 11:20, confirmed): remove the package
  (`mudi-volte uninstall -y` returns the modem to its standard mode), then as root
  `rm -rf /overlay/rootfs-upper/* /overlay/rootfs-upper/.[!.]* /overlay/.rootfs-work/*`,
  `sync`, `reboot -f` — the same thing `jffs2reset` would do if it knew GL's directory names.
  After the reboot: factory SSID `GL-E5800-xxx`, SSH closed until the web setup wizard
  has been completed, the old root password no longer works, new DHCP leases. This path does not touch
  the modem (uninstall has restored its settings). Deleting the upperdir under a running system
  is acceptable only with an immediate reboot, as the standard `jffs2reset` does.
- **The `lpm-monitor` power saving puts the whole router to sleep** (uci `lpm.global`):
  `wifi_sleep_time` (s; no Wi-Fi clients → radio off), `phy_sleep_time` (no wired
  link); with `system_sleep_enable=1`, after both — "ap sleep": modem `CFUN=0`, SoC in suspend
  (the kernel clock stops), and after `auto_shutdown_time` seconds of sleep — `poweroff`. Factory values:
  900/900/1/18000. For a VoLTE line all of this must be off: 0 = never
  (`/etc/init.d/lpm_monitor restart` after `uci commit lpm`). `mudi-volte setup` does this
  itself and saves the original values in `/etc/mudi-volte/lpm.orig`; uninstall restores them (§91, 2026-11-05).
  Setup does it only once the modem has taken its values: a failed setup leaves sleep as it was.
- **After a firmware update**, `clean_overlay` in the same preinit script wipes `/overlay` when
  `/overlay/.overlay_clr_flag` is set, keeping only the settings saved by the firmware
  (`cfg_bak`). Judging by the script, installed packages do not survive an update
  and `mudi-volte` has to be installed again; this has not been verified with a real update.
- `AT+CFUN=1,1` on the Mudi = a reboot of the whole router (~130–180 s). There is no separate
  "reboot only the modem" command.
- **Two SIMs (§117, §118).** Two nano-SIM slots and a built-in eSIM that takes the place of
  SIM 2 (`AT+QSIMTYPE="slot2"`: 0 = nano-SIM, 1 = eSIM). Both SIMs stay registered (dual standby);
  the internet goes through one, and GL's SIM Card Switch moves it (`current_sim_slot` in
  `ubus call cellular.modem status`), without a reboot. The phone line stays on SUB1. With the
  internet on the other SIM the IMS PDN stays up, but the RTP of a call has gaps of 0.23–0.4 s
  about every 2.4 s; with the internet on SIM 1, none over 29 ms outbound (one recorded call of
  each). The likely cause is the radio shared between the SIMs.

### 3.4 GL screen (gl_screen)

The `gl_screen` daemon (package `gl-sdk4-screen-large`, procd, ubus) draws the firmware UI on
`/dev/fb0` (240×320 px, RGB565, GC9307C panel over SPI).

- Backlight: `/sys/class/backlight/soc:backlight` (`bl_power 0/1`, `brightness 0–120`; GL sets 36+20).
- Touchscreen: `/dev/input/event0` (`chsc_cap_touch`, i2c `1-002e`, driver `semi_touch`).
- ubus methods: `ubus call gl_screen set '{"method":"reload|usb_detected|switch|..."}'`.
- Custom pages cannot be added to `gl_screen` (the layout files in `/etc/gl_screen/config`
  are proprietary).

**Drawing a QR code (§90):** stop `gl_screen` → write directly to `/dev/fb0` (RGB565) →
control the backlight via sysfs → start `gl_screen` again.

**⚠️ Touchscreen while gl_screen is stopped (§90):** touches are read from
`/dev/input/event0` only if the screen was not asleep at that moment. The touchscreen driver does not
wake up from sleep: the backlight can be woken via sysfs, the sensor cannot. That is why the screen with
the QR code closes on a timer (the screen says after how many seconds), and a touch
is only an extra way to close it.

---

## 4. Standard protocols — implementation

### 4.1 IMS registration (sec-agree, IPsec, AKA)

The full cycle has been verified live on the network of a European operator (§75).

#### Sequence

```
UE                                  P-CSCF (192.0.2.28:5060)
 │                                       │
 │── REGISTER (initial, unprotected) ───>│
 │   From/To: sip:<IMPU>@<domain>        │
 │   Via/Contact: <IMS-IP>:<port-s>      │
 │   Security-Client: ipsec-3gpp;        │
 │     alg=hmac-md5-96;ealg=null;        │
 │     prot=esp;mod=trans;               │
 │     spi-c=<SPI_c>;spi-s=<SPI_s>;     │
 │     port-c=<port_c>;port-s=<port_s>  │
 │   Require: sec-agree                  │
 │   Proxy-Require: sec-agree            │
 │   P-Access-Network-Info: <ANI>        │
 │<── 401 Unauthorized ──────────────────│
 │    WWW-Authenticate: Digest           │
 │      realm=<IMS_domain>               │
 │      nonce=<RAND‖AUTN hex>            │
 │      algorithm=AKAv1-MD5             │
 │    Security-Server: ipsec-3gpp;       │
 │      alg=hmac-md5-96;ealg=null;       │
 │      spi-c=<P_SPIc>;spi-s=<P_SPIs>; │
 │      port-c=<P_portc>;port-s=<P_ports>│
 │                                       │
 │  [SIM AKA: RAND+AUTN → RES, IK, CK] │
 │  [install 4 IPsec SAs in kernel XFRM] │
 │                                       │
 │== REGISTER (protected, ESP) =========>│
 │   Via/Contact: <IMS-IP>:<port-s>      │
 │   Authorization: Digest               │
 │     algorithm=AKAv1-MD5              │
 │     response=<MD5(RES as password)>   │
 │   Security-Verify: ipsec-3gpp;...    │
 │<== 200 OK ============================│
 │    P-Associated-URI: sip:+<MSISDN>@..│
 │    Service-Route: ...                 │
 │    Expires: 3600                      │
 │                                       │
 │== SUBSCRIBE (reg-event) =============>│
 │<== 200 OK + NOTIFY ====================│
```

#### REGISTER SIP headers

- **From / To**: `sip:<IMPU>@<domain>`; without an ISIM, IMPU = `sip:<IMSI>@ims.mncXXX.mccYYY.3gppnetwork.org`.
- **Via / Contact**: our protected server port. `Contact: <sip:<user>@<IMS-IP>:<port-s>;transport=tcp>;expires=…;+sip.instance="<urn:gsma:imei:...>";+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel";+g.3gpp.smsip`
- **Connections**: the first REGISTER goes over plain TCP from an ephemeral port to P-CSCF:5060;
  after the 401 the daemon listens on `port-s`, installs the SAs and opens a protected connection
  from `port-c` → the P-CSCF's `port-s`. The protected REGISTER carries `Security-Verify` (an echo of `Security-Server`).
- **Security-Client**: we offer `hmac-md5-96` / `null` (TS 33.203 §7). Every REGISTER over
  the current SAs carries new SPIs and a new port-c, with the same port-s (see "Refresh and re-REGISTER" below).
- **P-Access-Network-Info** (PANI): `3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=<PLMN><TAC><ECI>`.
  Mandatory: registration does not proceed when the access-network information cannot be built (§75).
- **Require / Proxy-Require**: `sec-agree` (RFC 3329).
- **Supported**: `path, gruu, sec-agree`.
- **P-Preferred-Identity**: after registration = the first P-Associated-URI (not the temporary
  IMSI-derived IMPU); otherwise outgoing calls get `403 Invalid User` (§88).

#### IPsec SA (XFRM / TS 33.203)

4 unidirectional SAs:

| SA | Source | Destination | Receiver's SPI |
|----|---------|------------|----------------|
| UE-uc → P-CSCF-ps | UE:port-uc | P-CSCF:port-s | P-CSCF SPI-s |
| UE-us → P-CSCF-pc | UE:port-us | P-CSCF:port-c | P-CSCF SPI-c |
| P-CSCF-pc → UE-us | P-CSCF:port-c | UE:port-s | UE SPI-s |
| P-CSCF-ps → UE-uc | P-CSCF:port-s | UE:port-c | UE SPI-c |

- `port-c` and `port-s` are our protected client and server ports (random, from
  20000–59999), announced in Security-Client. In the table they are also called `port-uc` and `port-us`.
- Algorithms: `hmac-md5-96` for integrity (IK key, 16 bytes), `null` encryption.
- Keys: IK from the AKA response for SA integrity; CK is ignored (ealg=null).
- Mode: transport (not tunnel).
- Every state and policy template has `reqid 0x4d554449` (the ASCII word
  `MUDI`). It is an ownership tag shared by all MudiVoLTE SAs; the SPI still
  selects a particular SA.

Installed through the kernel's XFRM netlink interface (`volte/ipsec/netlink_linux.go`, with
`github.com/vishvananda/netlink`), so the keys never pass through a command line; the same
operations rendered as `ip xfrm state add` / `ip xfrm policy add` (`volte/ipsec/xfrm.go`) serve
as a fallback (`ipsec_tool: "ip"`) and in the tests. Normal removal is targeted: policies by
selector and states by SPI. Before its first session and at shutdown, the service lists the SAD
and SPD and removes only entries carrying the `MUDI` reqid, including entries left by a process
killed before its in-memory teardown ran, with the tool of `ipsec_tool` (`RemoveOwnedWith` in
`volte/ipsec/owned.go`): through netlink, or with `ip -o xfrm policy list`, a delete by selector
for each policy of ours and `ip xfrm state deleteall proto esp reqid 1297433673 mode transport`.
`flush` and a `deleteall` without that filter are not used: they would wipe other SAs, for
example a VPN on the same router. A sweep that fails is logged and tried again before each
session until it works; it does not keep the line down, because the entries left cannot keep a
registration out. A new one takes fresh random ports and SPIs, and should one of its selectors
meet a stale policy all the same, the kernel refuses the add (`EEXIST`) and the rollback of that
attempt deletes by selector, the stale policy with it, so the next attempt goes in.

**LooseInboundSrcPort (§82):** P-CSCF 192.0.2.20 connects to our port-s from
an unpredictable source port (not from the port-c announced in Security-Server). The decapsulation
policy must not check the source port of incoming packets. Option `LooseInboundSrcPort bool`
in `volte/ipsec/sa.go`.

#### AKA — SIM authentication

The nonce from the 401 = RAND‖AUTN (16 bytes each, 32 bytes in total, hex in `nonce=`).

```
RAND, AUTN = nonce[:16], nonce[16:]
```

Two ways to call it (the daemon uses the second one):
1. **`AT+QIMSCFG="authenticate",11,...`** — only in External VoLTE mode; response
   `DB,RES,IK,CK` (§72).
2. **`AT+CSIM` + AUTHENTICATE APDU** (`00 88 00 81 ...`) — always works; used
   in `volte/` and `src/imsd/csim.go` (wwan-go `sim.Card`, §88).

On a sync failure: response `DC,AUTS` (CSIM: SW `98 62`); repeat the REGISTER with `auts=<AUTS>`
in Authorization (TS 33.203 §6.1.3, RFC 3310 §3.4), once. Code: `volte/reg/reg.go`,
`register()`, the `akaRes.SyncFailure()` branch. If the SIM rejected the AUTN on the MAC (the network does not know
the subscriber's key), there are no retries: this is an error-level log entry "the network is not authentic".

#### de-REGISTER and the known 500 error

`volte/reg` deregisters with a protected REGISTER with `expires=0` and the same Contact as at
registration, then removes the SAs. Before 0.11.1 the operator's SBC answered this with `500 Server Internal Error` and
`Warning: 399 … "AKA IP+Port conflict"` (the same response had previously been observed
with `Contact: *`; §75, §76, §79).

**Cause (§94):** the de-REGISTER `Security-Client` repeated the SPIs and ports of the current SAs, while
TS 24.229 §5.1.1.6.2 d requires new values in it for two new pairs of SAs. Per TS 33.203 §7.1
(rule 3), the P-CSCF aborts any REGISTER whose protected client port is already in its
SA table. Since 0.11.1 the de-REGISTER, like the refresh (below), offers new SPIs and a new port-c,
answers a 401 challenge with a full re-authentication, and only then removes the SAs. Not yet
verified live. If the 500 remains, it still does no harm: the registration in the network expires by itself (≤ 1 h),
the SAs are removed cleanly, and the log gets one WARN-level line on shutdown.

**No de-REGISTER over a lost PDN (§134).** A session of the service that ends because its PDN is
gone (`pdn-lost`, `helper-failed`) removes the SAs and the sockets and sends nothing: the address
the registration was bound to no longer exists, so the request reaches nobody, and the 5 s of
waiting for its answer would go into every recovery of the line. TS 24.229 (V19.7.0) permits
this: user-initiated de-registration is optional and uses the
SAs of the contact it removes (§5.1.1.6.1); after the loss of the bearer for SIP signalling the UE
brings it up again and performs a new initial registration (annex L.2.2.1B);
with that registration the S-CSCF drops the one before it, whose contact address is another
(§5.4.1.2.1 item 2, §5.4.1.2.2 item 4A, §5.4.2.1.2 NOTE 2), and a registration nobody replaces
expires (≤ 1 h). The service still de-registers when it stops and when a session ends with the
PDN alive (`rat-fallback`, `registration-failed`). Code: `reg.ErrAccessLost`, the cause that
cancels the context of `Run` (`volte/reg/run.go`), and `holdRegistration` in
`src/imsd/service.go`.

#### Refresh and re-REGISTER

- By default `expires=600000 s` in REGISTER (TS 24.229 §5.1.1.2.1); the network grants 3600 s;
  the refresh happens 600 s before expiry (§5.1.1.4.1), i.e. after 50 minutes.
- **Before 0.11.1 a refresh on the tested network never succeeded (§93, §94):** the repeated REGISTER
  went over the current SAs with the same `Security-Client`, the SBC answered
  `500 Server Internal Error` with `Warning: 399 … "AKA IP+Port conflict"`, and every
  50 minutes the daemon registered from scratch: the SAs, the protected connections and the listening port
  were torn down, and the ports and SPIs were new. A call in progress at that moment lost its Contact.
- **Rules (TS 33.203 V19.1.0, TS 24.229 V19.7.0; analysis in §94):**
  - Every REGISTER over the current SAs that does not answer a challenge (refresh,
    de-REGISTER) carries new spi-c, spi-s and port-c in `Security-Client`, with the same port-s
    (TS 24.229 §5.1.1.4.2 d, §5.1.1.5.3, §5.1.1.6.2 d; TS 33.203 §7.4.0). `Security-Verify` is
    the `Security-Server` of the last successful authentication. The SPIs differ from the SPIs of all
    existing SAs, inbound and outbound (TS 33.203 §7.1).
  - The P-CSCF aborts a REGISTER if the pair (UE IP, port-c from `Security-Client`) is already in its
    SA table (TS 33.203 §7.1, rule 3). On the tested network this is exactly the `500 … "AKA IP+Port conflict"`.
  - The UE's protected server port (port-s, which is also the Contact) does not change until all IMPUs
    are deregistered (TS 33.203 §7.1, note 10).
  - Network responses: 200 — registration refreshed without authentication, the SAs stay the same; 401 —
    re-authentication; 408, 500, 504 and 403 — initial registration
    (TS 24.229 §5.1.1.4.1); 423 — retry with `Min-Expires`.
  - Re-authentication (TS 33.203 §7.4.1a, TS 24.229 §5.1.1.5.1): the 401 arrives over the
    old SAs; the new SAs are built from the `Security-Server` in the 401 and our own offer; the answer
    to the challenge goes over the new SAs from the new port-c, with the same `Security-Client` as in the request
    that got the challenge. Until the 200 everything else goes over the old SAs, after the 200 over the new ones, except for transactions
    already in progress. The old SAs are deleted when the next message has arrived over the new ones and
    the transactions have finished, and in any case when they expire; the new SAs get the longer of the old SAs' lifetime
    and the registration lifetime plus 30 s. On a 403 or a response timeout the new SAs are deleted and
    work continues over the old ones. After the 200 the P-CSCF sends over the old SAs until it receives
    a message over the new ones (TS 33.203 §7.4.2a).
  - If the first REGISTER of the procedure was sent unprotected, the P-CSCF deletes the
    old SAs by itself after the 200 (§7.4.2a).
- **How `volte/reg` does it (since 0.11.1):**
  - `Refresh()` sends a protected REGISTER over the current SAs with a new offer. On 200
    the SAs stay the same; the log says `IMS registration refreshed`. On 401 — re-authentication,
    new SAs next to the old ones (`IMS registration refreshed with new security associations`).
    The old SAs live until the end of their lifetime (their registration lifetime plus 30 s; on the tested network about
    10.5 minutes after the refresh): the daemon cannot see over which SA a request to the server port arrived,
    so it does not delete them on the first message over the new ones. The connection from the old port-c stays
    open just as long: transactions already in progress get their responses over it. The reg-event subscription
    moves to the new SAs as is.
  - XFRM: the old and the new set share the server-port selectors (port-c of the tested P-CSCF
    is always 9950; inbound policies have no source port). The kernel cannot hold two policies with the same
    selector. During the transition the shared inbound policy accepts
    any MudiVoLTE ESP SA between the two addresses (a template without SPI but with the owner
    reqid); the shared outbound policy stays
    on the old SA and is switched to the new one after the 200 (a policy update). When
    one set is removed, the shared policies are bound to the SAs of the remaining set, which ends up exactly
    as `Install` would have set it up on its own (`ipsec.Set`: `InstallBeside`, `Supersede`,
    `RemoveBeside`; verified in the kernel, `TestKernelBeside`).
  - Fallback: initial registration with the same port-s. The listening port and the network's connections
    to it stay; the current SAs keep working until the 200 for the new ones and are removed after it. Only
    if this fails too — everything is torn down and the daemon registers from scratch with new ports. `Register()`
    does the same after losing the protected connection or on a NOTIFY from the network.
  - Registration procedures (`Register`, `Refresh`, `Deregister`, removal of the old SAs) run
    one at a time: the UE takes part in only one procedure at a time (§7.4.1a).
- **A call across re-registration.** The call's Contact (port-s) does not change, and the network's connections
  to it are not closed. Our in-dialog requests take `reg.Conn()` at the moment of sending —
  after the 200 this is the connection over the new SAs. **Limitation:** registration from scratch
  (the last fallback) changes port-s and closes the listening port: a call in progress
  stops receiving requests from the network (the other party's BYE, a session refresh). A call
  across re-registration has not been verified live.
- **What to look for in the daemon log:** once every 50 minutes `IMS registration refreshed` or
  `IMS registration refreshed with new security associations`. `re-REGISTER failed, registering
  afresh` with the Warning text — the network refused the refresh; then `registration at the same
  server port failed, starting from scratch` — the SBC did not accept the old port-s either. Capture analysis:
  `volte/tools/secagree.py` (ports, ESP SPIs and the Security-* headers of each SIP message).
- `423 Interval Too Brief`: retry with `Min-Expires` from the response, at any step (since 0.11.1).
- **The granted expiry.** The binding lasts for the `expires` of our Contact in the 200, else its
  `Expires` header, else what we asked for (RFC 3261 §10.2.4), read without overflow. More than we
  asked for counts as asked: a registrar may shorten the interval, not lengthen it (§10.3, step 7).
  A grant under a minute is refreshed as one of a minute, 30 s on, with the warning `registration
  granted for less than a minute`. An expiry of 0 or below means that the registrar has dropped the
  binding (`the registrar granted the binding no time`): the registration counts as failed, and the
  next one comes after the usual pause of 5 s growing to 5 minutes, not at once, whether the 200
  answered the first REGISTER or a refresh. Before, such a 200 armed the refresh at once, and every
  answer armed it again: REGISTER after REGISTER at the speed of the round trip (thousands a second
  on loopback), the kind of load an operator may bar a SIM for.
- SUBSCRIBE reg-event: after the 200 OK a `SUBSCRIBE` with `Event: reg` is sent to get notifications
  about the registration state (§88, `volte/reg/regevent.go`). The daemon handles the NOTIFYs.
  The tested network grants the subscription for 600000 s. Since 0.11.0 it is refreshed in its own dialog 600 s before
  expiry (TS 24.229 §5.1.1.3); a subscription that the network has forgotten is replaced by a new one, and the end
  of the replaced one does not lead to re-registration (§92). The expiry from `Subscription-State: active;expires=N`
  in a NOTIFY takes precedence over the expiry from the 200. `terminated` with `reason=timeout` or `deactivated` — a new
  subscription without re-registration; with any other reason and no terminated contact in the body —
  re-registration, as before. A failed SUBSCRIBE is retried after a pause of 1 to 30 minutes.
- **Network-initiated re-authentication (`shortened`, TS 24.229 §5.1.1.5A).** The S-CSCF asks for it
  with a reg-event NOTIFY in which our contact stays `active`, in an active registration, with
  `event="shortened"` and in `expires` the seconds left (RFC 3680 §5.4 requires the attribute then).
  The daemon takes that expiry and refreshes as for a binding granted for so long now (§5.1.1.4.1:
  at half time up to 1200 s, otherwise 600 s before the end); the S-CSCF challenges that REGISTER
  (§5.4.1.6), so it goes through the 401, the SIM and new SAs like any re-authentication. Log:
  `network asks for re-authentication: registration shortened`. Before, the event was ignored: the
  refresh stayed where the 200 had put it (50 minutes on), and the registration ran out with the
  shortened expiry.
  - A shortening only moves the refresh earlier. A full-state NOTIFY repeats the last event of a
    contact that has not changed since (§5.4.2.1.2), with less time left, and moves nothing.
  - A 200 to the refresh without a challenge times the binding anew and clears the shortening,
    unless the shortening arrived while that REGISTER was on its way: then it may be newer than the
    200 and stays.
  - Should the network shorten the binding again right after each refresh, the refreshes that
    shortenings make are kept a minute apart.
  - A `shortened` contact without a readable `expires` is ignored with a warning. Other events of an
    active contact change nothing; a terminated contact (`expired`, `deactivated`, `probation`,
    `unregistered`, `rejected`) means re-registration, as before.
  - Not seen on the tested network so far: re-authentication there came as a 401 to a refresh.


### 4.2 Incoming and outgoing calls

Verified live on the same network (§79, §81, §85, §86, §87, §88).

#### INVITE profile from the P-CSCF (live, §88)

From internal captures of live calls:

- The INVITE comes from P-CSCF:9950 to our `port-us` (= port-s as we announced it).
- `Supported: timer,100rel` (not `Require`).
- No preconditions (`preconditions`).
- `Record-Route`: P-CSCF:port-s (9900).
- `Session-Expires: 1800` without a `refresher` parameter, and `Min-SE: 600` (internal
  capture): the network asks for a session timer and leaves the choice of the refreshing
  side to us (see "Session timer" below).
- `Reason: Q.850;cause=16` in BYE on normal termination.
- Offer (SDP): AMR-WB PT=101 (`mode-set=0,1,2`) first, DTMF telephone-event/16000 PT=116.
  AMR-NB PT=102 (`mode-set=0,2,4,7`) appears in other calls (§86).

#### Incoming call (UAS)

```
P-CSCF           mudi-imsd              Linphone (LAN)
   │                  │                      │
   │── INVITE ───────>│                      │
   │<── 100 Trying ───│                      │
   │                  │── INVITE (fork) ────>│  (all bindings)
   │<── 180 Ringing ──│                      │
   │     (100rel if Require is present)      │
   │                  │<── 200 OK ───────────│  (first to answer)
   │                  │── CANCEL ───────────>│  (to the others)
   │<── 200 OK ───────│                      │
   │── ACK ──────────>│                      │
   │                  │  [RTP bridge]        │
   │<== RTP <==========│===================>  │
   │                  │                      │
   │── BYE ──────────>│── BYE ─────────────>│
   │<── 200 OK ────────│<── 200 OK ──────────│
```

**100rel/PRACK:** if the incoming INVITE has `Require: 100rel`, the 180 is sent reliably, with `RSeq`
and `Require: 100rel`, and retransmitted (T1, doubling up to T2) until the PRACK or until 64·T1.
The `200 OK` is retransmitted until the ACK; without an ACK within 64·T1 the call is ended with BYE (§88).

**Rejecting an incoming call:** always `6xx Decline/Busy/Not Acceptable` — this forbids
the proxy to try other branches (RFC 3261 §16.7). On `4xx/5xx` the SBC tries the CS contact
(`sip:<number>@192.0.2.42`), the MSC does CSFB to 3G, and this drops the IMS PDN (§87).
Codes in `src/imsd/callmgr.go`:
- No phones / nobody answered → `603 Decline`
- Line busy → `600 Busy Everywhere`
- Bad SDP → `606 Not Acceptable`
- Number not on the allow-list → `603 Decline`

#### Outgoing call (UAC)

Path over the IMS PDN with an AMR-WB + G.711 + DTMF offer. Headers:
- `Route: <sip:P-CSCF:port-s;lr>` + Service-Route from REGISTER.
- `P-Preferred-Service: urn:urn-7:3gpp-service.ims.icsi.mmtel`
- `P-Preferred-Identity: <first P-Associated-URI>` (§88 — the fix for 403).
- `Accept-Contact: *;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`
- `Supported: 100rel`

PRACK for reliable 18x (§88). ACK for 2xx (§88). CANCEL on hang-up before the 200 (§84).

On `488 Not Acceptable Here` from the gateway: the gateway requires AMR/AMR-WB (§88 — a G.711-only
offer is rejected by the MSX with `sipsl_CompareCodecListForCommon failed`). This needs a cross-compiled
binary with AMR-WB (cgo, opencore-amr + vo-amrwbenc).

#### re-INVITE and UPDATE

We answer with a mirrored SDP and keep the SDP version (§84, `onModify`). Both requests also refresh
the session timer.

#### Session timer (RFC 4028)

Since 0.11.0, `volte/call/session.go` (§92). One of the sides must refresh the interval from `Session-Expires`
before it ends, otherwise the other side hangs up.

| Case | What we do |
|--------|-----------|
| Incoming INVITE with `Session-Expires` without `refresher`, the network announced `Supported: timer` (as on the tested network) | 200 with `Session-Expires: N;refresher=uac` and `Require: timer`: the network refreshes |
| The incoming INVITE has `refresher=uas`, or the caller has no `Supported: timer` | We refresh: UPDATE without SDP at half the interval |
| Incoming INVITE without `Session-Expires` | No timer |
| Interval below 90 s, in an INVITE or UPDATE | `422 Session Interval Too Small` with `Min-SE: 90` |
| Our INVITE | `Supported: 100rel, timer` and `Session-Expires: 1800` without `refresher`; the role is taken from the 2xx (`uac` — us, `uas` — the network); a 2xx without `Session-Expires` means no timer |
| `422` to our INVITE | Retry with `Min-SE` and `Session-Expires` from the response, with the next CSeq, at most twice (TS 24.229 §5.1.2A.1.1) |
| The network should refresh but stays silent | At three quarters of the interval we first refresh ourselves (UPDATE, `refresher=uac`); BYE per RFC 4028 §10 only if that fails too |
| Response to our refresh | 2xx — the interval, the role and the peer's address from the response; without `Session-Expires` the timer is turned off; 422 — retry with `Min-SE`; 491 — retry after 2.1–4 s (our call) or within 2 s (incoming call); 481, 408 or 32 s of silence — BYE at once; other rejections and a dropped connection — up to three retries, then BYE 32 s before the end of the interval (for short intervals, a third of the interval before the end) |
| Our refresh | `Session-Expires` no lower than the largest `Min-SE` of this call (from 422 responses and from the network's requests), and `Min-SE` itself is sent along with it (RFC 4028 §7.4) |
| re-INVITE or UPDATE from the network during a call | We confirm the `Session-Expires` from the request in the 200 and restart the interval; without it the timer is turned off. The 200 to an UPDATE without SDP goes without SDP; the 200 to a re-INVITE without SDP carries our offer |
| UPDATE before the call is answered | Does not touch the timer: the timer belongs to the INVITE transaction |

On the live network only the negotiation has been verified (2026-11-06, §93): to `Session-Expires: 1800` without
`refresher` in an incoming INVITE we answered `Session-Expires: 1800;refresher=uac` and
`Require: timer`, the network accepted it, and the call went through. The refresh itself has not been verified: that needs a call
longer than 31 minutes, preferably with a capture. Before 0.11.0 we did not announce `timer`; how the network
behaved on long calls back then was not observed. What to look for: how the network refreshes the session
(UPDATE or re-INVITE), and whether its re-INVITE right after the answer contains `Session-Expires`
(§85, §87): without it the timer is turned off, as it was before 0.11.0. In the test call on 2026-11-06
(12 s) the network did not send a re-INVITE.

#### Stuck BYE (§85, §87)

If the TCP connection to the P-CSCF has closed (RST), the BYE does not reach the network. The daemon waits for the response
to the BYE for at most 12 s, then frees the line (otherwise the next INVITE gets `486 Busy`).
Code: `callmgr.go`, `Hangup` with a timeout.

#### Two contacts in the S-CSCF (§87)

The subscriber has two contacts registered in parallel in the S-CSCF:
- Our host contact: `sip:<IMPU>@<IMS-IP>:<port>`
- The MSC's CS contact: `sip:<number>@192.0.2.42` (CS domain registration)

On `4xx/5xx` the network tries the second one. On `6xx` it does not.

#### Pixel wakes up late (§87, no fix — Android behavior)

The INVITE arrives 3–4 times; Linphone on Android answers only the retransmission that comes after its own
re-registration (a delay of 3.6–7.6 s from the first INVITE). The first INVITEs are lost in the socket.
The daemon sends `100 Trying` at once, and `180 Ringing` only when the phone has answered.

#### Malformed messages from the network

One bad message costs at most its connection, never the daemon (`volte/sipnet`):

- A `Content-Length` beyond the message limit (256 KiB) is a framing error: the connection is
  closed with the warning `sip stream error, closing`. Before, a value near the integer limit
  overflowed the length check, and the panic on the read loop took the whole daemon down.
- A request without one of the header fields that every request carries (`Via`, `From`, `To`,
  `Call-ID`, `CSeq`; RFC 3261 §8.1.1) gets `400 Missing <name> header field` (§21.4.1) and goes no
  further; without `Via` no response could be routed (§18.2.2), so such a request is dropped, and so
  is an ACK, which takes no response. Before, an INVITE without `Call-ID` crashed the daemon in the
  call manager.
- A panic while one message is parsed or handled is logged as an error with its stack (`panic while
  handling a SIP message, message dropped`), the message is dropped, and the connection goes on with
  the next one. A panic elsewhere on the read loop closes that connection (`panic on the SIP read
  loop, closing the connection`): the position in the stream is then unknown. A handler that holds a
  lock of its own at the moment of a panic may leave it held; the guard keeps the line up, the
  error in the log is still a bug to fix.


### 4.3 Media (RTP, AMR-WB, G.722, G.711, DTMF)

#### RTP (RFC 3550)

- The daemon's RTP ports: dynamic (not fixed).
- **SO_BINDTODEVICE to the IMS interface** (§88, bug 1): the network-side RTP socket is bound
  to `rmnet_dataN` explicitly. Without this, packets leave via the default route
  (internet PDN `rmnet_data0`) — the network does not hear us; incoming RTP from the SBC is dropped by fw4
  as a "new" flow.
- Code: `netstack.go`, `SO_BINDTODEVICE` in Go via `syscall.SetsockoptString`.

#### AMR-WB (RFC 4867)

- PT=101 or PT=111 (the tested network has used both; check `rtpmap` in the SDP).
- **Bandwidth-efficient mode** (the tested network's default, §88). Octet-aligned if `fmtp` says so.
- Encoding mode: the highest mode allowed by the peer's `mode-set` in the SDP (the tested network's
  `mode-set=0,1,2` → mode 2, 12.65 kbit/s); without `mode-set` — mode 8 (23.85 kbit/s).
  Every packet has CMR=15 (no preference).
- Codec: a cgo wrapper around `opencore-amrwb` (decoding) and `vo-amrwbenc` (encoding),
  statically linked. Static build: `volte/media/amrwb`, tag `amrwb_static`.
  Without AMR-WB — G.711 only (an offer with G.711 only is rejected by some of the operator's gateways).

#### G.722 (ITU-T G.722)

- Used between mudi-imsd and Linphone on the LAN (§85, §87, §90).
- Implementation: `volte/media/g722` — written from the text of ITU-T G.722 (11/88); it matches
  ffmpeg 7.1 bit for bit (§90).
- Phone↔phone calls use it on both legs (§90). The bridge has no pass-through: it decodes to PCM and encodes again.

#### G.711 µ-law (PCMU) and A-law (PCMA)

- PT=0 (PCMU), PT=8 (PCMA).
- Seen in calls with Georgian phone numbers (§86: AMR-NB + PCMU), and with a G.711-only
  offer.
- Pure Go in `volte/media`.
- Resampling 8↔16 kHz for the AMR-WB (16 kHz) ↔ PCMU (8 kHz) bridge: Hamming-window FIR filter,
  33 taps, history kept between frames (`src/imsd/lan_codec.go`).

#### DTMF (RFC 4733)

- PT=116 (telephone-event/16000) for AMR-WB sessions.
- Receiving: one digit per event, on the first end packet.
- Implementation in `volte/media`.

#### Jitter buffer (SIP bridge, §84)

- Pre-buffer: 3 frames (60 ms, `jitter_frames`), ceiling 8 frames (160 ms): older frames are dropped.
- Loss concealment: for up to 3 frames the last frame is repeated with fading (1/2, 1/4, 1/8),
  then silence.
- A 20 ms ticker for each side.


### 4.4 SMS over IP

Implementation: `volte/sms/service.go`. Partly verified (§85, §88; there has been no live SMS over IMS —
the operator delivered SMS via CS/SGs in both test sessions, §88).

#### MT SMS (incoming)

```
IP-SM-GW          mudi-imsd
      │                 │
      │── MESSAGE ─────>│  (Content-Type: application/vnd.3gpp.sms)
      │<── 200 OK ───────│
      │                 │  [parse RP-DATA → SMS-DELIVER → OnMessage()]
      │<── MESSAGE ─────│  (RP-ACK in the body, In-Reply-To: Call-ID of the incoming MESSAGE)
      │── 200 OK ───────>│
```

On a storage error: `RP-Error Cause=22` (Memory Exceeded) — the network keeps the SMS and
retries later (§88, the fix for "SMS get lost" from §83).

#### MO SMS (outgoing)

```
mudi-imsd          SMSC (PSI from SIM EF_SMSP)
      │                      │
      │── MESSAGE ───────────>│  (RP-DATA with SMS-SUBMIT in the body)
      │<── 200 OK + RP-ACK ───│  (or RP-Error)
```

- SMSC URI: `sip:<+E164>@<domain>;user=phone`; the address is taken from SIM EF_SMSP via
  `wwan-go sim.Card` (§88). If it cannot be read from the SIM — from the config.
- `Accept-Contact: *;+g.3gpp.smsip` in the MESSAGE header.

#### Registration flags for SMS

The Contact in REGISTER carries `+g.3gpp.smsip` (TS 24.341 §5.3.2.2).
The IP-SM-GW is allowed to deliver MT SMS to our registration. Why the operator does not use
this path is an open question (§88: an IP-SM-GW subscription or a special
HLR profile may be required).

SMS that arrive via CS are intercepted by the GL firmware through `sms-forward` (§87).

### 4.5 SIP bridge for LAN phones (Mudi Wi-Fi)

Implementation: `src/imsd/lan_server.go`, `lan_registrar.go`, `lan_sdp.go`, `lan_codec.go`,
`lan_rtp.go`, `ims_leg.go`, `bridge.go`, `callmgr.go` (§84).
Verified live with Linphone on Android + iOS (§85, §86, §87, §90).

#### LAN registrar (SIP UAS)

- Address: `<LAN-IP>:5060` (UDP + TCP) and `<LAN-IP>:5061` (TLS), by default `br-lan` 192.168.8.1. With
  `option plain '0'` only TLS is open.
- TCP and TLS connections (`lan_listener.go`): at most 128 open and 8 from one IP, the last 32 of the 128 only
  for IPs a phone has signed in from; a connection over a limit is reset as soon as it is accepted. A connection
  is closed if no request on it passes digest authentication within 30 s. One a phone has signed in on has no
  idle timeout: Linphone on iOS keeps it silent in the background and is woken by a push; Go's TCP keep-alive
  (15 s idle, 9 probes 15 s apart) ends it once the phone is gone. A temporary `accept` error (EMFILE, ENFILE,
  ECONNABORTED) is retried after 5 ms, doubling up to 1 s; if sipgo's accept loop ends anyway, the error is
  logged at Error level and the port is listened on again. Refusals and closings are logged at most once a
  minute each, with a count.
- Digest authentication: MD5, `qop=auth`; 401 to REGISTER, 407 to other requests.
  Every challenge gets a nonce of its own: an HMAC bound to the client's IP and valid for an hour, so an intercepted
  Authorization from another address does not work. Under one nonce `nc` must grow and `uri` must name the target of
  the request: the same header sent again gets a new challenge with `stale=true` and does not count as a failure.
- An IP is blocked for 10 minutes after 10 failures in a row within 5 minutes (§84). Only a response to a nonce issued to that IP counts; anything else gets a new challenge. Blind UDP source spoofing cannot lock a phone out. An attacker who can capture the phone's plain SIP challenge can still use its nonce; disable plain SIP to avoid that exposure.
- re-INVITE, UPDATE and SIP INFO (tone dialing) are acted on only inside a dialog of the current call and only from
  that dialog's phone (its whole address over UDP, its host over TCP and TLS); anything else gets `481`. INFO also needs
  an authorized phone, and the SRTP keys of a re-offer travel only inside TLS.
- **Foreign nonce (§90):** after a daemon restart Linphone comes with an old nonce →
  the response is `401 stale=true`, and it does not count as a failure.
- **`+sip.instance` (RFC 5626, §90):** one account — one binding. On a REGISTER
  with the same `+sip.instance` but a different address, the old binding is removed.
  Linphone Android (SDK 5.5.37) and iOS (SDK 5.5.39) send `+sip.instance`.

#### Incoming call fork

INVITE from the network → B2BUA → INVITE to all live bindings of all phones (fork; an internal
call: the bindings of the called phone). The first `200` takes the call, the others → CANCEL.
Race: ACK+BYE to a late `200`. A binding over TCP or TLS without its connection is not dialled.

A phone that disappears without a BYE does not hold the line for ever: after 30 s without RTP
from it (a call on hold, DTX or a muted microphone can all stop the media) the daemon probes
the phone with an in-dialog OPTIONS. Any answer except `481` keeps the call; silence ends it —
BYE to the other leg, the line freed.

If there is nobody to ring (no live binding and no phone to push): `603 Decline` immediately
(§90 — before that it was 480 preceded by 183/180, which confused T-ADS).

#### Push to sleeping phones and late forking (§104, §109, §110, §114)

Implementation: `src/imsd/flexiapi.go`, `ringer.go`, `lan_push.go`. An explicit sign-out
(REGISTER with `Expires: 0` or `Contact: *`) forgets the device's saved push parameters as
well; a REGISTER with `pn-*` parameters brings them back.

Linphone on iOS stops its core in the background (`CoreContext.onEnterBackground` → `Core.stop()`):
the connection closes, the binding on the server stays until it expires. Only a VoIP push
(PushKit) from the app's owner wakes it, and iOS requires the app to show a call (CallKit) at
once. For the App Store Linphone the owner is Belledonne, so the push goes through their
FlexiAPI (flexisip-account-manager) at `subscribe.linphone.org`:

- Push parameters (RFC 8599) come in the Contact URI of every REGISTER: Linphone iOS sends
  `pn-provider=apns`, `pn-param=<TEAM>.org.linphone.phone.voip&remote`,
  `pn-prid=<voip-token>:voip&<remote-token>:remote`. They are kept per `+sip.instance` in
  `/etc/mudi-volte/push.json` (written only on change).
- `POST /api/push_notification`, JSON `pn_provider`, `pn_param` (`<TEAM>.org.linphone.phone.voip`),
  `pn_prid` (the VoIP token), `type=call` (FlexiAPI → `flexisip_pusher --apple-push-type PushKit`),
  `call_id`; headers `content-type`/`accept: application/json` and `From: sip:<login>@sip.linphone.org`.
  Unsigned, it answers `401` with two `WWW-Authenticate: Digest` challenges (MD5, SHA-256,
  `qop=auth`, `opaque`); the signed request (RFC 7616, SHA-256 preferred) gets `200`. FlexiAPI
  validation: `pn_param` `^[\w\.]+$`, `pn_prid` `^[\w\-:]+$`, `call_id` `^[\w\-~@.]+$`; a failed
  pusher → `503`. A user API key does not fit: it is bound to the IP that made it.
- The call: live bindings get the INVITE at once; each device without one gets a push with a
  Call-ID of the daemon (`mv-` + 24 hex) and counts as ringing until the ring time ends. Its
  next REGISTER (Linphone after the push: `Core::pushNotificationReceived` → `healNetworkConnections`,
  a 20 s background task) is answered `200`, and right after it the INVITE with that Call-ID goes
  into the new connection; Linphone matches it with the CallKit call of the push. No REGISTER within
  3 s → a second push with the same Call-ID: if iOS had unloaded Linphone, the first push only
  starts the app (`EarlyPushkitDelegate`: a placeholder call for ~4 s, no core, no REGISTER).
- A pushed device that registers after the ringing is over (caller gone, answered elsewhere)
  gets the INVITE and a CANCEL right after its first provisional response, within 25 s; Linphone
  then closes the call as missed. Any device that registers while a call rings is forked too.
- Measured (Linphone iOS, LAN): FlexiAPI ≈ 1 s; REGISTER 0.7–2.1 s after FlexiAPI answered; a call
  from the network rang the locked iPhone 1.8 s after it reached the router, a call from another
  phone 3.1 s; the woken Linphone keeps its connection ≈ 18 s.
- Only the device token and the made-up Call-ID leave the router (to Belledonne, then Apple or Google).
- Android Linphone sends `pn-provider=fcm`, `pn-param=<Firebase project number>`,
  `pn-prid=<FCM registration token>` (the token holds a `:`); FlexiAPI takes them as they are and
  its pusher sends a high-priority FCM data message (live check: `200` in 0.85 s). Linphone Android
  keeps a foreground service (`CoreKeepAliveThirdPartyAccountsService`, enabled by the QR code with
  `keep_service_alive=1`) and its connection, so it is pushed only when the system or a battery
  saver has stopped it. Linphone Android enables push by default only for `push_notification_domains`
  (`sip.linphone.org`) and strips it from other accounts once, when upgrading from a version before
  6.0.4; accounts set up later keep `pn-*` in their Contact.

#### SMS to the phones (§100, §119)

Implementation: `src/imsd/smsbridge.go`, `smslist.go`, `lan_message.go`.

An SMS from smsd's spool goes to every phone account as an out-of-dialog MESSAGE from the sender's
number. Only the files of SIM slot 1 count (`Slot: 1`, or no `Slot` line): smsd stores what a
second SIM receives in the same directory, under `Slot: 2` (§118).

- A locked Android phone answers late: the `200` came 16, 12 and 1 s after the MESSAGE (Linphone's
  keep-alive ran every 31 s meanwhile), past the 10 s the daemon waits (`msgTimeout`).
- Every attempt at one SMS carries the same Call-ID, `sms-<smsKey>@<LAN-IP>` (a piece of a long
  text over UDP: `sms-<smsKey>.<n>@<LAN-IP>`). liblinphone files an out-of-dialog MESSAGE under its
  Call-ID (`ChatRoom::getMessageFromSal`), and `ChatMessagePrivate::receive` answers `200` to one
  it already has without showing it. Live: three attempts at a locked Pixel, one message on the
  phone.
- A `200` that comes after the wait has no transaction left. sipgo hands it to the
  unhandled-response handler (`lateResponse`), and it still counts as delivered: no further
  attempt goes to that phone.
- Without any answer the attempts repeat after 1, 2, 4, 8 and then every 15 minutes while the
  phone stays registered. A phone that is away gets the SMS when it registers again, within
  7 days.

A message from one phone to another, by login or short number (`textToPhone`), waits for the
addressee inside the sender's own transaction:

- The wait is 30 s (`msgRelayWait`). A phone asleep answers when it next wakes up, and the sender
  gives up at Timer F, 64·T1 = 32 s in belle-sip and sipgo alike. A provisional response does not
  move Timer F.
- `200` as soon as one device has answered `2xx`, whatever the others do. When no device took the
  text and at least one may have it: `202 Accepted` (RFC 3428 §7), which liblinphone shows as
  delivered, like `200` (`SalMessageOp::processResponseEventCb`). `480` only when the text cannot
  have arrived: no device connected, or all of them refused it. Nothing is queued for
  phone-to-phone messages: a phone that has really gone away also gets `202`, and misses the text.
- `100 Trying` after 3.5 s without an answer (RFC 4320 §4.1: the sender's Timer E has reached T2).
- Call-ID `msg-<hash>@<LAN-IP>`, from the sender's login, the addressee, the sender's Call-ID and
  the text, so that the same request heard twice is one message for the addressee. A text Linphone
  sends again has a new Call-ID and is a new message for the daemon.

#### RTP bridge (network ↔ phone)

```
Network (IMS PDN)       mudi-imsd              Phone (LAN)
     │                      │                       │
     │  AMR-WB/AMR/PCMU     │  G.722/PCMU/PCMA     │
     │<=================== PCM 16k/8k =============>│
```

- LAN RTP ports: 40000–40199, only from the phone's IP in the SDP, symmetric RTP.
- Network leg: `SO_BINDTODEVICE` to the IMS interface.
- Every call goes through PCM, G.722↔G.722 inside the LAN too (§90): the bridge has no pass-through.

#### QR code for Linphone setup (§90)

The daemon serves a remote provisioning link:
```
http://<LAN-IP>:8060/p/<token>
```
Token: the first 96 bits (24 hex characters) of an HMAC-SHA256 of the phone's login and password with a random
key from `/etc/mudi-volte/provision.key`. If the password is changed or the phone is deleted, the link
stops working. The link has no expiry.
The URL is served over `http` on the LAN — Linphone accepts it (ATS/cleartext rules do not apply to liblinphone).

XML format: `linphonerc` (wiki.linphone.org "Remote Provisioning"). It contains the account,
`transient_provisioning=1` (applied once) and the codecs (`audio_codec_N`). With encryption on,
the account goes over TLS and `[sip]` gets `media_encryption=srtp`, `media_encryption_mandatory=1`,
`verify_server_certs=0`, `verify_server_cn=0` (liblinphone: `coreapi/linphonecore.c`,
`certificates_config_read`; only a CA file path and a subject regexp, no pinning).

#### SRTP towards the phones

SDES keys (RFC 4568) in the SDP, so only over TLS; SRTP per RFC 3711 (`volte/srtp`, AES-CM with
HMAC-SHA1, 128- and 256-bit keys, tags of 80 and 32 bits; RFC 3711 Appendix B and the libsrtp
reference packets are the tests). Linphone with `media_encryption_mandatory=1` accepts only
`RTP/SAVP` offers (liblinphone `offeranswer.cpp`, `areProtoCompatibles`: SAVP with SAVP), so our
offers to phones on TLS are `RTP/SAVP`; its default suites (`srtp_crypto_suites`) are
`AEAD_AES_128_GCM, AES_CM_128_HMAC_SHA1_80, AEAD_AES_256_GCM, AES_256_CM_HMAC_SHA1_80`, and we take
the first AES-CM one. In-dialog requests to a phone on TLS go to the source address of its INVITE
or answer (sipgo `DialogUA.RewriteContact`): the phone listens on no port.

QR code on the Mudi screen: `/dev/fb0` RGB565, with `gl_screen` stopped (§90).

#### SIP bridge limitations

- SRTP only with SDES keys over TLS: no DTLS-SRTP, no ZRTP, no SRTCP. Linphone does not check the
  router's self-signed certificate, so TLS protects against listening, not against an active
  impostor on the Wi-Fi.
- No IPv6.
- Early media from the network is not passed to the phone (§84).
- iOS: Linphone stops when the app goes to the background (~5 s, §85). Incoming calls reach it
  through a push (above), with a linphone.org account set; without one, only while the app is open.
  An iPhone on UDP is not pushed while its binding lasts: the server cannot tell it from a live one.
  SMS to a sleeping iPhone wait until Linphone registers.
- A second call → `486 Busy Here` (one line per SIM, §84).
- UDP limit of 1300 bytes: the response to REGISTER includes only the phone's own Contact, plus other contacts while
  the response stays ≤1300 bytes (TCP has no limit). RFC 3261 §10.3 says `SHOULD`. Otherwise Linphone does not
  get the 200 OK over UDP and retransmits per Timer E (§90).

---

## 5. Known pitfalls

| # | Problem | Symptom | Cause | Fix / Workaround | § |
|---|---------|---------|---------|--------------|---|
| **G1** | SUB2 trap in the GL AT proxy | QCFG ims → `0,0` instead of `1,1`/`2,0`; settings are not written | GL's background poller switches the AT context between slots | Every line starts with `AT+QUIMSUB=1;` and goes through the proxy with `sub_id:1`; for QIMSCFG — a separate `QUIMSUB=1` + the command | §69, §117 |
| **G2** | QEFSSYNC before CFUN=1,1 | The `ims` and `voice_disable` settings roll back after a reboot | The CFUN=1,1 hard reset does not save NV without `QEFSSYNC=0` | Always `AT+QEFSSYNC=0` before `CFUN=1,1` | §71 |
| **G3** | The first P-CSCF (192.0.2.20) is non-compliant | Incoming requests are not delivered; NOTIFY/INVITE silently dropped | The P-CSCF connects to port-s from an unpredictable source port | `LooseInboundSrcPort=true` in ipsec.Set; put 192.0.2.28 first in the config | §82, §81 |
| **G4** | conntrack generic 200 s | Incoming INVITE/NOTIFY is rejected with ICMP port-unreachable after ~200 s of silence | The IMS interface is not in an fw4 zone; the conntrack entry for generic proto 50 expires | Rule `/usr/share/nftables.d/chain-pre/input/20-mudi-volte.nft` | §87 |
| **G5** | 4xx/5xx → CSFB → IMS PDN drop | A rejected incoming call → the operator tries CS → the modem goes to 3G → the PDN dies | T-ADS tries the CS contact on a non-fatal rejection code | Reject only with `6xx` (`603 Decline`, `600 Busy`, `606 Not Acceptable`) | §87 |
| **G6** | Repeated REGISTER and de-REGISTER → `500 AKA IP+Port conflict` | Registration refresh fails, and the daemon registers from scratch every 50 minutes; deregistration fails | `Security-Client` repeated the SPIs and port-c of the current SAs; the P-CSCF rejects a REGISTER with a port-c that is already in use (TS 33.203 §7.1, rule 3) | Since 0.11.1 every REGISTER over the current SAs has new SPIs and a new port-c, with the same port-s (4.1, "Refresh and re-REGISTER"); not verified live | §75, §79, §93, §94 |
| **G7** | The IMS PDN dies while the daemon is running | `503 bind: cannot assign requested address`; the daemon believes it is registered | The PDN went down (CGACT 2,0), and the daemon did not monitor it; the IMS address disappeared from the interface | PDN monitoring in `service.go` (§89): `DSI_EVT_NET_NO_NET` → bring the PDN up | §81, §87, §85 |
| **G8** | The modem moves to UTRAN after an IMS rejection | The IMS PDN dies, the following calls go to voicemail | T-ADS/VLR tries CS on CSFB; the modem goes to 3G, and this breaks the IMS PDN | `voice_domain=1` + `ue_usage=1` (data-centric); on a move to 3G — `CFUN 4→1` + bring the PDN up again + re-register | §87, §90 |
| **G9** | TAC +6 vs +10 in QENG | PANI contains EARFCN instead of TAC | After `"LTE"` in QENG, TAC is the tenth field, not the sixth | Parse from the `"LTE"` token and count 10 fields | §85 |
| **G10** | Multi-line QENG on EN-DC | The parser fails or picks the wrong fields | On LTE+NR5G-NSA the modem answers with 3 `+QENG:` lines | Collect the fields of all `+QENG:` lines; parse by token search | §85 |
| **G11** | Duplicate bindings of one phone | A call is forked to a dead address; `devices=2` for a single iPhone | The binding key is login+host:port; when the port changes, the old binding is not removed until it expires | `+sip.instance` (RFC 5626): on a registration with the same instance → remove the old binding | §90 |
| **G12** | 200 OK to REGISTER > 1300 bytes over UDP | The iPhone retransmits REGISTER per Timer E and gets no response | sipgo refuses to send a UDP datagram ≥ MTU | Put only the phone's own Contact in the 200 OK, and other contacts only while the size stays ≤ 1300 bytes | §90 |
| **G13** | RTP for outgoing calls via rmnet_data0 | The network does not hear the UE; incoming RTP from the SBC is blocked by fw4 | Without `SO_BINDTODEVICE`, RTP leaves via the default route (internet PDN) | `SO_BINDTODEVICE` to the IMS interface for all media sockets | §88 |
| **G14** | The LAN registrar is memory-only | After a daemon restart the phones "disappeared"; an incoming call → `480` | The bindings were kept only in RAM | `phones.json` — persistent storage of the bindings (§89) | §87, §89 |
| **G15** | REGISTER over unprotected TCP (sec-agree rekey) | The first REGISTER did not go over ESP; the SBC issued new SPIs (401#2) | The second REGISTER (with Authorization) went out from the unprotected port because the SAs were not waited for | Rekey: the SBC may send a second 401 with new SPIs; handle it correctly (RFC 3329) | §78 |
| **G16** | The SBC closes unprotected TCP after ~80 s | A WARN in the log about an RST on the auxiliary connection | Normal SBC behavior | An informational WARN only; does not affect operation | §77 |
| **G17** | `firstboot -y` does nothing on the E5800 | After a "reset" the router boots with all its settings, packages and the old password | `jffs2reset` looks for a `rootfs_data` partition; the overlay here is the `systemrw` partition | Factory reset only with GL's own means (Reset Firmware → `AT+QCFG="ResetFactory"`); check the result by the contents of `/overlay/rootfs-upper`, not by the fact that the router rebooted | §91 |

---

## 6. References

Standards actually used in the project (as mentioned in the code and the log):

### IETF RFC

| RFC | Title | Where used |
|-----|----------|----------------|
| RFC 3261 | SIP: Session Initiation Protocol | Base protocol; §10.3 on the SHOULD for the contact list |
| RFC 3262 | Reliability of Provisional Responses (100rel/PRACK) | `inbound.go`: reliable delivery of 180 Ringing |
| RFC 3310 | HTTP Digest Authentication Using AKA | AKA authentication; the `AKAv1-MD5` algorithm |
| RFC 3311 | UPDATE Method | re-INVITE / UPDATE in `call/inbound.go` |
| RFC 3329 | Security Mechanism Agreement for SIP (sec-agree) | Security-Client / Security-Server; rekey |
| RFC 3680 | SIP Event Package for Registrations (reg-event) | Registration SUBSCRIBE / NOTIFY |
| RFC 4303 | IP Encapsulating Security Payload (ESP) | IPsec SA; §2.1 on the reserved SPIs < 256 |
| RFC 3550 | RTP: A Transport Protocol for Real-Time Applications | RTP bridge, marker after a gap in the stream |
| RFC 4028 | Session Timers in SIP | `volte/call/session.go`: both roles, refresh via UPDATE; 4.2, session timer |
| RFC 4733 | RTP Payload for DTMF Digits and Telephony Tones | telephone-event, PT=116 |
| RFC 4867 | RTP Payload Format and File Storage Format for AMR/AMR-WB | AMR-WB bandwidth-efficient; §88, §63 |
| RFC 5626 | Managing Client-Initiated Connections in SIP (+sip.instance) | Bindings with an instance UUID |
| RFC 7254 | A Uniform Resource Name Namespace for the GSMA and the IMEI | `urn:gsma:imei:...` in Contact |
| RFC 7616 / RFC 2617 | HTTP Digest Access Authentication | Authorization of LAN phones (MD5, `qop=auth`) |

### 3GPP TS

| TS | Title | Where used |
|----|----------|----------------|
| TS 23.003 §13 | Numbering, addressing and identification — IMPU/IMPI from IMSI | Deriving the identities without an ISIM |
| TS 24.229 | IP multimedia call control protocol based on SIP and SDP | Registration §5.1.1 (refresh, re-authentication and de-REGISTER §5.1.1.4–§5.1.1.6 checked against V19.7.0, §94); no de-REGISTER over a lost PDN: §5.1.1.6.1, annex L.2.2.1B, §5.4.1.2.1, §5.4.1.2.2, §5.4.2.1.2 (§134); PANI §7.2A.4, P-Preferred-Identity §5.1.2A.1.1, `Expires` §5.1.1.2.1 |
| TS 24.341 | Support of SMS over IP | SMS MESSAGE; §5.3.2.2 `+g.3gpp.smsip`; §5.3.2.4 RP-ACK to the SMSC; §5.3.1.2 MO |
| TS 24.011 | Point-to-Point SMS support on mobile radio interface | RP-DATA / RP-ACK / RP-ERROR, causes (table 8.4) |
| TS 23.040 | Technical realization of SMS | TPDU: SMS-DELIVER / SMS-SUBMIT, GSM-7, UCS-2, concatenation |
| TS 27.007 §10.1.23 | AT+CGCONTRDP | Response fields: positions of DNS and P-CSCF |
| TS 33.203 | 3G Security — Access security for IP-based services | §7: IPsec ESP transport, IK/CK, algorithms; §7.1: choice of SPIs and ports, P-CSCF checks; §7.4: re-authentication and SA change (checked against V19.1.0, §94); §6.1.3: SQN resynchronization |

### Quectel

| Document | Where used |
|----------|----------------|
| External VoLTE Stack Application Note V1.0 (RG520N/RM5x0N, 2023-12-21) | Procedure QCFG ims,2 + QEFSSYNC + dsi + CGCONTRDP, QIMSCFG; §68, §71 |
| AT Commands Manual RG520N/RG50xQ | QMAP MPDN, QCFG; §65, §68 |
| AT Commands Manual RG65xE/RG650V/RM550V/RM551E V1.0 (Released, 2024-07-11) | Values of `voice_domain` and `ue_usage_setting`, `QEFSSYNC`, NV write delay; cross-check in 2.9 |

### ITU-T

| Standard | Where used |
|----------|----------------|
| ITU-T G.722 (11/88) | Implementation in `volte/media/g722`; §90 |

---

*Compiled on 2026-11-04 from the internal engineering log (§62–§91) and the repository code; on 2026-11-05 checked
against the 0.9.14 code and corrected; on 2026-11-06 the cross-check against the RG650V AT manual (2.9), the session timer and the subscription refresh (4.1, 4.2) were added. The sections about the live network describe one European operator;
with another operator, the details of sec-agree, the P-CSCF and SMS delivery may differ.*
