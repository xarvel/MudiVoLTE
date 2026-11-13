# Security

MudiVoLTE puts a phone line on a home router: a flaw in it can let someone on
the Wi-Fi listen to calls, read SMS or place calls through the SIM at the
owner's expense. Reports of such flaws are welcome and are handled in private
first.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: the **Security** tab of
<https://github.com/xarvel/MudiVoLTE>, "Report a vulnerability". If that
form is not available, open an issue that says only that you have a security
report and how to reach you; keep the details out of the issue.

Please include the version (`mudi-volte version`), the firmware of the router,
what an attacker needs (a place on the Wi-Fi, a phone account, the admin
password of the router...) and how to reproduce it. Logs and captures carry
phone numbers, the IMSI and push tokens: mask them before sending.

MudiVoLTE is a personal project without a security team. You should hear back
within a week; fixes go out as a new release and the report is credited there
unless you prefer not to be named.

## What is in scope

- The SIP server, the RTP legs and the QR-code provisioning on the LAN side
  (`src/imsd/lan_*.go`, `provision.go`): anything a device on the router's
  network can do beyond what its phone account allows, such as listening to
  or hijacking a call, placing calls as another phone, reading SMS, or
  signing a phone in without its QR code.
- The pushes through subscribe.linphone.org (`flexiapi.go`): anything that
  leaks more than the push token and a random call ID.
- The web pages and their RPC modules (`package/files/www/`,
  `package/files/usr/lib/oui-httpd/rpc/`), the management script and the
  installer: anything a visitor of the admin panel or a package upgrade can
  do that the router's admin did not ask for.
- The IMS client (`volte/`): anything a hostile P-CSCF or a rogue cell can do
  to the router beyond refusing service.

## What the project does not protect against

The README's "Encryption" section describes the threat model. In short:

- Someone who already has the router's admin password or an SSH login owns
  the phone line.
- Linphone cannot pin the router's self-signed certificate, so a host on the
  Wi-Fi that actively poses as the router is not detected; the QR-code link
  itself is plain HTTP.
- Phones set up by hand on UDP talk and sign in the clear; the option
  `plain '0'` closes those ports once every phone is on TLS.
- Calls to ordinary numbers are never encrypted end to end, and emergency
  calls are not guaranteed to work.

## Supported versions

Only the latest release gets fixes. The release page lists the version and
the checksum of every package.
