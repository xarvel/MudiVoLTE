#!/bin/sh
# One push to a phone through Belledonne's FlexiAPI (subscribe.linphone.org),
# the way the daemon is to wake Linphone on an iPhone for a call (FINDINGS
# §104): POST /api/push_notification, type=call, a made-up Call-ID, signed
# with a linphone.org account (HTTP Digest with From: sip:<login>@<domain>).
# The phone's push parameters come from the router: /etc/mudi-volte/push.json,
# saved by the daemon from the phone's REGISTER. The login and password are
# asked here and reach curl only through its stdin: not the command line, the
# shell history or a file.
#   scripts/flexiapi-push-test.sh [phone]          (default: iphone)
# Expected on the iPhone: an incoming call that closes by itself after a few
# seconds, because no INVITE with that Call-ID follows.
set -eu
phone=${1:-iphone}
router=${MUDI_ROUTER:-root@192.168.8.1}
key=${MUDI_SSH_KEY:-$HOME/.ssh/mudi_ed25519}
api=${FLEXIAPI_URL:-https://subscribe.linphone.org/api}
domain=${FLEXIAPI_DOMAIN:-sip.linphone.org}

if ! params=$(ssh -i "$key" -o BatchMode=yes -o ConnectTimeout=8 "$router" 'cat /etc/mudi-volte/push.json 2>/dev/null || echo []'); then
	echo "Cannot read the push parameters from the router ($router, key $key)." >&2
	echo "Run the script as the user that has this key and the router in known_hosts: sudo -u <user> -H sh $0" >&2
	exit 1
fi

# Linphone on iOS sends pn-param TEAM.org.linphone.phone.voip&remote and
# pn-prid VOIPTOKEN:voip&REMOTETOKEN:remote; a call needs the VoIP (PushKit)
# token and the .voip topic.
body=$(printf '%s' "$params" | python3 -I -c '
import json, secrets, sys, urllib.parse
phone = sys.argv[1]
devs = [p for p in json.load(sys.stdin) if p.get("user") == phone]
if not devs:
    sys.exit("No push parameters for %r: open Linphone on it so that it signs in again." % phone)
p = max(devs, key=lambda d: d.get("updated", ""))
prov = p["provider"]
param = urllib.parse.unquote(p.get("param", ""))
prid = urllib.parse.unquote(p["prid"])
if prov in ("apns", "apns.dev"):
    prefix, _, services = param.rpartition(".")
    tokens = {}
    for part in prid.split("&"):
        tok, _, svc = part.partition(":")
        tokens[svc or services] = tok
    if "voip" not in tokens and "voip" not in services.split("&"):
        sys.exit("The phone sent no VoIP token (pn-param %r): Linphone cannot be woken for calls." % param)
    param, prid = prefix + ".voip", tokens.get("voip", prid)
print(json.dumps({"pn_provider": prov, "pn_param": param, "pn_prid": prid, "type": "call",
                  "call_id": "mudi-push-test-" + secrets.token_hex(6)}))
' "$phone")

printf 'linphone.org login (without @%s): ' "$domain"
read -r login
trap 'stty echo 2>/dev/null' EXIT INT TERM
stty -echo 2>/dev/null || true
printf 'Password: '
read -r pass
stty echo 2>/dev/null || true
echo

# curl's config on stdin: user = "login:password", quotes and backslashes escaped.
esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
echo "Sending a call push to \"$phone\" at $(date +%H:%M:%S)…"
res=$(printf 'user = "%s:%s"\n' "$(esc "$login")" "$(esc "$pass")" |
	curl -sS -m 30 --digest -K - -X POST "$api/push_notification" \
		-H 'content-type: application/json' -H 'accept: application/json' \
		-H "from: sip:$login@$domain" --data "$body" -w '\n%{http_code}')
pass=
echo "Answer at $(date +%H:%M:%S)."
code=$(printf '%s' "$res" | tail -n 1)
text=$(printf '%s' "$res" | sed '$d')
case $code in
200 | 204) echo "OK ($code): the push went out. \"$phone\" should show an incoming call that closes by itself in a few seconds." ;;
401) echo "401: wrong login or password, or the account is not activated yet (the e-mail link)." ;;
404) echo "404: no such account on $domain (the login is the part before @)." ;;
422) echo "422: the parameters were refused: $text" ;;
503) echo "503: FlexiAPI accepted the request but its pusher failed (the token or the app did not match, or APNs refused)." ;;
*) echo "HTTP $code: $text" ;;
esac
