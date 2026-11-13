# Contributing

Thank you for looking into MudiVoLTE. Reports from other operators and other
firmware versions are the most useful thing you can send; patches are welcome
too. Security problems go the private way described in [SECURITY.md](SECURITY.md).

## Reporting a problem

Open an issue with:

- the router model and the GL firmware version, and `mudi-volte version`;
- the country and the operator of the SIM (the operator can be left out);
- what you did, what happened and what you expected;
- `mudi-volte status` and the relevant part of `mudi-volte logs`. The log
  masks phone numbers; the status line and a packet capture do not, so look
  them over before pasting. Never post the IMSI, the IMEI or push tokens.

## Building and testing

The README explains the build (`scripts/build-static.sh`, `package/build.sh`)
and the layout of the repository. Before sending a change, run:

```sh
(cd volte && go vet ./... && go test ./...)
(cd src/imsd && go vet ./... && go test ./...)
python3 src/dsi-helper/tests/helper.test.py   # mudi-dsi-helper (needs Linux and a C compiler)
python3 package/tests/lifecycle.test.py       # mudi-volte setup and restore, the init script
shellcheck -s sh package/install.sh.in package/build.sh package/control/* \
    package/files/usr/sbin/mudi-volte package/files/etc/init.d/mudi-volte scripts/*.sh
sh package/tests/run.sh      # the GL admin panel and LuCI pages (needs node and npm)
luac5.1 -p package/files/usr/lib/oui-httpd/rpc/mudi-volte \
    package/files/usr/share/gl-validator.d/mudi-volte.lua   # the router runs Lua 5.1
```

The Go tests run on Linux and macOS; the few that need Linux (the data call
through `mudi-dsi-helper` and its stand-in library, TCP keep-alive) skip
elsewhere. The XFRM test of
`volte/ipsec` installs real security associations and runs only on request:
`VOLTE_XFRM_TEST=1 unshare -rn go test ./ipsec/` in `volte/`. A change that
touches the modem, the IMS side or the phones should be tried on a Mudi 7 as
well; say in the pull request what you tried it on.

## Code

- Go is formatted with `gofmt`; shell scripts pass `shellcheck`; comments and
  commit messages are in English. Each commit says what changed and why.
- New third-party code or a new Go module needs a permissive licence (BSD,
  MIT, Apache-2.0 and the like) and an entry in `package/THIRD_PARTY.md` and
  `volte/PROVENANCE.md`. The `volte` library is written from the 3GPP and
  IETF specifications: a change of its behaviour cites the clause it follows.
- Comments cite "§N": sections of the author's engineering log, which is not
  published. New comments should explain the behaviour in place instead;
  `docs/PROTOCOLS.md` is the public account of the live network.
- A change in behaviour comes with a test where the suites allow it
  (`src/imsd/*_test.go` play the phones and the network over 127.0.0.1).

## Licence of contributions

MudiVoLTE is published under the PolyForm Noncommercial License 1.0.0 and the
author also licenses it commercially. So that this can go on with outside
contributions, every contribution is made under these terms:

- You license your contribution under the PolyForm Noncommercial License
  1.0.0, like the rest of the project.
- You also grant the project's author, Arthur Valiullin, the right to license
  your contribution, as part of MudiVoLTE, under other terms, including
  commercial ones.
- You certify the [Developer Certificate of Origin 1.1](https://developercertificate.org):
  the contribution is yours to give, or you have the right to give it.

Sign off every commit to record this (`git commit -s` adds the line):

```
Signed-off-by: Your Name <you@example.com>
```

Pull requests without a sign-off cannot be merged.
