#!/bin/sh
# Fully static mudi-imsd on musl (linux/arm64, Mudi 7 / OpenWrt) with AMR-WB
# inside: opencore-amrwb and vo-amrwbenc are linked from .a files (tag
# amrwb_static), the libc is Debian's musl. glibc never gets into the binary
# (LGPL). The toolchain and the libraries come from
# package/toolchain/fetch-and-build.sh (cache in package/.cache; a second run
# rebuilds nothing).
# The same toolchain and tags run go test for volte/media/... (the build host
# is arm64 too, so the static tests run natively; Go is the same version as
# for the daemon). Smoke test: -mode check (no network, no modem), AMR-WB
# first in network_codecs. At the end package/toolchain/collect-licenses.sh
# rebuilds package/licenses for this binary and fails if a module is missing
# from THIRD_PARTY.md (the binary itself is built by then).
# mudi-dsi-helper (C, src/dsi-helper) is built with the same compiler, after
# its tests have passed with it. It loads the firmware's DSI library, so it
# is the one binary here that is linked dynamically: against musl, the libc
# of the firmware.
# Output: build/static/mudi-imsd and build/static/mudi-dsi-helper. Build
# without cgo: scripts/build-imsd.sh.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

command -v python3 >/dev/null || {
	echo "error: python3 not found (the tests of mudi-dsi-helper need it)" >&2
	exit 1
}
sh "$root/package/toolchain/fetch-and-build.sh"
cache=$root/package/.cache
sysroot=$cache/sysroot

export GOTOOLCHAIN=auto CGO_ENABLED=1 GOOS=linux GOARCH=arm64
export CC="$cache/bin/musl-gcc"
export CGO_CFLAGS="-O2 -I$sysroot/include" CGO_LDFLAGS="-L$sysroot/lib"
tags='amrwb_static netgo osusergo'
gover=$(cd "$root/src/imsd" && go env GOVERSION)

echo "== go test volte/media/... (static musl, $gover) =="
(cd "$root/volte" && GOTOOLCHAIN=$gover go test -count=1 -trimpath -tags "$tags" \
	-ldflags '-linkmode external -extldflags "-static"' ${VOLTE_TEST_PKGS:-./media/...})

# Version for `mudi-imsd version` and `mudi-volte version`: package/VERSION or $VERSION.
ver=${VERSION:-$(cat "$root/package/VERSION")}
echo "== build mudi-imsd $ver (static musl, $gover) =="
out=$root/build/static/mudi-imsd
mkdir -p "$root/build/static"
(cd "$root/src/imsd" && go build -trimpath -tags "$tags" \
	-ldflags "-s -w -X main.version=$ver -linkmode external -extldflags \"-static\"" -o "$out" .)

file "$out"
if readelf -l "$out" | grep -q -E 'INTERP|DYNAMIC'; then
	echo "error: $out is not static" >&2
	exit 1
fi

echo "== smoke test: -mode check =="
cfg=$(mktemp)
trap 'rm -f "$cfg"' EXIT
echo '{"mode": "check"}' >"$cfg"
log=$("$out" -mode check -config "$cfg" 2>&1)
echo "$log"
if ! echo "$log" | grep -q 'network_codecs=AMR-WB,'; then
	echo "error: AMR-WB is not first in network_codecs" >&2
	exit 1
fi
ls -l "$out"

# The host has no musl loader (/lib/ld-musl-aarch64.so.1). musl's libc.so is
# that loader, so the helper runs here when started through it.
loader=$cache/musl-root/usr/lib/aarch64-linux-musl/libc.so
echo "== test mudi-dsi-helper (musl, against a stand-in for the DSI library) =="
DSI_HELPER_CC=$CC DSI_HELPER_RUN=$loader python3 "$root/src/dsi-helper/tests/helper.test.py"

echo "== build mudi-dsi-helper (musl, dynamic) =="
helper=$root/build/static/mudi-dsi-helper
"$CC" -O2 -Wall -Wextra -Werror -pthread -s -o "$helper" "$root/src/dsi-helper/mudi-dsi-helper.c" -ldl
file "$helper"
# The firmware must be able to start it: its loader, and no library but libc.
if ! readelf -l "$helper" | grep -q 'interpreter: /lib/ld-musl-aarch64.so.1\]'; then
	echo "error: $helper does not ask for the firmware's loader" >&2
	exit 1
fi
needed=$(readelf -d "$helper" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | tr '\n' ' ')
if [ "$needed" != 'libc.so ' ]; then
	echo "error: $helper needs more than libc.so: $needed" >&2
	exit 1
fi
# Smoke test: without arguments it explains its usage and exits with 2.
rc=0
"$loader" "$helper" 2>/dev/null || rc=$?
if [ "$rc" != 2 ]; then
	echo "error: $helper does not run here (exit status $rc, expected 2)" >&2
	exit 1
fi
ls -l "$helper"

echo "== licenses: package/licenses, checked against package/THIRD_PARTY.md =="
sh "$root/package/toolchain/collect-licenses.sh"
