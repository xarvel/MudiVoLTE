#!/bin/sh
# License texts of everything linked into build/static/mudi-imsd, collected
# into package/licenses/. Run after scripts/build-static.sh.
#  - go/: Go standard library and runtime (LICENSE, PATENTS from the GOROOT
#    of the Go version that built the binary);
#  - <module path>/: Go modules the binary contains (go version -m), their
#    LICENSE/COPYING/NOTICE/PATENTS files from the module cache. Modules that
#    are only in src/imsd/go.sum are reported and skipped;
#  - opencore-amr/, vo-amrwbenc/, musl/: from the tarballs in
#    package/.cache/downloads verified by fetch-and-build.sh;
#  - gcc/ (libgcc.a, crtbeginS.o/crtendS.o): fixed texts taken from the
#    gcc-14 14.2.0 source (Debian orig); kept as they are.
# Finally checks that every Go module of the binary is listed in
# package/THIRD_PARTY.md with its version; any mismatch exits with 1.
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
lic=$root/package/licenses
table=$root/package/THIRD_PARTY.md
dl=$root/package/.cache/downloads
bin=$root/build/static/mudi-imsd

die() { echo "error: $*" >&2; exit 1; }
[ -f "$bin" ] || die "no $bin: run scripts/build-static.sh first"
[ -d "$lic/gcc" ] || die "no $lic/gcc (fixed GCC texts)"
for f in opencore-amr_0.1.6.orig.tar.gz vo-amrwbenc_0.1.3.orig.tar.gz musl_1.2.5.orig.tar.gz; do
	[ -f "$dl/$f" ] || die "no $dl/$f: run package/toolchain/fetch-and-build.sh first"
done

export GOTOOLCHAIN=auto
modcache=$(go env GOMODCACHE)
gover=$(go version "$bin" | awk '{print $2}')
new=$lic.new
tmp=$(mktemp -d)
trap 'rm -rf "$tmp" "$new"' EXIT
rm -rf "$new"
mkdir -p "$new"
cp -a "$lic/gcc" "$new/gcc"

# Go standard library and runtime.
goroot=$(GOTOOLCHAIN=$gover go env GOROOT)
mkdir -p "$new/go"
cp "$goroot/LICENSE" "$goroot/PATENTS" "$new/go/"

# Go modules in the binary.
go version -m "$bin" | awk '$1 == "dep" && $2 !~ /^github\.com\/xarvel\/MudiVoLTE\// { print $2, $3 }' | sort -u >"$tmp/deps"
nolicense=
while read -r mod ver; do
	# The module cache escapes upper-case letters as !lower-case.
	dir=$modcache/$(echo "$mod" | sed 's/[A-Z]/!&/g' | tr 'A-Z' 'a-z')@$ver
	if [ ! -d "$dir" ]; then
		dir=$(cd "$tmp" && GOFLAGS='' go mod download -json "$mod@$ver" | sed -n 's/^\t"Dir": "\(.*\)",$/\1/p')
	fi
	[ -d "$dir" ] || die "$mod@$ver: not in the module cache"
	mkdir -p "$new/$mod"
	found=
	for f in "$dir"/*; do
		case $(basename "$f" | tr 'A-Z' 'a-z') in
		licen[cs]e* | copying* | notice* | patents* | copyright* | unlicense*)
			cp "$f" "$new/$mod/"
			found=1
			;;
		esac
	done
	[ -n "$found" ] || nolicense="$nolicense $mod"
done <"$tmp/deps"

# C libraries and musl: single files from the verified tarballs (tar -O).
take() { # take <tarball> <member> <dest>
	mkdir -p "$(dirname "$3")"
	tar -xzOf "$dl/$1" "$2" >"$3"
}
o=opencore-amr-0.1.6
take opencore-amr_0.1.6.orig.tar.gz $o/LICENSE "$new/opencore-amr/LICENSE"
take opencore-amr_0.1.6.orig.tar.gz $o/opencore/NOTICE "$new/opencore-amr/NOTICE"
take opencore-amr_0.1.6.orig.tar.gz $o/opencore/codecs_v2/audio/gsm_amr/patent_disclaimer.txt \
	"$new/opencore-amr/patent_disclaimer.txt"
v=vo-amrwbenc-0.1.3
take vo-amrwbenc_0.1.3.orig.tar.gz $v/COPYING "$new/vo-amrwbenc/COPYING"
take vo-amrwbenc_0.1.3.orig.tar.gz $v/NOTICE "$new/vo-amrwbenc/NOTICE"
take vo-amrwbenc_0.1.3.orig.tar.gz $v/amrwbenc/NOTICE "$new/vo-amrwbenc/NOTICE.amrwbenc"
take vo-amrwbenc_0.1.3.orig.tar.gz $v/amrwbenc/patent_disclaimer.txt \
	"$new/vo-amrwbenc/patent_disclaimer.txt"
take musl_1.2.5.orig.tar.gz musl-1.2.5/COPYRIGHT "$new/musl/COPYRIGHT"

# Files from the module cache are read-only; use the project's modes.
find "$new" -type d -exec chmod 775 {} +
find "$new" -type f -exec chmod 664 {} +
rm -rf "$lic.old"
mv "$lic" "$lic.old"
mv "$new" "$lic"
rm -rf "$lic.old"
echo "== $lic:"
(cd "$lic" && find . -type f | sort)

# go.sum modules not in the binary: reported, no texts collected.
awk '$2 !~ /\/go\.mod$/ { print $1, $2 }' "$root/src/imsd/go.sum" | sort -u >"$tmp/gosum"
comm -23 "$tmp/gosum" "$tmp/deps" | while read -r mod ver; do
	echo "note: $mod $ver is in src/imsd/go.sum but not in the binary, skipped"
done

# THIRD_PARTY.md: module and version on one table line.
bad=0
while read -r mod ver; do
	if ! grep -F -- "$mod" "$table" 2>/dev/null | grep -q -F -- "$ver"; then
		echo "warning: $mod $ver is missing from $table" >&2
		bad=1
	fi
done <"$tmp/deps"
echo "Go $gover, modules in the binary: $(wc -l <"$tmp/deps"), without a license file:${nolicense:- none}"
exit $bad
