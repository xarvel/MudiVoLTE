#!/bin/sh
# Toolchain for the fully static musl build of mudi-imsd (aarch64, Mudi 7 /
# OpenWrt 23.05). glibc is never linked statically (LGPL).
#
# 1. musl, musl-dev, musl-tools from Debian: apt-get download (no root
#    needed), dpkg-deb -x into .cache/musl-root. The wrapper .cache/bin/musl-gcc
#    and its specs are made from Debian's, with the absolute
#    /usr/{lib,include}/aarch64-linux-musl paths rewritten into the unpacked tree.
# 2. opencore-amr 0.1.6 (AMR-WB decoder) and vo-amrwbenc 0.1.3 (AMR-WB
#    encoder): orig tarballs from the Debian pool. Their sha256 is pinned below
#    and must also match the Checksums-Sha256 line of the .dsc. Built with that
#    musl-gcc, -O2, --enable-static --disable-shared, installed into
#    .cache/sysroot/{lib,include}.
# 3. musl source (orig tarball from the pool, verified the same way): only for
#    COPYRIGHT in package/licenses, not built.
#
# Pinned hashes were checked on 2026-11-03 against the signed trixie index
# (InRelease -> Sources). Idempotent: finished steps are skipped by stamps, a
# second run downloads and rebuilds nothing. The cache (package/.cache) is not
# part of the package. Outputs used by scripts/build-static.sh:
#   CC      = package/.cache/bin/musl-gcc
#   sysroot = package/.cache/sysroot (lib/*.a, include/)
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cache=$(dirname -- "$here")/.cache
# The path ends up in gcc specs and configure arguments: safe characters only.
case $cache in
*[!A-Za-z0-9/._+-]*) echo "error: unsupported characters in cache path: $cache" >&2; exit 1 ;;
esac
dl=$cache/downloads
musl_root=$cache/musl-root
bin=$cache/bin
sysroot=$cache/sysroot
work=$cache/build
pool=https://deb.debian.org/debian/pool/main

MUSL_VERSION=1.2.5-3.1~deb13u1
MUSL_DEB_SHA256=46cf1fcaa2d49d1573ef0ceabdb36e04a359a9a37d8e4304024f9018682e3f35
MUSL_DEV_DEB_SHA256=384ea029e3694baac696d3993d93246f9a4b3741c493697e1ceb7256d8820748
MUSL_TOOLS_DEB_SHA256=3d3a33291ee2bb651dae1940671fb302d0a1b90a0ad9bc2a1ae8e81151d811c7
MUSL_DSC=musl_1.2.5-3.1~deb13u1.dsc
MUSL_DSC_SHA256=972970614ed9159b04343b7f85bdf16f565b4a903f05d97e57dc730c7b0b8066
MUSL_TAR=musl_1.2.5.orig.tar.gz
MUSL_TAR_SHA256=a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4

OPENCORE_DSC=opencore-amr_0.1.6-1.dsc
OPENCORE_DSC_SHA256=d5b7f7b6c811edffc76ec6197502a07b0f3b318b5e0542cd84e89f9306d104cc
OPENCORE_TAR=opencore-amr_0.1.6.orig.tar.gz
OPENCORE_TAR_SHA256=483eb4061088e2b34b358e47540b5d495a96cd468e361050fae615b1809dc4a1

VOENC_DSC=vo-amrwbenc_0.1.3-2.dsc
VOENC_DSC_SHA256=d198c3747c02a47e8b30c1b8481d9346381e395e829e6e02750d8ab4058641c9
VOENC_TAR=vo-amrwbenc_0.1.3.orig.tar.gz
VOENC_TAR_SHA256=5652b391e0f0e296417b841b02987d3fd33e6c0af342c69542cbb016a71d9d4e

LIB_CFLAGS=-O2

say() { echo "== $*"; }
die() { echo "error: $*" >&2; exit 1; }
sha256() { sha256sum "$1" | cut -d' ' -f1; }
stamp() { cat "$1" 2>/dev/null || true; }

# put <file> <mode>: stdin to file, only if the content changed.
put() {
	cat >"$1.new"
	if cmp -s "$1.new" "$1"; then
		rm -f "$1.new"
	else
		chmod "$2" "$1.new"
		mv -f "$1.new" "$1"
	fi
}

for t in apt-get dpkg-deb curl sha256sum tar make nm aarch64-linux-gnu-gcc; do
	command -v "$t" >/dev/null || die "$t not found"
done
mkdir -p "$dl" "$bin" "$work"
[ -f "$cache/.gitignore" ] || echo '*' >"$cache/.gitignore"

# fetch <pool dir> <file> <sha256>: download into downloads/ unless present
# with the right hash.
fetch() {
	f=$dl/$2
	if [ -f "$f" ] && [ "$(sha256 "$f")" = "$3" ]; then
		return 0
	fi
	say "downloading $pool/$1/$2"
	rm -f "$f" "$f.part"
	curl -fsS --retry 3 --connect-timeout 30 -m 900 -o "$f.part" "$pool/$1/$2"
	got=$(sha256 "$f.part")
	if [ "$got" != "$3" ]; then
		rm -f "$f.part"
		die "$2: sha256 $got, expected $3"
	fi
	mv -f "$f.part" "$f"
}

# fetch_src <pool dir> <dsc> <dsc sha256> <orig> <orig sha256>: the .dsc and
# the orig tarball; the tarball hash must also be listed in the .dsc.
fetch_src() {
	fetch "$1" "$2" "$3"
	fetch "$1" "$4" "$5"
	awk -v h="$5" -v f="$4" '
		/^Checksums-Sha256:/ { s = 1; next }
		/^[^ ]/ { s = 0 }
		s && $1 == h && $3 == f { ok = 1 }
		END { exit !ok }' "$dl/$2" || die "$4: no Checksums-Sha256 line with $5 in $2"
}

# --- 1. musl from Debian ------------------------------------------------------
musl_key="musl $MUSL_VERSION"
if [ "$(stamp "$musl_root/.stamp")" != "$musl_key" ]; then
	debs=$dl/musl-debs-$MUSL_VERSION
	mkdir -p "$debs"
	for p in musl:$MUSL_DEB_SHA256 musl-dev:$MUSL_DEV_DEB_SHA256 musl-tools:$MUSL_TOOLS_DEB_SHA256; do
		name=${p%%:*} sum=${p#*:}
		f=$debs/${name}_${MUSL_VERSION}_arm64.deb
		if [ ! -f "$f" ] || [ "$(sha256 "$f")" != "$sum" ]; then
			rm -f "$f"
			say "apt-get download $name=$MUSL_VERSION"
			(cd "$debs" && apt-get download "$name=$MUSL_VERSION")
		fi
		[ "$(sha256 "$f")" = "$sum" ] || die "$f: sha256 does not match the pinned one"
	done
	rm -rf "$musl_root.new"
	mkdir -p "$musl_root.new"
	for name in musl musl-dev musl-tools; do
		dpkg-deb -x "$debs/${name}_${MUSL_VERSION}_arm64.deb" "$musl_root.new"
	done
	rm -rf "$musl_root"
	mv "$musl_root.new" "$musl_root"
	echo "$musl_key" >"$musl_root/.stamp"
	say "musl $MUSL_VERSION unpacked into $musl_root"
fi

# Wrapper and specs: from Debian's, with paths into the unpacked tree.
# Regenerated on every run (cheap, and the cache may move with the project).
ml=$musl_root/usr/lib/aarch64-linux-musl
mi=$musl_root/usr/include/aarch64-linux-musl
sed -e "s#/usr/include/aarch64-linux-musl#$mi#g" -e "s#/usr/lib/aarch64-linux-musl#$ml#g" \
	"$ml/musl-gcc.specs" | put "$bin/musl-gcc.specs" 644
sed -e "s#/usr/lib/aarch64-linux-musl/musl-gcc.specs#$bin/musl-gcc.specs#" \
	"$musl_root/usr/bin/aarch64-linux-musl-gcc" | put "$bin/musl-gcc" 755
cc=$bin/musl-gcc
grep -q -- "-specs \"$bin/musl-gcc.specs\"" "$cc" || die "$cc: specs path not rewritten"
if sed "s#$musl_root/usr/#@/#g" "$bin/musl-gcc.specs" | grep -q -E '/usr/(lib|include)/aarch64-linux-musl'; then
	die "$bin/musl-gcc.specs: system musl paths left"
fi

# Self-test: musl headers (not glibc), a static binary runs.
t=$work/selftest
rm -rf "$t"
mkdir -p "$t"
if printf '#include <stdio.h>\n' | "$cc" -E -dM -x c - | grep -q __GLIBC__; then
	die "musl-gcc picked up glibc headers"
fi
printf '#include <stdio.h>\nint main(void) { puts("musl-gcc ok"); return 0; }\n' >"$t/hello.c"
"$cc" -O2 -static -o "$t/hello" "$t/hello.c"
[ "$("$t/hello")" = "musl-gcc ok" ] || die "static musl binary does not run"
say "musl-gcc: $cc (gcc $("$cc" -dumpfullversion), musl $MUSL_VERSION)"

# --- 2. sources ---------------------------------------------------------------
fetch_src o/opencore-amr "$OPENCORE_DSC" "$OPENCORE_DSC_SHA256" "$OPENCORE_TAR" "$OPENCORE_TAR_SHA256"
fetch_src v/vo-amrwbenc "$VOENC_DSC" "$VOENC_DSC_SHA256" "$VOENC_TAR" "$VOENC_TAR_SHA256"
fetch_src m/musl "$MUSL_DSC" "$MUSL_DSC_SHA256" "$MUSL_TAR" "$MUSL_TAR_SHA256"
say "sources verified (pinned sha256 = .dsc)"

# --- 3. static libraries --------------------------------------------------------
cc_id="gcc-$("$cc" -dumpfullversion) musl-$MUSL_VERSION"
jobs=$(nproc 2>/dev/null || echo 2)

# build_lib <name> <tarball> <sha256> <top dir> <.a file> [configure args]
build_lib() {
	name=$1 tarball=$dl/$2 sum=$3 top=$4 lib=$5
	shift 5
	key="$name $sum $cc_id cflags=$LIB_CFLAGS args=$*"
	if [ -f "$sysroot/lib/$lib" ] && [ "$(stamp "$sysroot/.stamp-$name")" = "$key" ]; then
		say "$name: already built ($sysroot/lib/$lib)"
		return 0
	fi
	say "$name: building"
	rm -f "$sysroot/.stamp-$name"
	# The tarball is untrusted data: its own new empty directory, and only
	# its configure and make are run from it.
	src=$work/$name
	rm -rf "$src"
	mkdir -p "$src"
	tar -xzf "$tarball" -C "$src"
	[ "$(ls -A "$src")" = "$top" ] || die "$2: expected a single directory $top"
	# LDFLAGS=-static: configure runs its test programs right here, and the
	# host has no musl dynamic loader (/lib/ld-musl-aarch64.so.1).
	(
		cd "$src/$top"
		./configure --prefix="$sysroot" --enable-static --disable-shared \
			--disable-dependency-tracking "$@" \
			CC="$cc" CXX="$cc" CFLAGS="$LIB_CFLAGS" CXXFLAGS="$LIB_CFLAGS" LDFLAGS=-static
		make -j"$jobs"
		make install
	)
	[ -f "$sysroot/lib/$lib" ] || die "$name: no $sysroot/lib/$lib after install"
	echo "$key" >"$sysroot/.stamp-$name"
}

# opencore-amr: only the AMR-WB decoder is needed; its .cpp files are compiled
# as C (--enable-compile-c is the default), so CXX is musl-gcc as well.
build_lib opencore-amr "$OPENCORE_TAR" "$OPENCORE_TAR_SHA256" opencore-amr-0.1.6 \
	libopencore-amrwb.a --disable-amrnb-encoder --disable-amrnb-decoder
build_lib vo-amrwbenc "$VOENC_TAR" "$VOENC_TAR_SHA256" vo-amrwbenc-0.1.3 libvo-amrwbenc.a

# Check: the E_IF_*/D_IF_* interface is there, and a frame encodes and decodes
# in a static musl binary.
for s in E_IF_init E_IF_encode E_IF_exit; do
	nm -g "$sysroot/lib/libvo-amrwbenc.a" | grep -q " T $s\$" || die "libvo-amrwbenc.a: no $s"
done
for s in D_IF_init D_IF_decode D_IF_exit; do
	nm -g "$sysroot/lib/libopencore-amrwb.a" | grep -q " T $s\$" || die "libopencore-amrwb.a: no $s"
done
cat >"$t/amrwb.c" <<'EOF'
#include <stdio.h>
void *E_IF_init(void);
int E_IF_encode(void *state, int mode, const short *speech, unsigned char *out, int dtx);
void E_IF_exit(void *state);
void *D_IF_init(void);
void D_IF_decode(void *state, const unsigned char *bits, short *synth, int bfi);
void D_IF_exit(void *state);

int main(void)
{
	short pcm[320] = {0}, out[320];
	unsigned char frame[64];
	void *enc = E_IF_init(), *dec = D_IF_init();
	int n = E_IF_encode(enc, 8, pcm, frame, 0); /* 23.85 kbit/s: 1 + 60 bytes */
	D_IF_decode(dec, frame, out, 0);
	E_IF_exit(enc);
	D_IF_exit(dec);
	printf("%d\n", n);
	return 0;
}
EOF
"$cc" -O2 -static -o "$t/amrwb" "$t/amrwb.c" -L"$sysroot/lib" -lopencore-amrwb -lvo-amrwbenc -lm
[ "$("$t/amrwb")" = 61 ] || die "AMR-WB: test frame did not encode to 61 bytes"

say "done"
echo "CC=$cc"
echo "sysroot=$sysroot"
ls -l "$sysroot/lib/libopencore-amrwb.a" "$sysroot/lib/libvo-amrwbenc.a"
