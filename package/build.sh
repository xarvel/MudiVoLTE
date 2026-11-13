#!/bin/sh
# Build the mudi-volte release into dist/:
#   mudi-volte_<version>_aarch64_cortex-a53.ipk   OpenWrt package (opkg / LuCI upload)
#   install.sh                                   one-line installer for the router
#   SHA256SUMS
# The daemon comes from scripts/build-static.sh (static musl, AMR-WB linked in),
# and so does mudi-dsi-helper (dynamic, for the firmware's musl); pass
# MUDI_IMSD_BIN or MUDI_DSI_HELPER_BIN to package another binary.
# MUDI_VOLTE_BASE_URL is where install.sh downloads the .ipk from (the release
# page of the hosting).
set -eu

root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
pkg=$root/package
ver=$(cat "$pkg/VERSION")
arch=aarch64_cortex-a53
ipk=mudi-volte_${ver}_${arch}.ipk
out=$root/dist
bin=${MUDI_IMSD_BIN:-$root/build/static/mudi-imsd}
helper=${MUDI_DSI_HELPER_BIN:-$root/build/static/mudi-dsi-helper}
base_url=${MUDI_VOLTE_BASE_URL:-https://github.com/xarvel/MudiVoLTE/releases/download/v$ver}
# Reproducible archives: fixed timestamps, owners and order.
epoch=${SOURCE_DATE_EPOCH:-$(date -d "$(stat -c %y "$pkg/VERSION")" +%s)}

[ -x "$bin" ] || {
	echo "no daemon binary at $bin: run scripts/build-static.sh first" >&2
	exit 1
}
case "$(file -b "$bin")" in
*ARM\ aarch64*statically\ linked*) ;;
*)
	echo "$bin is not a static aarch64 binary: $(file -b "$bin")" >&2
	exit 1
	;;
esac
[ -x "$helper" ] || {
	echo "no data call helper at $helper: run scripts/build-static.sh first" >&2
	exit 1
}
# The helper loads the firmware's DSI library: it must start with the
# firmware's loader.
case "$(file -b "$helper")" in
*ARM\ aarch64*dynamically\ linked,\ interpreter\ /lib/ld-musl-aarch64.so.1*) ;;
*)
	echo "$helper is not an aarch64 binary for the firmware's musl: $(file -b "$helper")" >&2
	exit 1
	;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/data" "$work/control" "$out"

cp -R "$pkg/files/." "$work/data/"
# The GL admin panel's pages are served gzip'd (nginx gzip_static), like its own.
for f in "$work"/data/www/views/*.js; do
	gzip -9n "$f"
done
install -D -m 0755 "$bin" "$work/data/usr/sbin/mudi-imsd"
install -D -m 0755 "$helper" "$work/data/usr/sbin/mudi-dsi-helper"
sed -i "s/@VERSION@/$ver/" "$work/data/usr/sbin/mudi-volte"
if [ -d "$pkg/licenses" ]; then
	mkdir -p "$work/data/usr/share/doc/mudi-volte"
	cp -R "$pkg/licenses" "$work/data/usr/share/doc/mudi-volte/"
	[ -f "$pkg/THIRD_PARTY.md" ] && cp "$pkg/THIRD_PARTY.md" "$work/data/usr/share/doc/mudi-volte/"
fi
# The package's own terms travel with it: the license asks that every copy
# carries them together with the Required Notice line.
for f in LICENSE NOTICE; do
	install -D -m 0644 "$root/$f" "$work/data/usr/share/doc/mudi-volte/$f"
done
find "$work/data" -type d -exec chmod 0755 {} +
find "$work/data" -type f -exec chmod 0644 {} +
chmod 0755 "$work/data/usr/sbin/mudi-imsd" "$work/data/usr/sbin/mudi-dsi-helper" \
	"$work/data/usr/sbin/mudi-volte" "$work/data/etc/init.d/mudi-volte"
chmod 0600 "$work/data/etc/config/mudi-volte" # phones' SIP passwords end up here

size=$(du -sk "$work/data" | cut -f1)
sed -e "s/@VERSION@/$ver/" -e "s/@SIZE@/$((size * 1024))/" "$pkg/control/control.in" >"$work/control/control"
for f in conffiles postinst prerm postrm; do
	cp "$pkg/control/$f" "$work/control/$f"
done
chmod 0644 "$work/control/control" "$work/control/conffiles"
chmod 0755 "$work/control/postinst" "$work/control/prerm" "$work/control/postrm"

mktar() { # dir → gzip'd tar on stdout, the way OpenWrt's ipkg-build packs
	tar --format=gnu --numeric-owner --owner=0 --group=0 --sort=name \
		--mtime="@$epoch" -C "$1" -cf - . | gzip -9n
}
mktar "$work/data" >"$work/data.tar.gz"
mktar "$work/control" >"$work/control.tar.gz"
echo 2.0 >"$work/debian-binary"
touch -d "@$epoch" "$work/debian-binary" "$work/data.tar.gz" "$work/control.tar.gz"
tar --format=gnu --numeric-owner --owner=0 --group=0 --mtime="@$epoch" -C "$work" \
	-cf - ./debian-binary ./data.tar.gz ./control.tar.gz | gzip -9n >"$out/$ipk"

sum=$(sha256sum "$out/$ipk" | cut -d' ' -f1)
sed -e "s|@VERSION@|$ver|g" -e "s|@BASE_URL@|$base_url|g" -e "s|@SHA256@|$sum|g" \
	"$pkg/install.sh.in" >"$out/install.sh"
chmod 0755 "$out/install.sh"
(cd "$out" && sha256sum "$ipk" install.sh >SHA256SUMS)

echo "== $out"
ls -la "$out"
echo "== package contents"
tar -xzOf "$out/$ipk" ./data.tar.gz | tar -tzvf - | awk '{print $1, $3, $6}'
