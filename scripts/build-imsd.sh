#!/bin/sh
# Quick development build of mudi-imsd: static linux/arm64 (CGO_ENABLED=0) for
# OpenWrt/musl on the Mudi. GOTOOLCHAIN=auto fetches the Go version of go.mod
# through proxy.golang.org. Without cgo the AMR-WB codec is not linked in, so
# the network side negotiates G.711 (PCMA/PCMU); release builds use
# scripts/build-static.sh. Also runs go vet and go test for the volte library
# and the daemon (natively on an arm64 host).
set -eu
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

echo "== volte library: vet + test =="
(cd "$root/volte" && GOTOOLCHAIN=auto go vet ./... && GOTOOLCHAIN=auto go test ./...)

echo "== vet + test + build imsd =="
cd "$root/src/imsd"
export GOTOOLCHAIN=auto CGO_ENABLED=0 GOOS=linux GOARCH=arm64
go vet ./...
go test ./...
go build -trimpath -ldflags "-s -w" -o "$root/build/mudi-imsd" .

ls -la "$root/build/mudi-imsd"
file "$root/build/mudi-imsd" 2>/dev/null || true
