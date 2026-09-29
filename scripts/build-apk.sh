#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || $(uname -s -m) != 'Linux x86_64' ]]; then
  echo "usage on Linux x86_64: $0 /path/to/openwrt-sdk-25.12.5-mediatek-filogic..." >&2
  exit 2
fi

root=$(cd "$(dirname "$0")/.." && pwd)
sdk=$(cd "$1" && pwd)
if [[ ! -f "$sdk/rules.mk" ]]; then
  echo "not an OpenWrt SDK: $sdk" >&2
  exit 1
fi

pkg="$sdk/package/lan-service-gateway"
mkdir -p "$pkg/files" "$root/dist"
cp "$root/package/Makefile" "$pkg/Makefile"
cp "$root/package/files/"* "$pkg/files/"
docker run --rm -v "$root:/src" -w /src golang:1.26.7 sh -ec \
  'GOCACHE=/tmp/go-build go test ./... && GOCACHE=/tmp/go-build GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /src/lan-service-gateway.bin .'
cp "$root/lan-service-gateway.bin" "$pkg/files/lan-service-gateway.bin"
rm "$root/lan-service-gateway.bin"

cd "$sdk"
make defconfig
make package/lan-service-gateway/clean
make package/lan-service-gateway/compile V=s

version=$(sed -n 's/^PKG_VERSION:=//p' "$root/package/Makefile")
release=$(sed -n 's/^PKG_RELEASE:=//p' "$root/package/Makefile")
shopt -s nullglob globstar
artifacts=("$sdk"/bin/**/"lan-service-gateway-$version-r$release.apk")
if [[ ${#artifacts[@]} -ne 1 ]]; then
  echo "expected one APK after SDK build; found ${#artifacts[@]}" >&2
  exit 1
fi
artifact=${artifacts[0]}
cp "$artifact" "$root/dist/"
shasum -a 256 "$root/dist/$(basename "$artifact")"
