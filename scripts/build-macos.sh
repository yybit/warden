#!/usr/bin/env bash
# Cross-build the Warden host binary for macOS from Linux with cargo-zigbuild.
#
#   SDKROOT=~/sdk/MacOSX15.5.sdk scripts/build-macos.sh x86_64-apple-darwin
#   SDKROOT=~/sdk/MacOSX15.5.sdk scripts/build-macos.sh aarch64-apple-darwin
#
# Requires: zig, cargo-zigbuild, the matching rust target, and a macOS SDK
# (zig ships libSystem but no frameworks; wasmtime links CoreFoundation).
set -euo pipefail

cd "$(dirname "$0")/.."

target=${1:-x86_64-apple-darwin}
case "$target" in
    x86_64-apple-darwin | aarch64-apple-darwin) ;;
    *)
        echo "unsupported target: $target" >&2
        exit 1
        ;;
esac

: "${SDKROOT:?set SDKROOT to a macOS SDK, e.g. ~/sdk/MacOSX15.5.sdk}"
[[ -d "$SDKROOT/System/Library/Frameworks" ]] || {
    echo "SDKROOT=$SDKROOT does not look like a macOS SDK" >&2
    exit 1
}
command -v zig >/dev/null || { echo "zig is not on PATH" >&2; exit 1; }
cargo zigbuild --help >/dev/null 2>&1 || {
    echo "cargo-zigbuild is not installed (cargo install cargo-zigbuild)" >&2
    exit 1
}

export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-11.0}
# zig's linker needs the SDK for -framework/-lSystem resolution.
sdk_flags="-C link-arg=-isysroot -C link-arg=$SDKROOT"
sdk_flags+=" -C link-arg=-F$SDKROOT/System/Library/Frameworks"
sdk_flags+=" -C link-arg=-L$SDKROOT/usr/lib"
# Keep local usernames/build directories out of panic-location strings in the
# published binary. CI remaps /home/runner the same way.
export RUSTFLAGS="${RUSTFLAGS:-} $sdk_flags --remap-path-prefix=${HOME}/.cargo=/cargo --remap-path-prefix=${HOME}=/build"

echo "building $target (SDK $SDKROOT, min macOS $MACOSX_DEPLOYMENT_TARGET)"
cargo zigbuild --release --target "$target"

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
mkdir -p dist
out="dist/warden-${version}-${target}"
cp "target/${target}/release/warden" "$out"
chmod +x "$out"

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$out" > "$out.sha256"
else
    shasum -a 256 "$out" > "$out.sha256"
fi

file "$out" || true
echo "built $out"
echo "checksum: $(cut -d' ' -f1 "$out.sha256")"
