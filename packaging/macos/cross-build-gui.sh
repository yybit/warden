#!/usr/bin/env bash
# Cross-build the Warden desktop app for macOS from Linux.
#
#   SDKROOT=~/sdk/MacOSX15.5.sdk packaging/macos/cross-build-gui.sh
#   SDKROOT=... packaging/macos/cross-build-gui.sh --target x86_64-apple-darwin
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
target=x86_64-apple-darwin
while [[ $# -gt 0 ]]; do
    case $1 in
        --target) target=$2; shift 2 ;;
        *) break ;;
    esac
done
: "${SDKROOT:?set SDKROOT to a macOS SDK, e.g. ~/sdk/MacOSX15.5.sdk}"
[[ -d "$SDKROOT/System/Library/Frameworks" ]] || {
    echo "SDKROOT=$SDKROOT does not look like a macOS SDK" >&2
    exit 1
}
command -v zig >/dev/null || { echo "zig is not on PATH" >&2; exit 1; }
zig_triple=${target%-apple-darwin}-macos.11.0
underscored=${target//-/_}
upper=$(echo "$underscored" | tr '[:lower:]' '[:upper:]')
export SDKROOT WARDEN_MACOS_TRIPLE=$zig_triple MACOSX_DEPLOYMENT_TARGET=11.0
# Keep the builder's username and registry path out of published binaries.
export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=${HOME}/.cargo=/cargo --remap-path-prefix=${HOME}=/build"
export "CC_$underscored=$root/packaging/macos/zig-cc.sh"
export "AR_$underscored=$root/packaging/macos/zig-ar.sh"
export "CARGO_TARGET_${upper}_LINKER=$root/packaging/macos/zig-cc.sh"
echo "building $target (zig target $zig_triple, SDK $SDKROOT)"
exec cargo build --manifest-path "$root/Cargo.toml" --release --target "$target" -p warden-gui "$@"
