#!/usr/bin/env bash
# cc/linker for a macOS target when cross-building from Linux with zig.
# Requires WARDEN_MACOS_TRIPLE and SDKROOT (see cross-build-gui.sh).
set -euo pipefail
args=()
for arg in "$@"; do
    case "$arg" in
        --target=*) ;;
        *) args+=("$arg") ;;
    esac
done
sysroot=()
if [[ -n ${SDKROOT:-} ]]; then
    sysroot=(
        -isysroot "$SDKROOT"
        "-L$SDKROOT/usr/lib"
        "-F$SDKROOT/System/Library/Frameworks"
    )
fi
exec zig cc -target "$WARDEN_MACOS_TRIPLE" "${sysroot[@]}" "${args[@]}"
