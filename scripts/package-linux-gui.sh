#!/usr/bin/env bash
# Package the Linux desktop app as a portable tarball.
#
#   scripts/package-linux-gui.sh [--skip-build] [--out DIR]
#
# The result is dist/Warden-<version>-linux-<arch>.tar.gz containing the binary,
# desktop entry, and icon. Install with the commands printed at the end.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
out=$root/dist
build=1
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build) build=0; shift ;;
        --out) out=$2; shift 2 ;;
        -h | --help) sed -n '2,9p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

case $(uname -m) in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    *) arch=$(uname -m) ;;
esac

if ((build)); then
    export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=${HOME}/.cargo=/cargo --remap-path-prefix=${HOME}=/build"
    cargo build --manifest-path "$root/Cargo.toml" --release -p warden-gui
fi
binary=$root/target/release/warden-gui
[[ -f $binary ]] || { echo "no binary at $binary" >&2; exit 1; }

version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)
stage=$out/Warden-$version-linux-$arch
mkdir -p "$stage"
cp "$binary" "$stage/warden-gui"
cp "$root/packaging/linux/warden-gui.desktop" "$stage/warden-gui.desktop"
cp "$root/packaging/linux/warden-gui.png" "$stage/warden-gui.png"
chmod +x "$stage/warden-gui"
tar -C "$out" -czf "$stage.tar.gz" "$(basename "$stage")"
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$out" && sha256sum "$(basename "$stage").tar.gz" > "$(basename "$stage").tar.gz.sha256")
else
    (cd "$out" && shasum -a 256 "$(basename "$stage").tar.gz" > "$(basename "$stage").tar.gz.sha256")
fi

echo "packaged $stage.tar.gz"
echo
echo "Install for the current user:"
echo "  install -Dm755 $stage/warden-gui ~/.local/bin/warden-gui"
echo "  install -Dm644 $stage/warden-gui.desktop ~/.local/share/applications/warden-gui.desktop"
echo "  install -Dm644 $stage/warden-gui.png ~/.local/share/icons/hicolor/256x256/apps/warden-gui.png"
