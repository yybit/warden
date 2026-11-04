#!/usr/bin/env bash
# Assemble Warden.app and a zip of it.
#
#   packaging/macos/package-gui.sh [--arch aarch64|x86_64|universal]
#                                  [--binary PATH] [--out DIR] [--skip-build]
#
# Native macOS builds use `cargo build --release -p warden-gui`. A cross-built
# x86_64 binary from Linux can be passed with --binary and --skip-build.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
case $(uname -m) in
    arm64 | aarch64) arch=aarch64 ;;
    x86_64) arch=x86_64 ;;
    *) arch=aarch64 ;;
esac
binary=
out=$root/dist
build=1

while [[ $# -gt 0 ]]; do
    case $1 in
        --arch) arch=$2; shift 2 ;;
        --binary) binary=$2; shift 2 ;;
        --out) out=$2; shift 2 ;;
        --skip-build) build=0; shift ;;
        -h | --help) sed -n '2,12p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

case $arch in
    aarch64) triple=aarch64-apple-darwin ;;
    x86_64) triple=x86_64-apple-darwin ;;
    universal) triple=universal ;;
    *) echo "--arch must be aarch64, x86_64 or universal" >&2; exit 2 ;;
esac

mkdir -p "$out"
out=$(cd "$out" && pwd)
version=$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -1)
short_version=${version%%-*}
sha=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)
stage=$out/Warden-$version-macos-$arch
app=$stage/Warden.app

if [[ -z $binary ]]; then
    if ((build)); then
        export RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=${HOME}/.cargo=/cargo --remap-path-prefix=${HOME}=/build"
        if [[ $triple == universal ]]; then
            for t in aarch64-apple-darwin x86_64-apple-darwin; do
                cargo build --manifest-path "$root/Cargo.toml" --release --target "$t" -p warden-gui
            done
        else
            cargo build --manifest-path "$root/Cargo.toml" --release --target "$triple" -p warden-gui
        fi
    fi
    binary=$root/target/$triple/release/warden-gui
fi

rm -rf "$stage"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

if [[ $triple == universal ]]; then
    lipo -create \
        "$root/target/aarch64-apple-darwin/release/warden-gui" \
        "$root/target/x86_64-apple-darwin/release/warden-gui" \
        -output "$app/Contents/MacOS/warden-gui" 2>/dev/null ||
        { echo "universal needs both target builds and lipo (macOS only)" >&2; exit 1; }
else
    [[ -f $binary ]] || { echo "no binary at $binary" >&2; exit 1; }
    cp "$binary" "$app/Contents/MacOS/warden-gui"
fi
chmod +x "$app/Contents/MacOS/warden-gui"

cp "$root/packaging/macos/Warden.icns" "$app/Contents/Resources/Warden.icns"
cp "$root/packaging/macos/README-GUI.txt" "$app/Contents/Resources/README.txt"
sed -e "s/@VERSION@/$version/g" \
    -e "s/@SHORT_VERSION@/$short_version/g" \
    -e "s/@BUILD_SHA@/$sha/g" \
    "$root/packaging/macos/Info.plist.in" >"$app/Contents/Info.plist"

command -v plutil >/dev/null && plutil -lint "$app/Contents/Info.plist"

if command -v codesign >/dev/null; then
    codesign --force --sign - "$app"
    codesign --verify --deep --strict "$app"
    echo "ad-hoc signed: $app"
else
    echo "note: no codesign here, so $app stays unsigned;" >&2
    echo "      on the target Mac run: codesign --force --sign - Warden.app" >&2
fi

if command -v ditto >/dev/null; then
    (cd "$stage" && ditto -c -k --keepParent Warden.app "$stage.zip")
elif command -v zip >/dev/null; then
    (cd "$stage" && zip -qr "$stage.zip" Warden.app)
elif command -v bsdtar >/dev/null; then
    (cd "$stage" && bsdtar -a -cf "$stage.zip" Warden.app)
else
    echo "no archiver here: need one of ditto, zip or bsdtar" >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$out" && sha256sum "$(basename "$stage").zip" > "$(basename "$stage").zip.sha256")
else
    (cd "$out" && shasum -a 256 "$(basename "$stage").zip" > "$(basename "$stage").zip.sha256")
fi
echo "packaged $stage.zip"
