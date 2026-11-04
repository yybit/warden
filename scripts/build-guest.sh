#!/usr/bin/env bash
# Build a Linux guest binary for `warden sandbox run --engine vm`.
# Must run on Linux (native build); use .github/workflows/release-guest.yml
# for both architectures.
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "guest binaries must be built on Linux; use the GitHub workflow or a Linux container" >&2
  exit 1
fi

cd "$(dirname "$0")/.."

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
arch=$(uname -m)
case "$arch" in
  x86_64 | aarch64) ;;
  *)
    echo "unsupported architecture: $arch" >&2
    exit 1
    ;;
esac

target="${arch}-unknown-linux-gnu"
name="warden-${version}-${target}"

cargo build --release --locked
mkdir -p dist
cp target/release/warden "dist/${name}"
chmod +x "dist/${name}"
(cd dist && sha256sum "${name}" > "${name}.sha256")

echo "built dist/${name}"
echo "URL example: https://example.com/releases/${name}"
