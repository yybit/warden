# Warden Desktop

The `warden-gui` crate is a native desktop front end for macOS and Linux. It is
built with **egui/eframe** and links the same `warden` library as the CLI. The detection checks and report model are not duplicated.

## Features

- **Findings** — severity-colored list, evidence, remediation, confidence, and
  ATT&CK techniques.
- **Checks** — every selected check with `ran` / `skipped` / `failed`, match
  count, platforms, a one-line description, and the exact skip/failure reason.
  This is where "what did it actually inspect?" is answered when there are zero
  findings.
- **Cross-navigation** — from a finding to its check, or from a check to its
  findings.
- **Scan controls** — target root, minimum severity, ClamAV, OSV, package
  verification, and optional YARA/IOC paths. Built-in defaults (webroots, rule
  directories, intel feed, malicious-package dataset, ClamAV availability) are
  detected exactly as in the CLI. A discovered `policy.toml` is applied.
- **Export** — JSON and SARIF.
- **Presentation** — dark/light themes, English/中文 UI chrome, bundled Noto Sans SC
  for CJK glyphs.

The UI chrome, severity labels, statuses, and buttons are localized. Finding
titles/messages/remediation, evidence, and check descriptions are still emitted
by the scan engine in English; raw evidence should remain verbatim. Full report
localization needs i18n keys and format arguments in the findings, and is not
implemented yet.

The desktop app is read-only. It does **not** include the sandbox, does not
execute scanned code, and never remediates automatically. Use the CLI for
`sandbox run/fetch`.

## Build and run

Requirements: Rust 1.95+, a GPU/desktop session, and the platform windowing
libraries.

```bash
# from the repository root
cargo run --release -p warden-gui
# or
make gui
```

Linux (Debian/Ubuntu example):

```bash
sudo apt install libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev
```

A Vulkan-capable GPU is recommended. The headless snapshot tests use the GL
backend:

```bash
WGPU_BACKEND=gl cargo test -p warden-gui
```

## Linux packaging

```bash
make gui-linux
# → dist/Warden-<version>-linux-<arch>.tar.gz
```

The tarball contains `warden-gui`, `warden-gui.desktop`, and a 256 px icon.
Install for the current user:

```bash
install -Dm755 Warden-*-linux-*/warden-gui ~/.local/bin/warden-gui
install -Dm644 Warden-*-linux-*/warden-gui.desktop ~/.local/share/applications/warden-gui.desktop
install -Dm644 Warden-*-linux-*/warden-gui.png ~/.local/share/icons/hicolor/256x256/apps/warden-gui.png
```

## macOS packaging

On a Mac with Xcode Command Line Tools:

```bash
make gui-build
packaging/macos/package-gui.sh --arch x86_64   # or aarch64 / universal
```

Cross-build an Intel app from Linux (the same workflow as the CLI, with zig and
a macOS SDK):

```bash
rustup target add x86_64-apple-darwin
SDKROOT=~/sdk/MacOSX15.5.sdk make gui-mac-x86_64
# → dist/Warden-<version>-macos-x86_64.zip
```

Apple Silicon uses `rustup target add aarch64-apple-darwin` and
`make gui-mac-arm64`.

The bundle is ad-hoc signed when `codesign` is available; cross-built bundles
are unsigned. For distribution, sign with a Developer ID and notarize. On a
downloaded unsigned/ad-hoc bundle, Gatekeeper may require:

```bash
xattr -dr com.apple.quarantine Warden.app
codesign --force --sign - Warden.app
```

Real-Mac regression testing is still required; CI only exercises the shared
engine and the headless egui snapshots.

## Privileges

The app runs with the privileges of the user who launches it. Unprivileged
scans cannot read `/etc/shadow`, other users' files, or some process details;
the UI shows a warning and the coverage table records what was skipped. Running
the GUI as root is possible but not recommended for normal desktop use.

## Architecture

```text
warden (library)
├── checks / engine / report model
└── CLI + TUI + sandbox

apps/warden-gui
├── app.rs    state, scan worker channel, findings/checks views
├── theme.rs  egui palette + bundled Noto Sans SC
└── i18n.rs   English/Chinese dictionary
```

The scan runs on a background thread and reports through a channel, so the UI
stays responsive while package/OSV checks are running. The report is a
`warden::model::Report`, the same value rendered by `--format json`/SARIF.

## Visual tests

`egui_kittest` renders the real layout through wgpu without a display server.
Snapshots live in `apps/warden-gui/tests/snapshots/` and cover the welcome,
findings, checks, compact layout, light theme, and Chinese UI. Refresh intentionally changed
snapshots with:

```bash
WGPU_BACKEND=gl UPDATE_SNAPSHOTS=1 cargo test -p warden-gui
```
