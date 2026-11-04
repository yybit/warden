Warden 0.18.0 — macOS Intel (x86_64) desktop build
====================================================

Requirements
------------
- macOS 11 or newer, Intel Mac (x86_64)
- This is a cross-built, unsigned app bundle.

First launch
------------
1. Unzip Warden-0.18.0-macos-x86_64.zip
2. Open Terminal in the folder containing Warden.app and run:

     xattr -dr com.apple.quarantine Warden.app
     codesign --force --sign - Warden.app
     open Warden.app

The codesign step is an ad-hoc local signature. It is not a Developer ID
signature or notarization; Gatekeeper may still warn on managed Macs.

If the app does not start, run the executable directly to see the error:

     ./Warden.app/Contents/MacOS/warden-gui

What it does
------------
- Read-only host scan: persistence, accounts, listeners, hardening, packages,
  IOC/YARA/ClamAV, and macOS signatures.
- Findings and Checks/coverage views, JSON/SARIF export.
- Dark/light themes, English/Chinese.
- The sandbox is CLI-only; this app does not execute samples.

Privileges
----------
The app runs as the user who launches it. Unprivileged scans cannot read
/etc/shadow, other users' files, or some process details; the UI shows this and
the Checks view records skipped coverage. Running the whole GUI as root is not
recommended.

This build has not been run on a real Mac in the development environment. If it
fails, keep the terminal output and report the macOS version and CPU.
