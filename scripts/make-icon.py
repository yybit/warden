#!/usr/bin/env python3
"""Regenerate Warden's PNG/ICNS branding from assets/warden-logo.svg.

Requires `rsvg-convert` (librsvg). Run from the repository root:

    python3 scripts/make-icon.py
"""
import struct
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "assets" / "warden-logo.svg"


def png(size: int) -> bytes:
    out = ROOT / "apps" / "warden-gui" / "assets" / f"icon-{size}.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            "rsvg-convert",
            "-w",
            str(size),
            "-h",
            str(size),
            str(SOURCE),
            "-o",
            str(out),
        ],
        check=True,
    )
    return out.read_bytes()


def icns(images):
    chunks = []
    for kind, data in images:
        chunks.append(kind + struct.pack(">I", len(data) + 8) + data)
    body = b"".join(chunks)
    return b"icns" + struct.pack(">I", len(body) + 8) + body


def main():
    if not SOURCE.is_file():
        raise SystemExit(f"missing logo: {SOURCE}")

    sizes = [16, 32, 64, 128, 256, 512, 1024]
    data = {size: png(size) for size in sizes}

    # The README uses the SVG; these are for the app window, Linux desktop, and
    # macOS bundle.
    (ROOT / "apps" / "warden-gui" / "assets" / "icon.png").write_bytes(data[512])
    (ROOT / "packaging" / "linux" / "warden-gui.png").write_bytes(data[256])

    mac = ROOT / "packaging" / "macos"
    mac.mkdir(parents=True, exist_ok=True)
    (mac / "Warden.icns").write_bytes(
        icns(
            [
                (b"icp4", data[16]),
                (b"icp5", data[32]),
                (b"icp6", data[64]),
                (b"ic07", data[128]),
                (b"ic08", data[256]),
                (b"ic09", data[512]),
                (b"ic10", data[1024]),
            ]
        )
    )
    print("wrote app icon, Linux PNG, and Warden.icns")


if __name__ == "__main__":
    main()
