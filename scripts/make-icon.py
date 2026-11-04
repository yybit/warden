#!/usr/bin/env python3
"""Generate Warden's app icon (PNG + macOS ICNS) with the Python stdlib.

The mark is the same shield used by the egui window icon: a rounded dark tile,
a blue heraldic shield, and a white check. Run from the repository root:

    python3 scripts/make-icon.py
"""
import math
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BG = (0x0B, 0x0E, 0x13)
BLUE = (0x4F, 0x8C, 0xFF)
WHITE = (0xF4, 0xF8, 0xFF)


def rounded_tile(x, y, size):
    r = size * 0.19
    left, top, right, bottom = r, r, size - r, size - r
    if left <= x <= right or top <= y <= bottom:
        # central cross
        if 0 <= x <= size and top <= y <= bottom:
            return True
        if left <= x <= right:
            return True
    cx = min(max(x, left), right)
    cy = min(max(y, top), bottom)
    return (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def in_shield(x, y, size):
    left, right = size * 0.26, size * 0.74
    top, shoulder, bottom = size * 0.16, size * 0.53, size * 0.86
    if y < top or y > bottom or x < left or x > right:
        return False
    if y <= shoulder:
        return True
    t = (y - shoulder) / (bottom - shoulder)
    half = (right - left) * 0.5 * (1.0 - t)
    return abs(x - (left + right) * 0.5) <= half


def segment_distance(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    length2 = dx * dx + dy * dy
    if length2 == 0:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / length2))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def in_check(x, y, size):
    thickness = size * 0.052
    a = (size * 0.36, size * 0.50)
    b = (size * 0.46, size * 0.61)
    c = (size * 0.65, size * 0.39)
    return min(
        segment_distance(x, y, a[0], a[1], b[0], b[1]),
        segment_distance(x, y, b[0], b[1], c[0], c[1]),
    ) <= thickness


def render(size):
    rows = []
    for py in range(size):
        row = bytearray([0])
        for px in range(size):
            # 2x2 supersampling smooths diagonal shield/check edges.
            acc = [0.0, 0.0, 0.0, 0.0]
            for sy in (0.25, 0.75):
                for sx in (0.25, 0.75):
                    x = (px + sx) * size / size
                    y = (py + sy) * size / size
                    if not rounded_tile(x, y, size):
                        color = (0, 0, 0, 0)
                    elif in_shield(x, y, size) and in_check(x, y, size):
                        color = (*WHITE, 255)
                    elif in_shield(x, y, size):
                        color = (*BLUE, 255)
                    else:
                        color = (*BG, 255)
                    for i in range(4):
                        acc[i] += color[i]
            row.extend(int(v / 4) for v in acc)
        rows.append(bytes(row))
    return zlib.compress(b"".join(rows), 9)


def png(size):
    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(
            ">I", zlib.crc32(tag + data) & 0xFFFFFFFF
        )

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", render(size))
        + chunk(b"IEND", b"")
    )


def icns(images):
    chunks = []
    for kind, size in images:
        data = png(size)
        chunks.append(kind + struct.pack(">I", len(data) + 8) + data)
    body = b"".join(chunks)
    return b"icns" + struct.pack(">I", len(body) + 8) + body


def main():
    icon_dir = ROOT / "apps" / "warden-gui" / "assets"
    icon_dir.mkdir(parents=True, exist_ok=True)
    (icon_dir / "icon.png").write_bytes(png(512))
    (icon_dir / "icon-256.png").write_bytes(png(256))

    pkg = ROOT / "packaging" / "linux"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "warden-gui.png").write_bytes(png(256))

    mac = ROOT / "packaging" / "macos"
    mac.mkdir(parents=True, exist_ok=True)
    (mac / "Warden.icns").write_bytes(
        icns(
            [
                (b"icp4", 16),
                (b"icp5", 32),
                (b"icp6", 64),
                (b"ic07", 128),
                (b"ic08", 256),
                (b"ic09", 512),
                (b"ic10", 1024),
            ]
        )
    )
    print("wrote app icon, Linux PNG, and Warden.icns")


if __name__ == "__main__":
    main()
