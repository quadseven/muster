#!/usr/bin/env python3
"""Draw the muster mark: SVG sources and every raster, from one set of numbers.

RUN IT WITH `python3 render.py` FROM THIS DIRECTORY. No dependencies - not
Pillow, not cairosvg, not rsvg. The mark is four flat polygons with no curves
and no corner rounding, so a rasterizer for it is fifty lines, and fifty lines
of arithmetic beats a build step that somebody has to install before they can
change a color.

THE SVG AND THE PNGs COME OUT OF THE SAME CONSTANTS, and that is the point of
generating both here rather than hand-writing the SVG and tracing it. A vector
source and a raster that disagree is the ordinary way an icon set rots; here
they cannot, because there is one definition of a plate and everything is a
function of it.

Geometry, colors and which size uses which drawing are all from ICON-SPEC.md
in the design project. Where this file and that one disagree, that one wins -
so change the constants here, never the output.
"""
from __future__ import annotations

import pathlib
import struct
import zlib

OUT = pathlib.Path(__file__).resolve().parent.parent
SRC = pathlib.Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Geometry. Both drawings are three parallelograms on a 64-unit viewBox,
# centered on (32, 32); the coordinates below are relative to that center.
# ---------------------------------------------------------------------------

# The canonical mark. Bar 26 wide, 5.4 tall, sheared 3.0 (29.05 degrees),
# gaps of 4.6. Used at 48px and above.
CANONICAL = [
    [(-11.5, -12.7), (14.5, -12.7), (11.5, -7.3), (-14.5, -7.3)],
    [(-11.5, -2.7), (14.5, -2.7), (11.5, 2.7), (-14.5, 2.7)],
    [(-11.5, 7.3), (14.5, 7.3), (11.5, 12.7), (-14.5, 12.7)],
]

# THE SMALL DRAWING IS NOT A SCALE OF THE BIG ONE, and that is deliberate.
# Plates thicken 5.4 -> 8.0, gaps close 4.6 -> 4.0, shear relaxes 3.0 -> 4.0.
# Every horizontal edge lands on a multiple of 4 in absolute viewBox units, so
# at 16px the plates fall on whole device pixels and get no vertical
# anti-aliasing at all - which is the difference between three crisp bars and
# three gray smudges. Used at 16 and 32 only.
SMALL = [
    [(-14, -16), (18, -16), (14, -8), (-18, -8)],
    [(-14, -4), (18, -4), (14, 4), (-18, 4)],
    [(-14, 8), (18, 8), (14, 16), (-18, 16)],
]

GROUND_DARK, GROUND_LIGHT = "#101110", "#FAF7F2"
PLATE_DARK, PLATE_LIGHT = "#FAF7F2", "#101110"
# AMBER NEVER FLIPS. It is the one color in the system that means the same
# thing on both grounds, so it is not part of the theme swap.
ACCENT = "#FFB703"

# The adaptive layer is a 108dp viewBox with the canonical mark at 1.6x,
# centered. That scale is what leaves clearance inside Android's 66dp crop;
# `check_safe_zone` below proves it rather than asserting it.
ADAPTIVE_VIEW = 108.0
ADAPTIVE_SCALE = 1.6


def rgb(h: str) -> tuple[int, int, int]:
    return int(h[1:3], 16), int(h[3:5], 16), int(h[5:7], 16)


def placed(plates, view, center, scale):
    """Plate coordinates moved from center-relative into viewBox absolute."""
    return [
        [(center + x * scale, center + y * scale) for x, y in plate]
        for plate in plates
    ]


# ---------------------------------------------------------------------------
# The safe-zone proof.
# ---------------------------------------------------------------------------

def check_safe_zone() -> str:
    """Android crops an adaptive layer to the inner 66 of 108dp.

    THE TEST IS THE FURTHEST VERTEX, NOT THE BOUNDING BOX. The mark's corners
    are cut away by the shear, so the bounding-box corner is empty space and
    measuring it would fail a mark that is actually fine. The two points that
    matter are the top-right of the top plate and the bottom-left of the
    bottom plate; every other vertex is nearer the center.
    """
    worst = 0.0
    where = (0.0, 0.0)
    for plate in CANONICAL:
        for x, y in plate:
            r = (x * x + y * y) ** 0.5 * ADAPTIVE_SCALE
            if r > worst:
                worst, where = r, (x, y)
    safe = 66.0 / 2
    tip = (ADAPTIVE_VIEW / 2 + where[0] * ADAPTIVE_SCALE,
           ADAPTIVE_VIEW / 2 + where[1] * ADAPTIVE_SCALE)
    assert worst < safe, f"mark reaches {worst:.2f}dp, past the {safe}dp crop"
    return (f"furthest vertex {worst:.2f}dp of {safe:.0f}dp safe radius "
            f"({safe - worst:.2f}dp clear), at layer point "
            f"({tip[0]:.1f}, {tip[1]:.1f})")


# ---------------------------------------------------------------------------
# Rasterizer. Exact horizontal coverage, 16 subsample rows per pixel.
# ---------------------------------------------------------------------------

SUBSAMPLES = 16


def span(poly, y):
    """Where a horizontal line at `y` enters and leaves a convex polygon."""
    xs = []
    n = len(poly)
    for i in range(n):
        x0, y0 = poly[i]
        x1, y1 = poly[(i + 1) % n]
        if y0 == y1:
            continue
        if min(y0, y1) <= y < max(y0, y1):
            xs.append(x0 + (y - y0) * (x1 - x0) / (y1 - y0))
    return (min(xs), max(xs)) if xs else None


def coverage(polys, size, view):
    """Per-pixel coverage in 0..1 for each polygon, anti-aliased."""
    scale = size / view
    out = [[0.0] * (size * size) for _ in polys]
    weight = 1.0 / SUBSAMPLES
    for py in range(size):
        for sy in range(SUBSAMPLES):
            y = (py + (sy + 0.5) * weight) / scale
            for idx, poly in enumerate(polys):
                got = span(poly, y)
                if not got:
                    continue
                x0, x1 = got[0] * scale, got[1] * scale
                x0, x1 = max(0.0, x0), min(float(size), x1)
                if x1 <= x0:
                    continue
                row = out[idx]
                for px in range(int(x0), min(size, int(x1) + 1)):
                    left, right = max(x0, px), min(x1, px + 1.0)
                    if right > left:
                        row[py * size + px] += (right - left) * weight
    return out


def render(size, plates, view, ground, colors):
    """Composite ground then plates into straight RGBA bytes."""
    cov = coverage(plates, size, view)
    if ground:
        gr, gg, gb = rgb(ground)
        px = [[gr, gg, gb, 255] for _ in range(size * size)]
    else:
        px = [[0, 0, 0, 0] for _ in range(size * size)]
    for idx, col in enumerate(colors):
        cr, cg, cb = rgb(col)
        row = cov[idx]
        for i, a in enumerate(row):
            if a <= 0.0:
                continue
            a = min(1.0, a)
            r, g, b, oa = px[i]
            na = a + oa / 255.0 * (1 - a)
            # Straight alpha, so the transparent case composites correctly
            # rather than fringing dark at the plate edges.
            nr = (cr * a + r * (oa / 255.0) * (1 - a)) / na
            ng = (cg * a + g * (oa / 255.0) * (1 - a)) / na
            nb = (cb * a + b * (oa / 255.0) * (1 - a)) / na
            px[i] = [round(nr), round(ng), round(nb), round(na * 255)]
    raw = bytearray()
    for y in range(size):
        raw.append(0)
        for x in range(size):
            raw.extend(px[y * size + x])
    return bytes(raw)


def write_png(path, size, raw):
    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data
                + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 9))
           + chunk(b"IEND", b""))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(png)
    return len(png)


# ---------------------------------------------------------------------------
# SVG sources, from the same constants.
# ---------------------------------------------------------------------------

def svg_paths(plates, view, center, scale, colors, indent="  "):  # noqa: ARG001
    out = []
    # strict=True: three plates need three colors, and a mismatch that
    # silently truncated would drop a plate from the SVG while the PNG
    # (which does not go through this function) still had it.
    for plate, col in zip(placed(plates, view, center, scale), colors, strict=True):
        d = " ".join(
            ("M" if i == 0 else "L") + f"{x:g} {y:g}"
            for i, (x, y) in enumerate(plate)
        ) + " Z"
        out.append(f'{indent}<path d="{d}" fill="{col}"/>')
    return "\n".join(out)


def svg(view, ground, plates, center, scale, colors, note):
    rect = (f'  <rect width="{view:g}" height="{view:g}" fill="{ground}"/>\n'
            if ground else "")
    return (f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'viewBox="0 0 {view:g} {view:g}" '
            f'width="{view:g}" height="{view:g}">\n'
            f"  <!-- {note} -->\n"
            f"{rect}"
            f"{svg_paths(plates, view, center, scale, colors)}\n"
            f"</svg>\n")


def main() -> None:
    print(check_safe_zone())

    tile_colors_dark = [PLATE_DARK, ACCENT, PLATE_DARK]
    tile_colors_light = [PLATE_LIGHT, ACCENT, PLATE_LIGHT]

    # ---- SVG sources -----------------------------------------------------
    sources = {
        "icon-tile.svg": svg(64, GROUND_DARK, CANONICAL, 32, 1, tile_colors_dark,
                             "Canonical mark. Used at 48px and above."),
        "icon-tile-light.svg": svg(64, GROUND_LIGHT, CANONICAL, 32, 1, tile_colors_light,
                                   "Canonical mark, light ground."),
        "icon-tile-sm.svg": svg(64, GROUND_DARK, SMALL, 32, 1, tile_colors_dark,
                                "Small-size drawing. 16 and 32 only - edges land on whole pixels."),
        "icon-tile-sm-light.svg": svg(64, GROUND_LIGHT, SMALL, 32, 1, tile_colors_light,
                                      "Small-size drawing, light ground."),
        "adaptive-foreground.svg": svg(108, None, CANONICAL, 54, ADAPTIVE_SCALE, tile_colors_dark,
                                       "Android adaptive foreground. Transparent; cropped to inner 66dp."),
        "adaptive-foreground-light.svg": svg(108, None, CANONICAL, 54, ADAPTIVE_SCALE, tile_colors_light,
                                             "Android adaptive foreground, light plates."),
        "adaptive-background.svg": svg(108, GROUND_DARK, [], 54, 1, [],
                                       "Android adaptive background. Flat color."),
        "adaptive-background-light.svg": svg(108, GROUND_LIGHT, [], 54, 1, [],
                                             "Android adaptive background, light."),
        "adaptive-monochrome.svg": svg(108, None, CANONICAL, 54, ADAPTIVE_SCALE,
                                       ["#000000"] * 3,
                                       "Android 13+ themed layer. Android takes the alpha and tints it."),
        "maskable-tile.svg": svg(108, GROUND_DARK, CANONICAL, 54, ADAPTIVE_SCALE, tile_colors_dark,
                                 "Web maskable icon. Opaque, mark inside the inner 80%."),
    }
    for name, body in sources.items():
        (SRC / name).write_text(body)
    print(f"{len(sources)} svg sources")

    # ---- rasters ---------------------------------------------------------
    # (filename, size, plates, view, ground, colors)
    jobs = []
    for suffix, ground, cols in (
        ("", GROUND_DARK, tile_colors_dark),
        ("-light", GROUND_LIGHT, tile_colors_light),
    ):
        for n in (16, 32):
            jobs.append((f"favicon-{n}{suffix}.png", n, SMALL, 64, 32, 1, ground, cols))
        for n in (48, 64):
            jobs.append((f"favicon-{n}{suffix}.png", n, CANONICAL, 64, 32, 1, ground, cols))
        jobs.append((f"apple-touch-icon-180{suffix}.png", 180, CANONICAL, 64, 32, 1, ground, cols))
        for n in (192, 512):
            jobs.append((f"android-chrome-{n}{suffix}.png", n, CANONICAL, 64, 32, 1, ground, cols))
        jobs.append((f"android-adaptive-foreground-432{suffix}.png", 432, CANONICAL,
                     108, 54, ADAPTIVE_SCALE, None, cols))
        jobs.append((f"android-adaptive-background-432{suffix}.png", 432, [],
                     108, 54, 1, ground, []))

    jobs.append(("android-chrome-maskable-512.png", 512, CANONICAL, 108, 54,
                 ADAPTIVE_SCALE, GROUND_DARK, tile_colors_dark))
    jobs.append(("android-adaptive-monochrome-432.png", 432, CANONICAL, 108, 54,
                 ADAPTIVE_SCALE, None, ["#000000"] * 3))

    total = 0
    for name, size, plates, view, center, scale, ground, cols in jobs:
        polys = placed(plates, view, center, scale)
        raw = render(size, polys, view, ground, cols)
        total += write_png(OUT / name, size, raw)
        print(f"  {name} {size}x{size}")

    # ---- Android mipmap buckets -----------------------------------------
    # RENDERED FROM THE VECTOR AT EACH SIZE, never downscaled from the 432.
    # A downscale of a downscale is how a crisp mark turns soft on the exact
    # devices with the least resolution to spare.
    res = OUT.parent.parent / "agent/android/app/src/main/res"
    buckets = {"mdpi": 108, "hdpi": 162, "xhdpi": 216, "xxhdpi": 324, "xxxhdpi": 432}
    for bucket, size in buckets.items():
        fg = placed(CANONICAL, 108, 54, ADAPTIVE_SCALE)
        total += write_png(res / f"mipmap-{bucket}/ic_launcher_foreground.png",
                           size, render(size, fg, 108, None, tile_colors_dark))
        total += write_png(res / f"mipmap-{bucket}/ic_launcher_monochrome.png",
                           size, render(size, fg, 108, None, ["#000000"] * 3))
        print(f"  mipmap-{bucket} foreground + monochrome {size}x{size}")

    print(f"{len(jobs) + len(buckets) * 2} rasters, {total / 1024:.0f} KiB")


if __name__ == "__main__":
    main()
