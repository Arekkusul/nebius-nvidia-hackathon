"""Assemble the frames from scripts/record_demo.js into an animated GIF.

    python scripts/make_gif.py FRAMES_DIR docs/demo.gif [--width 1000] [--ms 400]

Also used to produce the link-preview image:

    python scripts/make_gif.py --og docs/screenshot.png rulesmith/server/static/og.jpg

Needs Pillow (in the ``dev`` extras). The GIF is scaled down and quantised
to a 128-colour palette so a full replay stays a few megabytes, small enough
for a README and the Devpost gallery.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image


def make_gif(frames_dir: Path, out: Path, width: int, frame_ms: int) -> None:
    """Scale every frame to ``width``, quantise, and write a looping GIF."""
    paths = sorted(frames_dir.glob("f*.png"))
    if not paths:
        raise SystemExit(f"no frames in {frames_dir}")
    frames = []
    for p in paths:
        im = Image.open(p).convert("RGB")
        h = round(im.height * width / im.width)
        im = im.resize((width, h), Image.LANCZOS)
        # Median-cut palette per frame keeps text crisp; Pillow handles the per-frame palettes.
        frames.append(im.quantize(colors=128, method=Image.Quantize.MEDIANCUT))
    # Hold the last frame a little longer so the pack is readable before the loop restarts.
    durations = [frame_ms] * (len(frames) - 1) + [frame_ms * 6]
    frames[0].save(out, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)
    print(f"wrote {out} ({len(frames)} frames, {out.stat().st_size / 1024:.0f} KB)")


def make_og(screenshot: Path, out: Path) -> None:
    """Crop the README screenshot to the 1200x630 Open Graph size (top of the page)."""
    im = Image.open(screenshot).convert("RGB")
    w = 1200
    im = im.resize((w, round(im.height * w / im.width)), Image.LANCZOS).crop((0, 0, w, 630))
    im.save(out, "JPEG", quality=82, optimize=True)
    print(f"wrote {out} ({out.stat().st_size / 1024:.0f} KB)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the demo GIF or the link-preview image.")
    parser.add_argument("src", type=Path, help="frames directory, or the screenshot with --og")
    parser.add_argument("out", type=Path)
    parser.add_argument("--width", type=int, default=1000)
    parser.add_argument("--ms", type=int, default=400, help="milliseconds per frame")
    parser.add_argument("--og", action="store_true", help="make the 1200x630 preview image instead of a GIF")
    args = parser.parse_args()
    if args.og:
        make_og(args.src, args.out)
    else:
        make_gif(args.src, args.out, args.width, args.ms)


if __name__ == "__main__":
    main()
