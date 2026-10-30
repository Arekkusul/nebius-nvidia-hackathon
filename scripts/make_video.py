"""Turn the frames from scripts/record_video.js into the demo video.

    python scripts/make_video.py FRAMES_DIR docs/demo.webm

Title cards open and close the video, every screen frame gets its caption
burned into a bar at the bottom, and ffmpeg (the Playwright build is
enough: it encodes VP8/WebM from raw frames) writes a WebM that YouTube
accepts as-is. Needs Pillow (dev extras) and a TrueType font.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

# Low on purpose: screen captures barely change between frames, so 16 fps keeps the encode
# fast and the file small; each recorded frame is simply repeated for its playback time.
FPS = 16
FONT_CANDIDATES = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
]
# A system ffmpeg if there is one, else the build Playwright ships with its browsers
# (it has libvpx, which is all this script needs).
FFMPEG_CANDIDATES = [shutil.which("ffmpeg") or "", "/opt/pw-browsers/ffmpeg-1011/ffmpeg-linux"]

# Title cards: (headline, lines, seconds). Kept short; the screen does the talking.
OPENING = [
    ("RuleSmith", ["Threat intel in. Tested detections out.", "", "An autonomous detection-engineering agent built on", "NVIDIA Nemotron via Nebius Token Factory, with Tavily for the web."], 4.5),
    ("The problem", ["A vendor threat report lands. A detection engineer spends the afternoon", "turning it into SIEM rules, guessing field names, and nobody tests them.", "", "RuleSmith does it in minutes and proves every rule before you see it."], 6.0),
]
CLOSING = [
    ("Five reports, 25 rules", ["15 validated under the strict definition (60%), 9 on the first try.", "0 false positives on 2,390 benign baseline events.", "187 red-team evasion variants. $0.73 and seven minutes for all five.", "", "The rest ship as needs-review with the exact failing test attached."], 7.0),
    ("RuleSmith", ["Open source, MIT.", "Nemotron 3.5 Lightning extracts. Nemotron 3 Super writes and refines.", "Nemotron 3 Ultra plans and red-teams. All served by Nebius Token Factory.", "", "github.com/Arekkusul/nebius-nvidia-hackathon"], 6.0),
]


def font(size: int) -> ImageFont.FreeTypeFont:
    """Load the first TrueType font found on the system at ``size`` points."""
    for p in FONT_CANDIDATES:
        if Path(p).exists():
            return ImageFont.truetype(p, size)
    raise SystemExit("no TrueType font found; install fonts-dejavu")


def title_card(w: int, h: int, headline: str, lines: list[str]) -> Image.Image:
    """Dark card with a green headline, matching the UI's palette."""
    im = Image.new("RGB", (w, h), (11, 15, 20))
    d = ImageDraw.Draw(im)
    # Layout: a small "RS" badge above the headline, then the body lines 44 px apart, all centred.
    d.rounded_rectangle((w // 2 - 36, h // 2 - 200, w // 2 + 36, h // 2 - 128), radius=16, fill=(16, 185, 129))
    d.text((w // 2, h // 2 - 164), "RS", font=font(30), fill=(6, 43, 30), anchor="mm")
    d.text((w // 2, h // 2 - 70), headline, font=font(54), fill=(52, 211, 153), anchor="mm")
    y = h // 2 + 10
    for line in lines:
        d.text((w // 2, y), line, font=font(28), fill=(230, 237, 243), anchor="mm")
        y += 44
    return im


def captioned(frame: Image.Image, caption: str, w: int, h: int) -> Image.Image:
    """Screen frame with a translucent caption bar along the bottom."""
    im = frame.convert("RGB").resize((w, h), Image.LANCZOS)
    if not caption:
        return im
    overlay = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(overlay)
    f = font(26)
    # Wrap to the bar width: 60 px margin on either side, 36 px per line of 26 pt text.
    words, lines, cur = caption.split(), [], ""
    for word in words:
        trial = f"{cur} {word}".strip()
        if d.textlength(trial, font=f) > w - 120:
            lines.append(cur)
            cur = word
        else:
            cur = trial
    lines.append(cur)
    bar_h = 28 + 36 * len(lines)
    d.rectangle((0, h - bar_h, w, h), fill=(11, 15, 20, 215))
    y = h - bar_h + 14
    for line in lines:
        d.text((60, y), line, font=f, fill=(230, 237, 243))
        y += 36
    return Image.alpha_composite(im.convert("RGBA"), overlay).convert("RGB")


def main() -> None:
    """Compose the frame sequence and stream it through ffmpeg into the WebM."""
    parser = argparse.ArgumentParser(description="Assemble the demo video from recorded frames.")
    parser.add_argument("frames", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--width", type=int, default=1280)
    parser.add_argument("--height", type=int, default=720)
    args = parser.parse_args()
    manifest = json.loads((args.frames / "manifest.json").read_text(encoding="utf-8"))
    ffmpeg = next((p for p in FFMPEG_CANDIDATES if p and Path(p).exists()), None)
    if ffmpeg is None:
        raise SystemExit("ffmpeg not found")
    w, h = args.width, args.height

    # Sequence of (image, seconds): title cards, screen frames, closing cards.
    seq: list[tuple[Image.Image, float]] = [(title_card(w, h, head, lines), secs) for head, lines, secs in OPENING]
    for entry in manifest["frames"]:
        seq.append((captioned(Image.open(args.frames / entry["file"]), entry["caption"], w, h), entry["ms"] / 1000))
    seq += [(title_card(w, h, head, lines), secs) for head, lines, secs in CLOSING]
    total = sum(s for _, s in seq)

    # Frames are decoded and composed with Pillow (captions burned in, title cards drawn) and
    # handed to ffmpeg as raw RGB over stdin, so ffmpeg only encodes: no temp files, no image
    # demuxer, and the per-segment timing is controlled here rather than by -framerate.
    # libvpx (VP8) is the encoder the Playwright ffmpeg has; -auto-alt-ref 0 keeps the stream
    # simple, -crf 10 keeps the small caption text legible, deadline/cpu-used is the usual
    # speed-versus-quality middle ground.
    cmd = [ffmpeg, "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{w}x{h}", "-r", str(FPS), "-i", "-",
           "-c:v", "libvpx", "-b:v", "2500k", "-crf", "10", "-auto-alt-ref", "0", "-deadline", "good", "-cpu-used", "2", str(args.out)]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)
    assert proc.stdin is not None
    carry = 0.0  # fractional frames carried between segments so timing stays exact
    for im, secs in seq:
        n_frames = secs * FPS + carry
        count = int(n_frames)
        carry = n_frames - count
        data = im.tobytes()
        for _ in range(count):
            proc.stdin.write(data)
    proc.stdin.close()
    if proc.wait() != 0:
        raise SystemExit("ffmpeg failed")
    print(f"wrote {args.out}: {total:.0f}s, {len(seq)} segments, {args.out.stat().st_size / 1024 / 1024:.1f} MB")


if __name__ == "__main__":
    main()
