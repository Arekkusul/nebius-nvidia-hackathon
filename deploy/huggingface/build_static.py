"""Build a static, replay-only copy of the RuleSmith UI.

Hugging Face hosts static Spaces for free, while Docker Spaces need a PRO
subscription. This script turns the normal front-end into a self-contained
site: the same index.html/app.js/style.css, a replays/ folder with the
recorded runs (JSON) and their downloadable packs (zip), and the Space card.

    python deploy/huggingface/build_static.py [out_dir] [--zips] [--exclude ID,ID]
    # default out_dir: deploy/huggingface/static_site; --exclude leaves listed runs out

Upload the output directory to a Space created with sdk: static.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from rulesmith.package import build_zip
from rulesmith.pipeline import RECORDED_RUNS_DIR, load_run

STATIC_SRC = ROOT / "rulesmith" / "server" / "static"
RUNS_DIR = RECORDED_RUNS_DIR

CARD = """---
title: RuleSmith
emoji: 🛡️
colorFrom: green
colorTo: gray
sdk: static
pinned: false
license: mit
short_description: Threat intel in, tested Sigma rules out. Nemotron on Nebius.
---

# RuleSmith (static demo)

Replay of real runs of an autonomous detection-engineering agent built on NVIDIA Nemotron via Nebius Token Factory.
This static copy serves the recorded runs; to run the agent live, clone the repository and set `NEBIUS_API_KEY`.

Source and documentation: https://github.com/Arekkusul/nebius-nvidia-hackathon
"""


# Characters per replay part file. A full run is over 100 KB of JSON, above the per-write
# limit of the upload tools used to publish the Space; 20 KB parts go through reliably and
# fetchReplay() in app.js joins them back together before parsing.
PART_CHARS = 20_000


def slim_run(run: dict) -> dict:
    """Keep only what app.js reads from a run (see renderResult/renderRule/replay)."""
    report = run["report"]
    return {
        "run_id": run["run_id"],
        "created_at": run["created_at"],
        "source": {"chars": run["source"]["chars"], "tavily_used": run["source"]["tavily_used"]},
        "models": run["models"],
        "warnings": run.get("warnings", []),
        "report": {
            "title": report["title"],
            "iocs": [{"type": i["type"], "value": i["value"]} for i in report.get("iocs", [])],
            "behaviors": [
                {k: b[k] for k in ("id", "description", "attack_technique_id", "attack_tactic", "confidence", "detectable", "evidence")}
                for b in report.get("behaviors", [])
            ],
        },
        "plan": {
            "candidates": [
                {k: c[k] for k in ("id", "title", "behavior_ids", "attack_technique_ids", "logsource", "priority", "key_fields")}
                for c in run["plan"]["candidates"]
            ],
            "skipped": run["plan"].get("skipped", []),
        },
        "rules": [
            {
                "candidate_id": r["candidate_id"],
                "title": r["title"],
                "status": r["status"],
                "attack_technique_ids": r["attack_technique_ids"],
                "sigma_yaml": r["sigma_yaml"],
                "tests": r["tests"],
                "validation": {k: r["validation"][k] for k in ("parse_ok", "issues", "test_outcomes", "positives_total", "positives_matched", "negatives_total", "negatives_matched", "benign_total", "benign_hits", "benign_examples", "passed")},
                # The SQLite query duplicates the validator's SQL; the other targets are what analysts deploy.
                "conversions": {k: v for k, v in r["conversions"].items() if k != "sqlite"},
                "conversion_errors": r["conversion_errors"],
                "history": r["history"],
                "author_notes": r["author_notes"],
                "redteam_analysis": r["redteam_analysis"],
                "retired_tests": r.get("retired_tests", []),
                "replaced_tests": r.get("replaced_tests", []),
                "redteam_out_of_scope": r.get("redteam_out_of_scope", []),
            }
            for r in run["rules"]
        ],
        "metrics": {"calls": [{k: c[k] for k in ("tier", "model", "prompt_tokens", "completion_tokens", "cost_usd", "latency_s")} for c in run["metrics"]["calls"]]},
    }


def main(out_dir: Path, with_zips: bool = False, exclude: set[str] | None = None) -> None:
    """Write the site: patched index.html, static assets, split replays and the Space card."""
    exclude = exclude or set()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    (out_dir / "static").mkdir(parents=True)
    (out_dir / "replays").mkdir()

    # index.html: relative asset paths and the static flag, nothing else changes.
    html = (STATIC_SRC / "index.html").read_text(encoding="utf-8")
    html = html.replace('href="/static/style.css"', 'href="static/style.css"')
    html = html.replace('<script src="/static/app.js"></script>', '<script>window.RULESMITH_STATIC = true;</script>\n  <script src="static/app.js"></script>')
    (out_dir / "index.html").write_text(html, encoding="utf-8")
    shutil.copy(STATIC_SRC / "app.js", out_dir / "static" / "app.js")
    shutil.copy(STATIC_SRC / "style.css", out_dir / "static" / "style.css")
    if (STATIC_SRC / "og.jpg").exists():  # link-preview image referenced from the og:image tag
        shutil.copy(STATIC_SRC / "og.jpg", out_dir / "static" / "og.jpg")
    # Favicons and the top-bar mark, cropped from the RuleSmith logo.
    for name in ("favicon-32.png", "apple-touch-icon.png", "logo.png", "favicon.ico"):
        if (STATIC_SRC / name).exists():
            shutil.copy(STATIC_SRC / name, out_dir / "static" / name)

    # Recorded runs: only the fields the front-end renders, as compact JSON,
    # split into small part files (replays/<id>.part0.json ...) that the UI
    # concatenates. Small parts upload reliably through size-limited channels.
    index = []
    for path in sorted(RUNS_DIR.glob("*.json")):
        if path.stem in exclude:  # keep the published index in step with what is uploaded
            continue
        result = load_run(path)
        slim = slim_run(json.loads(result.model_dump_json()))
        text = json.dumps(slim, separators=(",", ":"), ensure_ascii=False)
        parts = [text[i : i + PART_CHARS] for i in range(0, len(text), PART_CHARS)]
        for n, chunk in enumerate(parts):
            (out_dir / "replays" / f"{path.stem}.part{n}.json").write_text(chunk, encoding="utf-8")
        if with_zips:
            (out_dir / "replays" / f"{path.stem}.zip").write_bytes(build_zip(result))
        index.append({"id": path.stem, "title": result.report.title, "rules": len(result.rules), "validated": result.stats()["validated"], "created_at": result.created_at, "parts": len(parts), "zip": with_zips})
    (out_dir / "replays" / "index.json").write_text(json.dumps(index), encoding="utf-8")
    (out_dir / "README.md").write_text(CARD, encoding="utf-8")
    total = sum(p.stat().st_size for p in out_dir.rglob("*") if p.is_file())
    print(f"built {out_dir} ({len(index)} replays, {total / 1024:.0f} KB)")


if __name__ == "__main__":
    # Hand-rolled argv handling: one optional positional and two flags did not justify argparse.
    argv = sys.argv[1:]
    # --exclude takes a comma-separated list of run ids (file stems under examples/runs/).
    excluded: set[str] = set()
    if "--exclude" in argv:
        at = argv.index("--exclude")
        excluded = {x for x in argv[at + 1].split(",") if x}
        del argv[at : at + 2]
    args = [a for a in argv if not a.startswith("--")]
    main(Path(args[0]) if args else ROOT / "deploy" / "huggingface" / "static_site", with_zips="--zips" in argv, exclude=excluded)
