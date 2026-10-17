"""Benchmark RuleSmith on the bundled example reports.

    python eval/run_eval.py                 # live: needs NEBIUS_API_KEY
    python eval/run_eval.py --record        # also save runs to examples/runs/<id>.json for replay mode
    python eval/run_eval.py --replay        # score the recorded runs instead of calling the model

Writes eval/results.md (markdown table for the README) and eval/results.json.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from rulesmith.config import Settings  # noqa: E402
from rulesmith.ingest import list_examples  # noqa: E402
from rulesmith.llm import TokenFactoryLLM  # noqa: E402
from rulesmith.models import RunResult  # noqa: E402
from rulesmith.pipeline import Pipeline, RunInput, load_run  # noqa: E402

RUNS_DIR = ROOT / "examples" / "runs"
OUT_MD = ROOT / "eval" / "results.md"
OUT_JSON = ROOT / "eval" / "results.json"


def score(result: RunResult) -> dict:
    """Headline metrics for one run."""
    s = result.stats()
    tiers = result.metrics.by_tier()
    return {
        "example": "",
        "title": result.report.title,
        "behaviors": s["behaviors"],
        "rules": s["rules"],
        "validated": s["validated"],
        "needs_review": s["needs_review"],
        "failed": s["failed"],
        "positive_recall": s["positive_recall"],
        "negative_precision": s["negative_precision"],
        "benign_hits": s["benign_hits"],
        "first_try_pass": sum(1 for r in result.rules if r.history and r.history[0].passed),
        "iterations": s["iterations"],
        "redteam_variants": sum(1 for r in result.rules for t in r.tests if t.id.startswith("R")),
        "prompt_tokens": s["prompt_tokens"],
        "completion_tokens": s["completion_tokens"],
        "cost_usd": s["cost_usd"],
        "model_time_s": s["latency_s"],
        "wall_s": 0.0,
        "tiers": {k: {"calls": v["calls"], "cost_usd": v["cost_usd"]} for k, v in tiers.items()},
        "models": result.models,
    }


def fmt_pct(v):  # type: ignore[no-untyped-def]
    return "n/a" if v is None else f"{v * 100:.0f}%"


def write_table(rows: list[dict]) -> str:
    head = "| Report | Behaviours | Rules | Validated | First-try pass | Attack events caught | Benign look-alikes blocked | Baseline FPs | Refine cycles | Red-team variants | Tokens in/out | Est. cost | Wall time |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|\n"
    body = "".join(
        f"| {r['example']} | {r['behaviors']} | {r['rules']} | {r['validated']} | {r['first_try_pass']} | {fmt_pct(r['positive_recall'])} | {fmt_pct(r['negative_precision'])} | {r['benign_hits']} | {r['iterations'] - r['rules']} | {r['redteam_variants']} | {r['prompt_tokens']:,}/{r['completion_tokens']:,} | ${r['cost_usd']:.3f} | {r['wall_s']:.0f}s |\n"
        for r in rows
    )
    if rows:
        tot_rules = sum(r["rules"] for r in rows)
        tot_val = sum(r["validated"] for r in rows)
        tot_cost = sum(r["cost_usd"] for r in rows)
        body += f"| **Total** | {sum(r['behaviors'] for r in rows)} | {tot_rules} | {tot_val} ({tot_val / tot_rules * 100:.0f}%) | {sum(r['first_try_pass'] for r in rows)} | | | {sum(r['benign_hits'] for r in rows)} | {sum(r['iterations'] - r['rules'] for r in rows)} | {sum(r['redteam_variants'] for r in rows)} | {sum(r['prompt_tokens'] for r in rows):,}/{sum(r['completion_tokens'] for r in rows):,} | ${tot_cost:.3f} | {sum(r['wall_s'] for r in rows):.0f}s |\n"
    return head + body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--examples", nargs="*", help="example ids (default: all)")
    ap.add_argument("--record", action="store_true", help="save runs for replay mode")
    ap.add_argument("--replay", action="store_true", help="score recorded runs instead of calling the model")
    ap.add_argument("--max-rules", type=int, default=5)
    ap.add_argument("--iterations", type=int, default=3)
    args = ap.parse_args()

    ids = args.examples or [e["id"] for e in list_examples()]
    rows: list[dict] = []
    if args.replay:
        for ex in ids:
            path = RUNS_DIR / f"{ex}.json"
            if not path.exists():
                print(f"skip {ex}: no recorded run", file=sys.stderr)
                continue
            result = load_run(path)
            row = score(result)
            row["example"] = ex
            rows.append(row)
    else:
        settings = Settings.from_env()
        if not settings.has_llm:
            print("NEBIUS_API_KEY not set", file=sys.stderr)
            return 2
        llm = TokenFactoryLLM(settings)
        pipeline = Pipeline(settings, llm, on_event=lambda e: print(f"  {e['stage']}: {e['message']}", file=sys.stderr) if e["type"] != "rule" else print(f"    [{e['stage']}] {e['message']}", file=sys.stderr))
        for ex in ids:
            print(f"== {ex}", file=sys.stderr)
            t0 = time.perf_counter()
            result = pipeline.run(RunInput(mode="example", value=ex, max_rules=args.max_rules, max_refine_iterations=args.iterations))
            wall = time.perf_counter() - t0
            row = score(result)
            row["example"] = ex
            row["wall_s"] = round(wall, 1)
            rows.append(row)
            if args.record:
                RUNS_DIR.mkdir(parents=True, exist_ok=True)
                (RUNS_DIR / f"{ex}.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
                print(f"  recorded -> examples/runs/{ex}.json", file=sys.stderr)

    table = write_table(rows)
    OUT_MD.write_text(f"# Eval results\n\nGenerated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}. Models: {json.dumps(rows[0]['models']) if rows else 'n/a'}\n\n{table}", encoding="utf-8")
    OUT_JSON.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
