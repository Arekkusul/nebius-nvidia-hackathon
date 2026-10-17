"""Command-line interface.

    rulesmith run --example macro_loader_campaign
    rulesmith run --url https://vendor.example/report --out ./pack
    rulesmith run --text-file report.md --max-rules 4 --no-redteam
    rulesmith serve --port 7860
    rulesmith models
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from .config import Settings
from .ingest import list_examples
from .llm import TokenFactoryLLM
from .package import build_zip, markdown_report
from .pipeline import Pipeline, PipelineError, RunInput


def _print_event(evt: dict) -> None:
    """Compact progress line for terminals."""
    t = evt.get("type")
    if t == "stage":
        print(f"[{evt['stage']:<8}] {evt['message']}", file=sys.stderr)
    elif t == "rule":
        print(f"  ({evt['stage']}) {evt.get('status', ''):<12} {evt['message']}", file=sys.stderr)
    elif t in ("done", "error"):
        print(f"[{t}] {evt['message']}", file=sys.stderr)


def cmd_run(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    if not settings.has_llm:
        print("NEBIUS_API_KEY is not set. Get a key at https://tokenfactory.nebius.com and export it.", file=sys.stderr)
        return 2
    if args.example:
        inp = RunInput(mode="example", value=args.example)
    elif args.url:
        inp = RunInput(mode="url", urls=args.url)
    elif args.query:
        inp = RunInput(mode="query", value=args.query)
    elif args.text_file:
        inp = RunInput(mode="text", value=Path(args.text_file).read_text(encoding="utf-8"))
    else:
        print("Provide one of --example, --url, --query or --text-file", file=sys.stderr)
        return 2
    inp.max_rules = args.max_rules
    inp.max_refine_iterations = args.iterations
    inp.enable_redteam = not args.no_redteam

    llm = TokenFactoryLLM(settings)
    pipeline = Pipeline(settings, llm, on_event=_print_event if not args.quiet else None)
    try:
        result = pipeline.run(inp)
    except PipelineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    out = Path(args.out) if args.out else None
    if out:
        out.mkdir(parents=True, exist_ok=True)
        (out / f"{result.run_id}.zip").write_bytes(build_zip(result))
        (out / f"{result.run_id}.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
        (out / f"{result.run_id}.md").write_text(markdown_report(result), encoding="utf-8")
        print(f"wrote {out / result.run_id}.{{zip,json,md}}", file=sys.stderr)
    if args.json:
        print(result.model_dump_json(indent=2))
    else:
        print(markdown_report(result))
    stats = result.stats()
    print(f"\n{stats['validated']}/{stats['rules']} rules validated · ${stats['cost_usd']:.4f} · {stats['latency_s']}s model time", file=sys.stderr)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run("rulesmith.server.app:app", host=args.host, port=args.port, reload=args.reload, log_level="info")
    return 0


def cmd_models(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    if not settings.has_llm:
        print("NEBIUS_API_KEY is not set.", file=sys.stderr)
        return 2
    llm = TokenFactoryLLM(settings)
    available = llm.list_models()
    resolved = llm.resolve_models()
    print("Nemotron tiers:")
    for tier, model in resolved.items():
        print(f"  {tier:<10} {model}")
    print(f"\nNVIDIA models in the Token Factory catalog ({len(available)} total models):")
    for m in sorted(available):
        if "nvidia" in m.lower() or "nemotron" in m.lower():
            print(f"  {m}")
    return 0


def cmd_examples(args: argparse.Namespace) -> int:
    for ex in list_examples():
        print(f"{ex['id']:<32} {ex['title']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="rulesmith", description="Threat intel in, tested Sigma rules out.")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="analyse a report and produce a detection pack")
    src = r.add_mutually_exclusive_group()
    src.add_argument("--example", help="bundled example id (see `rulesmith examples`)")
    src.add_argument("--url", action="append", help="report URL (repeatable)")
    src.add_argument("--query", help="search query, e.g. 'Qilin ransomware TTPs' (needs TAVILY_API_KEY)")
    src.add_argument("--text-file", help="path to a text/markdown report")
    r.add_argument("--out", help="directory to write the zip, json and markdown pack")
    r.add_argument("--max-rules", type=int, default=None)
    r.add_argument("--iterations", type=int, default=None, help="max refine iterations per rule")
    r.add_argument("--no-redteam", action="store_true")
    r.add_argument("--json", action="store_true", help="print the full run JSON instead of the markdown report")
    r.add_argument("--quiet", action="store_true")
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("serve", help="start the web UI")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=7860)
    s.add_argument("--reload", action="store_true")
    s.set_defaults(func=cmd_serve)

    m = sub.add_parser("models", help="show which Nemotron models each tier resolves to")
    m.set_defaults(func=cmd_models)

    e = sub.add_parser("examples", help="list bundled example reports")
    e.set_defaults(func=cmd_examples)
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
