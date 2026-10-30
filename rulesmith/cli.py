"""Command-line interface.

    rulesmith run --example macro_loader_campaign
    rulesmith run --url https://vendor.example/report --out ./pack
    rulesmith run --text-file report.md --max-rules 4 --no-redteam
    rulesmith replay macro_loader_campaign --out ./pack   # no key needed
    rulesmith serve --port 7860 --open
    rulesmith examples
    rulesmith models

The CLI is the thin front door of the pipeline (ingest -> extract -> plan ->
author -> validate -> refine -> red-team -> package): it builds a ``RunInput``,
hands it to ``Pipeline`` and prints or writes whatever comes back.
"""

from __future__ import annotations

import argparse
import logging
import sys
import threading
import time
import webbrowser
from pathlib import Path

from .config import Settings
from .ingest import list_examples
from .llm import TokenFactoryLLM
from .models import RunResult
from .package import build_zip, markdown_report
from .pipeline import RECORDED_RUNS_DIR, Pipeline, PipelineError, RunInput, load_run, recorded_run_path

KEY_HELP = "NEBIUS_API_KEY is not set. Get a key at https://tokenfactory.nebius.com, put it in .env or export it, then retry."


def _progress_printer():  # type: ignore[no-untyped-def]
    """Progress lines for terminals, each stamped with the seconds since the run started.

    Stage lines are left-aligned, per-rule lines are indented under them, so a
    five-rule run reads as a short tree rather than an undifferentiated log.
    """
    t0 = time.perf_counter()

    def _print(evt: dict) -> None:
        stamp = f"[{time.perf_counter() - t0:6.1f}s]"
        t = evt.get("type")
        if t == "stage":
            print(f"{stamp} {evt['stage']:<8} {evt['message']}", file=sys.stderr)
        elif t == "rule":
            print(f"{stamp}   {evt['stage']:<4} {evt.get('status', ''):<12} {evt['message']}", file=sys.stderr)
        elif t in ("done", "error"):
            print(f"{stamp} {t:<8} {evt['message']}", file=sys.stderr)

    return _print


def _write_pack(result: RunResult, out: Path) -> None:
    """Write the zip, the raw run JSON and the markdown report into ``out``."""
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{result.run_id}.zip").write_bytes(build_zip(result))
    (out / f"{result.run_id}.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
    (out / f"{result.run_id}.md").write_text(markdown_report(result), encoding="utf-8")
    print(f"wrote {out / result.run_id}.{{zip,json,md}}", file=sys.stderr)


def _emit_result(result: RunResult, args: argparse.Namespace) -> None:
    """Shared tail of ``run`` and ``replay``: optional pack on disk, report or JSON on stdout, one-line summary."""
    if args.out:
        _write_pack(result, Path(args.out))
    print(result.model_dump_json(indent=2) if args.json else markdown_report(result))
    stats = result.stats()
    print(f"\n{stats['validated']}/{stats['rules']} rules validated · ${stats['cost_usd']:.4f} · {stats['latency_s']}s model time", file=sys.stderr)


def cmd_run(args: argparse.Namespace) -> int:
    """Run the full pipeline on one report and print the resulting detection pack.

    Exit codes: 0 on success, 1 when the pipeline fails part-way, 2 for a
    usage problem (no API key, no input source).
    """
    settings = Settings.from_env()
    if not settings.has_llm:
        print(KEY_HELP, file=sys.stderr)
        return 2
    # argparse makes the four sources mutually exclusive but not required,
    # hence the explicit "provide one of" error at the end of this chain.
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
    # None leaves the Settings default in place; --no-redteam always decides for itself.
    inp.max_rules = args.max_rules
    inp.max_refine_iterations = args.iterations
    inp.enable_redteam = not args.no_redteam

    llm = TokenFactoryLLM(settings)
    pipeline = Pipeline(settings, llm, on_event=None if args.quiet else _progress_printer())
    try:
        result = pipeline.run(inp)
    except PipelineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    _emit_result(result, args)
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    """Re-package a recorded run: the same outputs as ``run``, no model calls, no key."""
    path = recorded_run_path(args.run_id)
    if path is None:
        ids = ", ".join(sorted(p.stem for p in RECORDED_RUNS_DIR.glob("*.json"))) or "(none)"
        print(f"No recorded run named '{args.run_id}'. Available: {ids}", file=sys.stderr)
        return 2
    _emit_result(load_run(path), args)
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    """Start the web UI with uvicorn after printing what this environment can do."""
    import uvicorn

    settings = Settings.from_env()
    # A bind-all address is not something a browser can open, so the banner
    # and --open point at loopback instead.
    url = f"http://{'127.0.0.1' if args.host in ('0.0.0.0', '::') else args.host}:{args.port}"
    recorded = len(list(RECORDED_RUNS_DIR.glob("*.json")))
    # A short banner so the first run of `rulesmith serve` tells you what works before you open the page.
    print(f"RuleSmith UI: {url}", file=sys.stderr)
    print(f"  live runs:     {'enabled (NEBIUS_API_KEY set)' if settings.has_llm else 'disabled, no NEBIUS_API_KEY (recorded runs still play)'}", file=sys.stderr)
    print(f"  Tavily:        {'enabled' if settings.has_tavily else 'not configured (URL fetch still works, search is off)'}", file=sys.stderr)
    print(f"  recorded runs: {recorded}", file=sys.stderr)
    if args.open:
        # Open the browser once the server has had a moment to bind the port.
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    uvicorn.run("rulesmith.server.app:app", host=args.host, port=args.port, reload=args.reload, log_level="info")
    return 0


def cmd_models(args: argparse.Namespace) -> int:
    """Show which Nemotron model each tier resolves to, plus the NVIDIA models in the catalog."""
    settings = Settings.from_env()
    if not settings.has_llm:
        print(KEY_HELP, file=sys.stderr)
        return 2
    llm = TokenFactoryLLM(settings)
    available = llm.list_models()
    resolved = llm.resolve_models()
    print("Nemotron tiers:")
    for tier, model in resolved.items():
        print(f"  {tier:<10} {model}")
    print(f"\nNVIDIA models in the Token Factory catalog ({len(available)} total models):")
    # The catalog lists every provider on Token Factory; only NVIDIA/Nemotron
    # entries matter when choosing a tier model.
    for m in sorted(available):
        if "nvidia" in m.lower() or "nemotron" in m.lower():
            print(f"  {m}")
    return 0


def cmd_examples(args: argparse.Namespace) -> int:
    """List bundled reports and recorded runs, and which ids work with which command."""
    recorded = {p.stem for p in RECORDED_RUNS_DIR.glob("*.json")}
    examples = list_examples()
    print("Bundled reports (rulesmith run --example <id>):")
    for ex in examples:
        print(f"  {ex['id']:<34} {ex['title']}" + ("   [recorded run available]" if ex["id"] in recorded else ""))
    extra = sorted(recorded - {ex["id"] for ex in examples})
    if extra:
        print("\nRecorded runs of real reports (rulesmith replay <id>):")
        for rid in extra:
            print(f"  {rid:<34} {load_run(RECORDED_RUNS_DIR / f'{rid}.json').report.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse tree: run, replay, serve, models and examples."""
    p = argparse.ArgumentParser(prog="rulesmith", description="Threat intel in, tested Sigma rules out.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def output_flags(cmd: argparse.ArgumentParser) -> None:
        """Flags shared by ``run`` and ``replay``, which produce the same outputs."""
        cmd.add_argument("--out", help="directory to write the zip, json and markdown pack")
        cmd.add_argument("--json", action="store_true", help="print the full run JSON instead of the markdown report")

    r = sub.add_parser("run", help="analyse a report and produce a detection pack (needs NEBIUS_API_KEY)")
    src = r.add_mutually_exclusive_group()
    src.add_argument("--example", help="bundled example id (see `rulesmith examples`)")
    src.add_argument("--url", action="append", help="report URL (repeatable)")
    src.add_argument("--query", help="search query, e.g. 'Qilin ransomware TTPs' (needs TAVILY_API_KEY)")
    src.add_argument("--text-file", help="path to a text/markdown report")
    output_flags(r)
    r.add_argument("--max-rules", type=int, default=None)
    r.add_argument("--iterations", type=int, default=None, help="max refine iterations per rule")
    r.add_argument("--no-redteam", action="store_true")
    r.add_argument("--quiet", action="store_true", help="no progress lines on stderr")
    r.set_defaults(func=cmd_run)

    rp = sub.add_parser("replay", help="re-package a recorded run from examples/runs (no key, no model calls)")
    rp.add_argument("run_id", help="recorded run id (see `rulesmith examples`)")
    output_flags(rp)
    rp.set_defaults(func=cmd_replay)

    s = sub.add_parser("serve", help="start the web UI")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=7860)
    s.add_argument("--reload", action="store_true")
    s.add_argument("--open", action="store_true", help="open the UI in your browser once the server is up")
    s.set_defaults(func=cmd_serve)

    m = sub.add_parser("models", help="show which Nemotron models each tier resolves to")
    m.set_defaults(func=cmd_models)

    e = sub.add_parser("examples", help="list bundled example reports and recorded runs")
    e.set_defaults(func=cmd_examples)
    return p


def main(argv: list[str] | None = None) -> int:
    """Entry point: parse ``argv`` (``sys.argv`` by default), dispatch, return the exit code."""
    # Progress reaches the terminal through the event printer, so logging only
    # needs to surface warnings and errors from the libraries underneath.
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
