"""HTTP API + static UI.

This is the server layer: it wraps :class:`rulesmith.pipeline.Pipeline`
(ingest -> extract -> plan -> author -> validate -> refine -> red-team ->
package) in a FastAPI app and serves the vanilla JS front end.

Runs execute in a background thread; progress is streamed to the browser
over Server-Sent Events so the judges can watch Nemotron plan, write, test
and harden each rule in real time.

Route groups (all defined inside ``create_app``):

* page/static        ``GET /`` and ``/static/*``: the single-page UI.
* health + examples  ``GET /api/health``, ``GET /api/examples``: what this
                     deployment can do and which bundled reports it ships.
* live runs + SSE    ``POST /api/runs`` starts a run; ``GET /api/runs/{id}``
                     polls it; ``.../events`` streams progress; ``.../download``,
                     ``.../report.md`` and ``.../navigator.json`` package it.
* recorded replays   ``GET /api/replays[/{id}[/download|/report.md|/navigator.json]]``:
                     the same outputs for runs shipped in ``examples/runs``, which
                     work without an API key.

Run state lives in process memory only (see :class:`RunManager`), so a
restart forgets every live run; the recorded replays are the durable path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..config import Settings
from ..ingest import list_examples
from ..llm import BaseLLM, TokenFactoryLLM
from ..models import RunResult
from ..package import build_zip, markdown_report, navigator_layer
from ..pipeline import RECORDED_RUNS_DIR, Pipeline, PipelineError, RunInput, load_run, recorded_run_path

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
REPLAYS_DIR = RECORDED_RUNS_DIR
# Each run already fans out over a per-candidate thread pool and the demo runs
# on small hosts, so a low cap keeps one visitor's run from starving another.
MAX_CONCURRENT_RUNS = 2
# Finished runs stay downloadable for an hour, then are garbage-collected.
RUN_TTL_S = 3600


class StartRun(BaseModel):
    """Request body for POST /api/runs."""

    mode: str = Field(pattern="^(url|text|query|example)$")
    value: str = ""
    urls: list[str] = Field(default_factory=list)
    max_rules: int | None = Field(default=None, ge=1, le=10)
    max_refine_iterations: int | None = Field(default=None, ge=0, le=5)
    enable_redteam: bool | None = None


@dataclass
class RunState:
    """Bookkeeping for one in-flight or finished run.

    ``events`` is the full history (so a client that connects late, or
    reconnects, can catch up); ``queue`` is the live feed the SSE generator
    blocks on. A ``None`` on the queue is the sentinel for "run finished".
    """

    id: str
    events: list[dict[str, Any]] = field(default_factory=list)
    queue: queue.Queue[dict[str, Any] | None] = field(default_factory=queue.Queue)
    result: RunResult | None = None
    error: str | None = None
    done: bool = False
    started: float = field(default_factory=time.time)


class RunManager:
    """Owns background runs and fans events out to SSE subscribers.

    Everything here is in-memory: the run table, the rate-limit window and the
    demo budget all reset when the process restarts. That is deliberate for a
    hackathon demo (no database to provision), and the per-hour rate limits
    bound the spend even on hosts that restart the process when it idles.
    All public methods are safe to call from any thread.
    """

    def __init__(self, pipeline_factory, *, budget_usd: float = 0.0, reserve_usd: float = 0.30, runs_per_hour: int = 0, runs_per_ip_per_hour: int = 0) -> None:  # type: ignore[no-untyped-def]
        self.pipeline_factory = pipeline_factory
        self.runs: dict[str, RunState] = {}
        self._lock = threading.Lock()
        # Rolling one-hour window of (start time, client address) for every live run
        # started, used for the per-process and per-client rate limits (0 = unlimited).
        self.runs_per_hour = runs_per_hour
        self.runs_per_ip_per_hour = runs_per_ip_per_hour
        self._starts: list[tuple[float, str]] = []
        # Spend cap for a public demo: 0 means uncapped. Each in-flight run
        # reserves ``reserve_usd`` (about the cost of a three-rule run) until
        # its real cost is known, so a burst of visitors cannot overshoot.
        self.budget_usd = budget_usd
        self.reserve_usd = reserve_usd
        self.spent_usd = 0.0

    def active(self) -> int:
        """Count the runs that are still executing."""
        with self._lock:
            return sum(1 for r in self.runs.values() if not r.done)

    def budget(self) -> dict[str, float] | None:
        """Budget status for the health endpoint, or None when uncapped."""
        if not self.budget_usd:
            return None
        with self._lock:
            reserved = sum(self.reserve_usd for r in self.runs.values() if not r.done)
            spent = self.spent_usd
        return {"limit_usd": self.budget_usd, "spent_usd": round(spent, 4), "remaining_usd": round(max(0.0, self.budget_usd - spent - reserved), 4)}

    def _charge(self, result: RunResult | None) -> None:
        """Add a finished run's estimated cost to the demo spend."""
        if result is not None:
            with self._lock:
                self.spent_usd += float(result.stats().get("cost_usd", 0.0))

    def _gc(self) -> None:
        """Forget finished runs older than ``RUN_TTL_S`` so memory stays bounded."""
        cutoff = time.time() - RUN_TTL_S
        with self._lock:
            for rid in [k for k, v in self.runs.items() if v.done and v.started < cutoff]:
                del self.runs[rid]

    def _check_rate(self, client: str) -> None:
        """Refuse a run that would exceed the hourly limits; records the start otherwise."""
        now = time.time()
        with self._lock:
            self._starts = [(t, c) for t, c in self._starts if now - t < 3600]
            if self.runs_per_hour and len(self._starts) >= self.runs_per_hour:
                raise HTTPException(status_code=429, detail=f"This demo allows {self.runs_per_hour} live runs per hour and the hour is used up; try again later, or play a recorded run.")
            if self.runs_per_ip_per_hour and sum(1 for _, c in self._starts if c == client) >= self.runs_per_ip_per_hour:
                raise HTTPException(status_code=429, detail=f"This demo allows {self.runs_per_ip_per_hour} live runs per hour per visitor; try again later, or play a recorded run.")
            self._starts.append((now, client))

    def start(self, inp: RunInput, client: str = "") -> RunState:
        """Admit a run, launch it on a daemon thread and return its state immediately.

        Raises HTTP 429 when the concurrency cap, an hourly rate limit or the
        demo budget would be exceeded. The caller polls or streams the
        returned state; the thread fills it in.
        """
        self._gc()
        if self.active() >= MAX_CONCURRENT_RUNS:
            raise HTTPException(status_code=429, detail="Too many runs in progress; try again in a minute.")
        self._check_rate(client)
        budget = self.budget()
        if budget is not None and budget["remaining_usd"] < self.reserve_usd:
            raise HTTPException(status_code=429, detail=f"This demo's live budget (${self.budget_usd:.2f}) is spent for now; the recorded replays still work, or run RuleSmith locally with your own key.")
        state = RunState(id=uuid.uuid4().hex[:12])
        with self._lock:
            self.runs[state.id] = state

        def on_event(evt: dict[str, Any]) -> None:
            """Record a pipeline event for late subscribers and wake the live stream."""
            state.events.append(evt)
            state.queue.put(evt)

        def work() -> None:
            """Run the pipeline to completion on the background thread.

            A PipelineError is a user-facing message (bad input, nothing
            detectable); anything else is a crash and gets logged with its
            traceback. Both end up as an ``error`` event so the UI can show
            them, and ``done`` plus the queue sentinel are set no matter what
            so the SSE stream always closes.
            """
            try:
                pipeline = self.pipeline_factory(on_event)
                state.result = pipeline.run(inp)
                self._charge(state.result)
            except PipelineError as exc:
                state.error = str(exc)
                on_event({"type": "error", "stage": "error", "message": str(exc), "ts": time.time()})
            except Exception as exc:
                log.exception("run %s crashed", state.id)
                state.error = f"{type(exc).__name__}: {exc}"
                on_event({"type": "error", "stage": "error", "message": state.error, "ts": time.time()})
            finally:
                state.done = True
                state.queue.put(None)

        # Daemon so an in-flight run never blocks process shutdown.
        threading.Thread(target=work, name=f"run-{state.id}", daemon=True).start()
        return state

    def get(self, run_id: str) -> RunState:
        """Look up a run by id, raising HTTP 404 when it is unknown or already garbage-collected."""
        with self._lock:
            state = self.runs.get(run_id)
        if state is None:
            raise HTTPException(status_code=404, detail="Unknown run id")
        return state


def create_app(settings: Settings | None = None, llm: BaseLLM | None = None) -> FastAPI:
    """Application factory (tests inject a FakeLLM)."""
    settings = settings or Settings.from_env()
    app = FastAPI(title="RuleSmith", version=__version__, docs_url="/api/docs", redoc_url=None)

    # One client for the whole process: it caches the resolved model ids and
    # which JSON modes each model accepts, so later runs skip those probes.
    shared_llm: BaseLLM | None = llm
    if shared_llm is None and settings.has_llm:
        shared_llm = TokenFactoryLLM(settings)

    def pipeline_factory(on_event):  # type: ignore[no-untyped-def]
        """Build a fresh Pipeline for one run, wired to that run's event sink.

        Raising PipelineError (rather than refusing at startup) lets a keyless
        deployment still serve the UI and the recorded replays.
        """
        if shared_llm is None:
            raise PipelineError("No NEBIUS_API_KEY configured on this server; use the replay mode or run locally with your key.")
        return Pipeline(settings, shared_llm, on_event=on_event)

    # The rate limits apply only to a public demo (a budget or the example-only lock is set).
    public_demo = bool(settings.demo_budget_usd) or settings.demo_locked
    manager = RunManager(
        pipeline_factory,
        budget_usd=settings.demo_budget_usd,
        runs_per_hour=settings.demo_runs_per_hour if public_demo else 0,
        runs_per_ip_per_hour=settings.demo_runs_per_ip_per_hour if public_demo else 0,
    )
    app.state.settings = settings
    app.state.manager = manager

    # ---------------------------------------------------------------- pages

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index() -> HTMLResponse:
        """Serve the single-page UI."""
        # Read on every request (not cached) so editing the HTML during development shows up on reload.
        return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ------------------------------------------------------------------ api

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        """Report what this deployment can do, so the UI can adapt its controls.

        The front end uses this to hide the live-run form when no key is
        configured, show the budget meter, and label which Nemotron model
        serves each tier.
        """
        models: dict[str, str] = {}
        if shared_llm is not None:
            try:
                models = shared_llm.resolve_models() if hasattr(shared_llm, "resolve_models") else dict(shared_llm.models)
            except Exception as exc:  # noqa: BLE001
                # A catalog outage must not take the health check down with it; the UI just sees no models.
                log.warning("model resolution failed: %s", exc)
        return {
            "version": __version__,
            "llm_configured": shared_llm is not None,
            "tavily_configured": settings.has_tavily,
            "demo_locked": settings.demo_locked,
            "budget": manager.budget(),
            "rate_limits": {"runs_per_hour": manager.runs_per_hour, "runs_per_ip_per_hour": manager.runs_per_ip_per_hour} if manager.runs_per_hour or manager.runs_per_ip_per_hour else None,
            "models": models,
            "active_runs": manager.active(),
        }

    @app.get("/api/examples")
    def examples() -> list[dict[str, str]]:
        """List the bundled example reports the UI offers as one-click inputs."""
        return list_examples()

    @app.get("/api/replays")
    def replays() -> list[dict[str, Any]]:
        """List the recorded runs shipped in the repository, with headline stats for the picker."""
        out = []
        for p in sorted(REPLAYS_DIR.glob("*.json")):
            try:
                r = load_run(p)
                out.append({"id": p.stem, "title": r.report.title, "rules": len(r.rules), "validated": r.stats()["validated"], "created_at": r.created_at})
            except Exception as exc:  # noqa: BLE001
                # One stale recording (schema drift) should not hide the others.
                log.warning("bad replay %s: %s", p, exc)
        return out

    @app.get("/api/replays/{replay_id}")
    def replay(replay_id: str) -> JSONResponse:
        """Return a recorded run as raw JSON; the UI replays it as if it were live. 404 when unknown."""
        path = _replay_path(replay_id)
        # Served verbatim rather than re-validated, so even a recording from an
        # older schema still plays back if the UI can read it.
        return JSONResponse(json.loads(path.read_text(encoding="utf-8")))

    @app.get("/api/replays/{replay_id}/download")
    def replay_download(replay_id: str) -> Response:
        """Package a recorded run as the same zip bundle a live run produces."""
        result = load_run(_replay_path(replay_id))
        return Response(build_zip(result), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="rulesmith-{replay_id}.zip"'})

    @app.get("/api/replays/{replay_id}/report.md", response_class=PlainTextResponse)
    def replay_report(replay_id: str) -> str:
        """Render a recorded run as the Markdown report."""
        return markdown_report(load_run(_replay_path(replay_id)))

    @app.get("/api/replays/{replay_id}/navigator.json")
    def replay_navigator(replay_id: str) -> dict[str, Any]:
        """Render a recorded run as an ATT&CK Navigator layer."""
        return navigator_layer(load_run(_replay_path(replay_id)))

    @app.post("/api/runs", status_code=202)
    def start_run(body: StartRun, request: Request) -> dict[str, str]:
        """Validate the request and start a live run; returns the id to poll or stream.

        202 because the work continues after the response. 403 when the hosted
        demo is locked to the bundled examples, 422 for an empty input, and
        429 (from ``RunManager.start``) when a cap is hit.
        """
        if settings.demo_locked and body.mode != "example":
            raise HTTPException(status_code=403, detail="This hosted demo only runs the bundled example reports. Clone the repo and add your own NEBIUS_API_KEY to analyse arbitrary reports.")
        if body.mode == "url" and not (body.urls or body.value):
            raise HTTPException(status_code=422, detail="Provide at least one URL.")
        if body.mode in ("text", "query", "example") and not body.value.strip():
            raise HTTPException(status_code=422, detail="Provide a value.")
        # On a budgeted public demo every run is capped at a few rules so one visitor cannot drain it.
        max_rules = body.max_rules
        if settings.demo_budget_usd and body.mode != "example":
            max_rules = min(max_rules or settings.demo_max_rules, settings.demo_max_rules)
        inp = RunInput(mode=body.mode, value=body.value, urls=body.urls, max_rules=max_rules, max_refine_iterations=body.max_refine_iterations, enable_redteam=body.enable_redteam)
        # Behind a reverse proxy (Render, Spaces) the visitor's address is in X-Forwarded-For.
        forwarded = request.headers.get("x-forwarded-for", "")
        client = forwarded.split(",")[0].strip() or (request.client.host if request.client else "")
        state = manager.start(inp, client=client)
        return {"run_id": state.id}

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
        """Return a run's status and, once finished, its full result (polling fallback to the SSE stream)."""
        state = manager.get(run_id)
        return {
            "run_id": run_id,
            "done": state.done,
            "error": state.error,
            "events": len(state.events),
            "result": state.result.model_dump() if state.result else None,
        }

    @app.get("/api/runs/{run_id}/events")
    async def run_events(run_id: str) -> StreamingResponse:
        """Stream a run's progress as Server-Sent Events until it finishes.

        The stream always starts by replaying every event recorded so far:
        the browser connects a moment after POST /api/runs returns, and the
        first stages may already be done by then. The same replay makes a
        dropped connection recoverable by simply reconnecting. A final
        ``end`` event closes the stream.
        """
        state = manager.get(run_id)

        async def gen():
            """Yield buffered events, then live ones, as SSE frames."""
            # Replay anything that happened before the client connected.
            idx = 0
            while True:
                while idx < len(state.events):
                    yield _sse(state.events[idx])
                    idx += 1
                if state.done and idx >= len(state.events):
                    yield _sse({"type": "end", "stage": "end", "message": "stream closed", "error": state.error})
                    return
                # Wait for new events without blocking the event loop. The 15 s
                # timeout exists only to emit a keep-alive comment, which stops
                # proxies and browsers from closing an idle connection while a
                # slow reasoning call is in flight.
                try:
                    item = await asyncio.get_event_loop().run_in_executor(None, state.queue.get, True, 15)
                except queue.Empty:
                    yield ": keep-alive\n\n"
                    continue
                if item is None:
                    continue  # sentinel: loop re-checks done flag
                # The item was appended to state.events already; the loop above emits it.

        # X-Accel-Buffering tells nginx-style proxies not to buffer the stream.
        return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/api/runs/{run_id}/download")
    def download(run_id: str) -> Response:
        """Package a finished live run as a zip bundle; 409 while it is still running or if it failed."""
        state = manager.get(run_id)
        if state.result is None:
            raise HTTPException(status_code=409, detail="Run not finished")
        return Response(build_zip(state.result), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="rulesmith-{run_id}.zip"'})

    @app.get("/api/runs/{run_id}/report.md", response_class=PlainTextResponse)
    def report_md(run_id: str) -> str:
        """Render a finished live run as the Markdown report; 409 while running or if it failed."""
        state = manager.get(run_id)
        if state.result is None:
            raise HTTPException(status_code=409, detail="Run not finished")
        return markdown_report(state.result)

    @app.get("/api/runs/{run_id}/navigator.json")
    def navigator(run_id: str) -> dict[str, Any]:
        """Render a finished live run as an ATT&CK Navigator layer; 409 while running or if it failed."""
        state = manager.get(run_id)
        if state.result is None:
            raise HTTPException(status_code=409, detail="Run not finished")
        return navigator_layer(state.result)

    return app


def _replay_path(replay_id: str) -> Path:
    """Resolve a replay id to its file, raising HTTP 404 for unknown or unsafe ids."""
    path = recorded_run_path(replay_id)
    if path is None:
        raise HTTPException(status_code=404, detail="Unknown replay")
    return path


def _sse(evt: dict[str, Any]) -> str:
    """Encode one event as an SSE ``data:`` frame (``default=str`` covers Paths and datetimes)."""
    return f"data: {json.dumps(evt, default=str)}\n\n"


# ``uvicorn rulesmith.server.app:app`` entrypoint.
app = create_app()
