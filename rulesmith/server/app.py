"""HTTP API + static UI.

Runs execute in a background thread; progress is streamed to the browser
over Server-Sent Events so the judges can watch Nemotron plan, write, test
and harden each rule in real time.
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

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..config import Settings
from ..ingest import list_examples
from ..llm import BaseLLM, TokenFactoryLLM
from ..package import build_zip, markdown_report, navigator_layer
from ..pipeline import Pipeline, PipelineError, RunInput, load_run
from ..models import RunResult

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
REPLAYS_DIR = Path(__file__).resolve().parents[2] / "examples" / "runs"
MAX_CONCURRENT_RUNS = 2
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
    """Bookkeeping for one in-flight or finished run."""

    id: str
    events: list[dict[str, Any]] = field(default_factory=list)
    queue: "queue.Queue[dict[str, Any] | None]" = field(default_factory=queue.Queue)
    result: RunResult | None = None
    error: str | None = None
    done: bool = False
    started: float = field(default_factory=time.time)


class RunManager:
    """Owns background runs and fans events out to SSE subscribers."""

    def __init__(self, pipeline_factory) -> None:  # type: ignore[no-untyped-def]
        self.pipeline_factory = pipeline_factory
        self.runs: dict[str, RunState] = {}
        self._lock = threading.Lock()

    def active(self) -> int:
        with self._lock:
            return sum(1 for r in self.runs.values() if not r.done)

    def _gc(self) -> None:
        cutoff = time.time() - RUN_TTL_S
        with self._lock:
            for rid in [k for k, v in self.runs.items() if v.done and v.started < cutoff]:
                del self.runs[rid]

    def start(self, inp: RunInput) -> RunState:
        self._gc()
        if self.active() >= MAX_CONCURRENT_RUNS:
            raise HTTPException(status_code=429, detail="Too many runs in progress; try again in a minute.")
        state = RunState(id=uuid.uuid4().hex[:12])
        with self._lock:
            self.runs[state.id] = state

        def on_event(evt: dict[str, Any]) -> None:
            state.events.append(evt)
            state.queue.put(evt)

        def work() -> None:
            try:
                pipeline = self.pipeline_factory(on_event)
                state.result = pipeline.run(inp)
            except PipelineError as exc:
                state.error = str(exc)
                on_event({"type": "error", "stage": "error", "message": str(exc), "ts": time.time()})
            except Exception as exc:  # noqa: BLE001 - report anything to the UI
                log.exception("run %s crashed", state.id)
                state.error = f"{type(exc).__name__}: {exc}"
                on_event({"type": "error", "stage": "error", "message": state.error, "ts": time.time()})
            finally:
                state.done = True
                state.queue.put(None)

        threading.Thread(target=work, name=f"run-{state.id}", daemon=True).start()
        return state

    def get(self, run_id: str) -> RunState:
        with self._lock:
            state = self.runs.get(run_id)
        if state is None:
            raise HTTPException(status_code=404, detail="Unknown run id")
        return state


def create_app(settings: Settings | None = None, llm: BaseLLM | None = None) -> FastAPI:
    """Application factory (tests inject a FakeLLM)."""
    settings = settings or Settings.from_env()
    app = FastAPI(title="RuleSmith", version=__version__, docs_url="/api/docs", redoc_url=None)

    shared_llm: BaseLLM | None = llm
    if shared_llm is None and settings.has_llm:
        shared_llm = TokenFactoryLLM(settings)

    def pipeline_factory(on_event):  # type: ignore[no-untyped-def]
        if shared_llm is None:
            raise PipelineError("No NEBIUS_API_KEY configured on this server; use the replay mode or run locally with your key.")
        return Pipeline(settings, shared_llm, on_event=on_event)

    manager = RunManager(pipeline_factory)
    app.state.settings = settings
    app.state.manager = manager

    # ---------------------------------------------------------------- pages

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index() -> HTMLResponse:
        return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ------------------------------------------------------------------ api

    @app.get("/api/health")
    def health() -> dict[str, Any]:
        models: dict[str, str] = {}
        if shared_llm is not None:
            try:
                models = shared_llm.resolve_models() if hasattr(shared_llm, "resolve_models") else dict(shared_llm.models)
            except Exception as exc:  # noqa: BLE001
                log.warning("model resolution failed: %s", exc)
        return {
            "version": __version__,
            "llm_configured": shared_llm is not None,
            "tavily_configured": settings.has_tavily,
            "demo_locked": settings.demo_locked,
            "models": models,
            "active_runs": manager.active(),
        }

    @app.get("/api/examples")
    def examples() -> list[dict[str, str]]:
        return list_examples()

    @app.get("/api/replays")
    def replays() -> list[dict[str, Any]]:
        out = []
        for p in sorted(REPLAYS_DIR.glob("*.json")):
            try:
                r = load_run(p)
                out.append({"id": p.stem, "title": r.report.title, "rules": len(r.rules), "validated": r.stats()["validated"], "created_at": r.created_at})
            except Exception as exc:  # noqa: BLE001
                log.warning("bad replay %s: %s", p, exc)
        return out

    @app.get("/api/replays/{replay_id}")
    def replay(replay_id: str) -> JSONResponse:
        path = _replay_path(replay_id)
        return JSONResponse(json.loads(path.read_text(encoding="utf-8")))

    @app.get("/api/replays/{replay_id}/download")
    def replay_download(replay_id: str) -> Response:
        result = load_run(_replay_path(replay_id))
        return Response(build_zip(result), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="rulesmith-{replay_id}.zip"'})

    @app.post("/api/runs", status_code=202)
    def start_run(body: StartRun) -> dict[str, str]:
        if settings.demo_locked and body.mode != "example":
            raise HTTPException(status_code=403, detail="This hosted demo only runs the bundled example reports. Clone the repo and add your own NEBIUS_API_KEY to analyse arbitrary reports.")
        if body.mode == "url" and not (body.urls or body.value):
            raise HTTPException(status_code=422, detail="Provide at least one URL.")
        if body.mode in ("text", "query", "example") and not body.value.strip():
            raise HTTPException(status_code=422, detail="Provide a value.")
        inp = RunInput(mode=body.mode, value=body.value, urls=body.urls, max_rules=body.max_rules, max_refine_iterations=body.max_refine_iterations, enable_redteam=body.enable_redteam)
        state = manager.start(inp)
        return {"run_id": state.id}

    @app.get("/api/runs/{run_id}")
    def get_run(run_id: str) -> dict[str, Any]:
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
        state = manager.get(run_id)

        async def gen():
            # Replay anything that happened before the client connected.
            idx = 0
            while True:
                while idx < len(state.events):
                    yield _sse(state.events[idx])
                    idx += 1
                if state.done and idx >= len(state.events):
                    yield _sse({"type": "end", "stage": "end", "message": "stream closed", "error": state.error})
                    return
                # Wait for new events without blocking the event loop.
                try:
                    item = await asyncio.get_event_loop().run_in_executor(None, state.queue.get, True, 15)
                except queue.Empty:
                    yield ": keep-alive\n\n"
                    continue
                if item is None:
                    continue  # sentinel: loop re-checks done flag
                # The item was appended to state.events already; the loop above emits it.

        return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/api/runs/{run_id}/download")
    def download(run_id: str) -> Response:
        state = manager.get(run_id)
        if state.result is None:
            raise HTTPException(status_code=409, detail="Run not finished")
        return Response(build_zip(state.result), media_type="application/zip", headers={"Content-Disposition": f'attachment; filename="rulesmith-{run_id}.zip"'})

    @app.get("/api/runs/{run_id}/report.md", response_class=PlainTextResponse)
    def report_md(run_id: str) -> str:
        state = manager.get(run_id)
        if state.result is None:
            raise HTTPException(status_code=409, detail="Run not finished")
        return markdown_report(state.result)

    @app.get("/api/runs/{run_id}/navigator.json")
    def navigator(run_id: str) -> dict[str, Any]:
        state = manager.get(run_id)
        if state.result is None:
            raise HTTPException(status_code=409, detail="Run not finished")
        return navigator_layer(state.result)

    return app


def _replay_path(replay_id: str) -> Path:
    safe = "".join(ch for ch in replay_id if ch.isalnum() or ch in "-_")
    path = REPLAYS_DIR / f"{safe}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Unknown replay")
    return path


def _sse(evt: dict[str, Any]) -> str:
    return f"data: {json.dumps(evt, default=str)}\n\n"


# ``uvicorn rulesmith.server.app:app`` entrypoint.
app = create_app()
