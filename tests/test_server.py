"""API tests with an injected FakeLLM."""

from __future__ import annotations

import io
import json
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from rulesmith.config import Settings
from rulesmith.llm import FakeLLM
from rulesmith.server.app import create_app
from tests.fixtures import REPORT_TEXT, responses_all_good


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(runs_dir=tmp_path / "runs"), llm=FakeLLM(responses_all_good()))
    return TestClient(app)


def _wait(client, run_id, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/runs/{run_id}").json()
        if r["done"]:
            return r
        time.sleep(0.05)
    raise AssertionError("run did not finish")


def test_index_and_health(client):
    assert client.get("/").status_code == 200 and "RuleSmith" in client.get("/").text
    h = client.get("/api/health").json()
    assert h["llm_configured"] is True and h["models"]["reasoning"] == "fake/nemotron-ultra"
    assert client.get("/api/examples").status_code == 200


def test_run_lifecycle_events_result_and_download(client):
    r = client.post("/api/runs", json={"mode": "text", "value": REPORT_TEXT})
    assert r.status_code == 202
    run_id = r.json()["run_id"]
    final = _wait(client, run_id)
    assert final["error"] is None and final["result"]["rules"][0]["status"] == "validated"

    # SSE stream replays buffered events and closes with an end marker.
    with client.stream("GET", f"/api/runs/{run_id}/events") as resp:
        assert resp.headers["content-type"].startswith("text/event-stream")
        body = "".join(resp.iter_text())
    payloads = [json.loads(line[6:]) for line in body.splitlines() if line.startswith("data: ")]
    assert payloads[0]["type"] == "stage" and payloads[-1]["type"] == "end"
    assert any(p["type"] == "done" for p in payloads)

    z = client.get(f"/api/runs/{run_id}/download")
    assert z.status_code == 200 and z.headers["content-type"] == "application/zip"
    assert "report.md" in zipfile.ZipFile(io.BytesIO(z.content)).namelist()
    assert "# RuleSmith detection pack" in client.get(f"/api/runs/{run_id}/report.md").text
    assert client.get(f"/api/runs/{run_id}/navigator.json").json()["domain"] == "enterprise-attack"


def test_run_validation_errors(client):
    assert client.post("/api/runs", json={"mode": "bogus", "value": "x"}).status_code == 422
    assert client.post("/api/runs", json={"mode": "url"}).status_code == 422
    assert client.post("/api/runs", json={"mode": "text", "value": "   "}).status_code == 422
    assert client.get("/api/runs/nope").status_code == 404
    assert client.get("/api/replays/../../etc").status_code == 404


def test_pipeline_error_is_reported_not_500(client):
    run_id = client.post("/api/runs", json={"mode": "text", "value": "too short"}).json()["run_id"]
    final = _wait(client, run_id)
    assert "too short" in final["error"]
    assert client.get(f"/api/runs/{run_id}/download").status_code == 409


def test_demo_lock_blocks_arbitrary_input(tmp_path):
    app = create_app(Settings(runs_dir=tmp_path, demo_locked=True), llm=FakeLLM(responses_all_good()))
    c = TestClient(app)
    assert c.post("/api/runs", json={"mode": "text", "value": REPORT_TEXT}).status_code == 403
    assert c.get("/api/health").json()["demo_locked"] is True


def test_no_llm_configured_reports_cleanly(tmp_path):
    app = create_app(Settings(runs_dir=tmp_path, nebius_api_key=""), llm=None)
    c = TestClient(app)
    assert c.get("/api/health").json()["llm_configured"] is False
    run_id = c.post("/api/runs", json={"mode": "text", "value": REPORT_TEXT}).json()["run_id"]
    final = _wait(c, run_id)
    assert "NEBIUS_API_KEY" in final["error"]


def test_cli_examples_and_models_without_key(monkeypatch, capsys):
    from rulesmith.cli import main

    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    assert main(["examples"]) == 0
    assert main(["models"]) == 2
    assert main(["run", "--example", "x"]) == 2
