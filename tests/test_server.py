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


def test_budgeted_demo_reports_and_enforces_the_spend_cap(tmp_path):
    from rulesmith.server.app import RunManager

    app = create_app(Settings(runs_dir=tmp_path / "runs", demo_budget_usd=0.5), llm=FakeLLM(responses_all_good()))
    c = TestClient(app)
    h = c.get("/api/health").json()
    assert h["budget"] == {"limit_usd": 0.5, "spent_usd": 0.0, "remaining_usd": 0.5}
    # A run with the fake model costs nothing, so the budget is untouched afterwards and runs keep working.
    r = c.post("/api/runs", json={"mode": "text", "value": REPORT_TEXT, "max_rules": 9})
    assert r.status_code == 202
    _wait(c, r.json()["run_id"])
    assert c.get("/api/health").json()["budget"]["spent_usd"] == 0.0
    # Once the reserve no longer fits, new runs are refused with a clear message; replays are unaffected.
    app.state.manager.spent_usd = 0.45
    r = c.post("/api/runs", json={"mode": "text", "value": REPORT_TEXT})
    assert r.status_code == 429 and "budget" in r.json()["detail"]
    assert c.get("/api/replays").status_code == 200
    # Uncapped servers report no budget at all.
    assert RunManager(lambda cb: None).budget() is None


def test_replay_endpoints_serve_recorded_runs(client):
    replays = client.get("/api/replays").json()
    assert replays, "examples/runs should ship at least one recorded run"
    rid = replays[0]["id"]
    assert client.get(f"/api/replays/{rid}").json()["run_id"]
    assert client.get(f"/api/replays/{rid}/report.md").text.startswith("# RuleSmith detection pack")
    assert client.get(f"/api/replays/{rid}/navigator.json").json()["domain"] == "enterprise-attack"
    assert client.get(f"/api/replays/{rid}/download").headers["content-type"] == "application/zip"
    assert client.get("/api/replays/nope/report.md").status_code == 404


def test_cli_replay_packages_a_recorded_run_without_a_key(monkeypatch, tmp_path, capsys):
    from rulesmith.cli import main

    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    assert main(["replay", "macro_loader_campaign", "--out", str(tmp_path)]) == 0
    assert list(tmp_path.glob("*.zip")) and list(tmp_path.glob("*.md"))
    assert "# RuleSmith detection pack" in capsys.readouterr().out
    assert main(["replay", "no_such_run"]) == 2


def test_public_demo_rate_limits_runs_per_visitor_and_per_hour(tmp_path):
    app = create_app(Settings(runs_dir=tmp_path / "runs", demo_budget_usd=5.0, demo_runs_per_hour=4, demo_runs_per_ip_per_hour=2), llm=FakeLLM(responses_all_good()))
    c = TestClient(app)
    assert c.get("/api/health").json()["rate_limits"] == {"runs_per_hour": 4, "runs_per_ip_per_hour": 2}
    body = {"mode": "text", "value": REPORT_TEXT}
    # Two runs from one address are fine, the third is refused with the per-visitor message.
    for _ in range(2):
        _wait(c, c.post("/api/runs", json=body).json()["run_id"])
    r = c.post("/api/runs", json=body)
    assert r.status_code == 429 and "per visitor" in r.json()["detail"]
    # Another address (as a proxy would report it) still gets runs until the hourly total is used up.
    other = {"X-Forwarded-For": "203.0.113.9, 10.0.0.1"}
    for _ in range(2):
        _wait(c, c.post("/api/runs", json=body, headers=other).json()["run_id"])
    r = c.post("/api/runs", json=body, headers={"X-Forwarded-For": "198.51.100.7"})
    assert r.status_code == 429 and "per hour" in r.json()["detail"]
    # Replays are never rate limited, and a private server has no limits at all.
    assert c.get("/api/replays").status_code == 200
    assert create_app(Settings(runs_dir=tmp_path / "p"), llm=FakeLLM(responses_all_good())).state.manager.runs_per_hour == 0
