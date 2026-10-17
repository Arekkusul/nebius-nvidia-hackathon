"""End-to-end pipeline tests driven by FakeLLM (no network)."""

from __future__ import annotations

import json

import pytest

from rulesmith.author import normalize_rule_yaml
from rulesmith.config import Settings
from rulesmith.llm import FakeLLM
from rulesmith.models import RefinedRule
from rulesmith.pipeline import Pipeline, PipelineError, RunInput, load_run
from tests.fixtures import BROAD_YAML, GOOD_YAML, PLAN, REPORT_TEXT, responses_all_good, responses_refine_once


@pytest.fixture
def settings(tmp_path):
    return Settings(runs_dir=tmp_path / "runs", max_refine_iterations=2)


def test_pipeline_happy_path_streams_events_and_saves(settings):
    events = []
    llm = FakeLLM(responses_all_good())
    pipe = Pipeline(settings, llm, on_event=events.append)
    result = pipe.run(RunInput(mode="text", value=REPORT_TEXT))

    assert [c["stage"] for c in llm.calls] == ["extract", "plan", "author", "redteam"]
    assert llm.calls[1]["thinking"] is True and llm.calls[2]["thinking"] is False, "plan uses thinking, author does not"
    assert len(result.rules) == 1
    rule = result.rules[0]
    assert rule.status == "validated", rule.validation.issues
    assert rule.validation.positives_total == 5, "3 authored + 2 red-team variants"
    assert rule.validation.positives_matched == 5
    assert [h.phase for h in rule.history] == ["initial", "redteam"]
    assert set(rule.conversions) >= {"splunk", "elasticsearch", "kusto", "sqlite"}, rule.conversion_errors
    assert "DeviceProcessEvents" in rule.conversions["kusto"]
    assert rule.attack_technique_ids == ["T1059.001"]
    # housekeeping was filled in by normalisation
    assert "id:" in rule.sigma_yaml and "RuleSmith" in rule.sigma_yaml
    # events
    types = [e["type"] for e in events]
    assert types[0] == "stage" and types[-1] == "done"
    assert any(e["type"] == "rule" and e.get("status") == "validated" for e in events)
    stats = result.stats()
    assert stats["validated"] == 1 and stats["positive_recall"] == 1.0 and stats["benign_hits"] == 0
    assert result.metrics.by_tier()["reasoning"]["calls"] == 2
    # saved and reloadable
    saved = list((settings.runs_dir).glob("*.json"))
    assert len(saved) == 1
    assert load_run(saved[0]).run_id == result.run_id


def test_pipeline_refines_broad_rule_using_benign_corpus_evidence(settings):
    llm = FakeLLM(responses_refine_once())
    pipe = Pipeline(settings, llm, on_event=lambda e: None)
    result = pipe.run(RunInput(mode="text", value=REPORT_TEXT))
    rule = result.rules[0]
    assert [c["stage"] for c in llm.calls] == ["extract", "plan", "author", "refine", "redteam"]
    refine_prompt = llm.calls[3]["user"]
    assert "BENIGN BASELINE EVENTS" in refine_prompt and "CcmExec" in refine_prompt, "the model must see the SCCM events it fired on"
    assert "benign_noise" in refine_prompt
    assert rule.status == "validated"
    assert [h.phase for h in rule.history] == ["initial", "refine", "redteam"]
    assert rule.history[0].passed is False and rule.history[1].passed is True
    assert rule.history[1].change_summary.startswith("Required an Office parent")


def test_pipeline_marks_needs_review_when_iterations_exhausted(settings):
    # Refine keeps returning the broad rule, so it never passes.
    resp = responses_refine_once()
    resp["refine"] = [RefinedRule(sigma_yaml=BROAD_YAML, change_summary="no-op"), RefinedRule(sigma_yaml=BROAD_YAML, change_summary="no-op"), RefinedRule(sigma_yaml=BROAD_YAML, change_summary="no-op")]
    llm = FakeLLM(resp)
    result = Pipeline(settings, llm).run(RunInput(mode="text", value=REPORT_TEXT, enable_redteam=False))
    rule = result.rules[0]
    assert rule.status == "needs_review"
    assert sum(1 for c in llm.calls if c["stage"] == "refine") == 2, "bounded by max_refine_iterations"
    assert rule.validation.benign_hits > 0


def test_pipeline_redteam_triggers_extra_hardening_pass(settings):
    # Good rule passes initially, but a red-team variant uses '-ep' which it misses; one hardening pass fixes it.
    from rulesmith.models import RedTeamVariants, TestEvent

    hardened = GOOD_YAML.replace("      - '-ec '\n", "      - '-ec '\n      - '-ep bypass -e'\n")
    resp = responses_all_good()
    resp["redteam"] = RedTeamVariants(variants=[TestEvent(id="V", label="positive", description="-ep bypass then -e", event={"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "powershell -ep bypass -eQQBB"})], analysis="x")
    resp["refine"] = [RefinedRule(sigma_yaml=hardened, change_summary="Added -ep bypass -e variant.")]
    llm = FakeLLM(resp)
    result = Pipeline(settings, llm).run(RunInput(mode="text", value=REPORT_TEXT))
    rule = result.rules[0]
    assert [h.phase for h in rule.history] == ["initial", "redteam", "refine"]
    assert rule.history[1].passed is False and rule.status == "validated"


def test_pipeline_author_failure_yields_failed_rule_not_crash(settings):
    resp = responses_all_good()
    del resp["author"]  # FakeLLM raises LLMError for the missing stage
    result = Pipeline(settings, FakeLLM(resp)).run(RunInput(mode="text", value=REPORT_TEXT))
    assert result.rules[0].status == "failed"
    assert result.warnings and "authoring failed" in result.warnings[0]


def test_pipeline_rejects_bad_input(settings):
    with pytest.raises(PipelineError):
        Pipeline(settings, FakeLLM(responses_all_good())).run(RunInput(mode="text", value="short"))
    with pytest.raises(PipelineError):
        Pipeline(settings, FakeLLM(responses_all_good())).run(RunInput(mode="example", value="does-not-exist"))


def test_normalize_rule_yaml_fills_housekeeping_and_keeps_logic():
    out = normalize_rule_yaml(GOOD_YAML, candidate=PLAN.candidates[0], references=["https://src.example/r", "example://x"])
    assert out.startswith("title: ")
    assert "https://src.example/r" in out and "example://x" not in out
    assert "attack.t1059.001" in out
    assert "selection_parent and selection_child" in out
    # idempotent apart from the generated id
    again = normalize_rule_yaml(out, candidate=PLAN.candidates[0])
    assert again.count("attack.t1059.001") == 1
    # garbage passes through untouched for the validator to report
    assert normalize_rule_yaml("title: [oops") == "title: [oops"
