"""End-to-end pipeline tests driven by FakeLLM (no network)."""

from __future__ import annotations

import pytest

from rulesmith.author import normalize_rule_yaml
from rulesmith.config import Settings
from rulesmith.llm import FakeLLM
from rulesmith.models import RefinedRule, SigmaRuleDoc
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
    broad = SigmaRuleDoc.from_yaml(BROAD_YAML)
    resp["refine"] = [RefinedRule(rule=broad, change_summary="no-op"), RefinedRule(rule=broad, change_summary="no-op"), RefinedRule(rule=broad, change_summary="no-op")]
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
    resp["refine"] = [RefinedRule(rule=SigmaRuleDoc.from_yaml(hardened), change_summary="Added -ep bypass -e variant.")]
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


def test_pipeline_reverts_when_refinement_regresses(settings):
    """A refinement that breaks a compiling rule must not replace the best earlier draft."""
    from rulesmith.models import SigmaRuleDoc

    resp = responses_refine_once()
    broken = SigmaRuleDoc.from_yaml(GOOD_YAML)
    broken.detection = {**broken.detection, "condition": "selection_parent and (CommandLine|contains:'x')"}  # pySigma rejects this
    resp["refine"] = [RefinedRule(rule=broken, change_summary="made it worse"), RefinedRule(rule=broken, change_summary="made it worse")]
    result = Pipeline(settings, FakeLLM(resp)).run(RunInput(mode="text", value=REPORT_TEXT, enable_redteam=False))
    rule = result.rules[0]
    assert [h.phase for h in rule.history] == ["initial", "refine", "refine", "revert"]
    assert rule.status == "needs_review", "the broad rule still parses, so it is reviewable rather than failed"
    assert "condition: selection_child" in rule.sigma_yaml and "CommandLine|contains:" not in rule.sigma_yaml
    assert rule.validation.parse_ok


def test_normalize_rule_yaml_drops_unknown_plan_technique_ids():
    """A hallucinated technique id from the plan must not be re-added on every refinement."""
    from rulesmith.models import DetectionCandidate, LogSourceHint

    cand = DetectionCandidate(id="D9", title="x", behavior_ids=["B1"], attack_technique_ids=["T1605.004", "T1059.001", "T1059.999"], logsource=LogSourceHint(category="process_creation", product="windows"), rationale="r", key_fields=["Image"], false_positive_risks="f", priority="low")
    out = normalize_rule_yaml(GOOD_YAML, candidate=cand)
    assert "attack.t1059.001" in out
    assert "t1605" not in out, "unknown technique with no known parent is dropped"
    assert "t1059.999" not in out and "- attack.t1059\n" in out, "unknown sub-technique collapses to its parent"


def test_pipeline_keeps_out_of_scope_evasions_without_testing_them(settings):
    from rulesmith.models import RedTeamVariants, TestEvent

    resp = responses_all_good()
    resp["redteam"] = RedTeamVariants(
        variants=[],
        out_of_scope=[TestEvent(id="z", label="positive", description="renamed binary, no OriginalFileName in this logsource", event={"Image": "C:\\x\\notps.exe", "ParentImage": "C:\\Office\\WINWORD.EXE", "CommandLine": "notps -enc AAA"})],
        analysis="renamed binaries are out of reach",
    )
    result = Pipeline(settings, FakeLLM(resp)).run(RunInput(mode="text", value=REPORT_TEXT))
    rule = result.rules[0]
    assert rule.status == "validated"
    assert rule.validation.positives_total == 3, "out-of-scope evasions are not added to the tests"
    assert [t.id for t in rule.redteam_out_of_scope] == ["X1"]


def test_pipeline_retires_unreachable_redteam_variant_with_reason(settings):
    # The red-team hands back an env-var path that no substring on CommandLine can match; the hardening
    # pass keeps the rule and retires that variant instead, so the rule validates on the real tests.
    from rulesmith.models import RedTeamVariants, RefinedRule, RetiredTest, SigmaRuleDoc, TestEvent

    resp = responses_all_good()
    unreachable = TestEvent(id="V", label="positive", description="script path via %APPDATA%, no -enc", event={"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "powershell -File %APPDATA%\\x.ps1"})
    resp["redteam"] = RedTeamVariants(variants=[unreachable], analysis="x")
    resp["refine"] = [RefinedRule(rule=SigmaRuleDoc.from_yaml(GOOD_YAML), change_summary="Kept the rule.", retire_tests=[RetiredTest(id="R1", reason="no encoded command to key on")])]
    result = Pipeline(settings, FakeLLM(resp)).run(RunInput(mode="text", value=REPORT_TEXT))
    rule = result.rules[0]
    assert rule.status == "validated"
    assert [t.id for t in rule.retired_tests] == ["R1"]
    assert rule.retired_tests[0].description.endswith("[retired: no encoded command to key on]")
    assert all(t.id != "R1" for t in rule.tests), "a retired variant leaves the test set"
    assert rule.validation.positives_total == 3
    assert "Retired R1" in rule.history[-1].change_summary


def test_pipeline_never_retires_original_positives(settings):
    # A refine reply that tries to retire P1 (an author positive) is ignored: the rule stays needs_review.
    from rulesmith.models import RefinedRule, RetiredTest, SigmaRuleDoc

    resp = responses_refine_once()
    resp["refine"] = [RefinedRule(rule=SigmaRuleDoc.from_yaml(BROAD_YAML), change_summary="Tried to drop a test.", retire_tests=[RetiredTest(id="P1", reason="inconvenient")])] * 4
    result = Pipeline(settings, FakeLLM(resp)).run(RunInput(mode="text", value=REPORT_TEXT, max_refine_iterations=1, enable_redteam=False))
    rule = result.rules[0]
    assert rule.status == "needs_review"
    assert rule.retired_tests == []
    assert {t.id for t in rule.tests} >= {"P1", "P2", "P3"}


def test_pipeline_can_retire_redteam_negative_identical_to_the_attack(settings):
    # A red-team "benign" look-alike with the same fields as the attack can never be excluded; retiring it is allowed.
    from rulesmith.models import RedTeamVariants, RefinedRule, RetiredTest, SigmaRuleDoc, TestEvent

    resp = responses_all_good()
    twin = TestEvent(id="N", label="negative", description="same command, authorised admin", event={"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "powershell -enc SQBFAFgA"})
    resp["redteam"] = RedTeamVariants(variants=[twin], analysis="x")
    resp["refine"] = [RefinedRule(rule=SigmaRuleDoc.from_yaml(GOOD_YAML), change_summary="Kept the rule.", retire_tests=[RetiredTest(id="R1", reason="identical to P1 in every recorded field")])]
    result = Pipeline(settings, FakeLLM(resp)).run(RunInput(mode="text", value=REPORT_TEXT))
    rule = result.rules[0]
    assert rule.status == "validated"
    assert [t.id for t in rule.retired_tests] == ["R1"] and rule.retired_tests[0].label == "negative"


def test_pipeline_hardening_gets_a_second_pass_after_an_unparsable_reply(settings):
    # First hardening reply breaks the rule, the second fixes it: the rule still validates.
    from rulesmith.models import RedTeamVariants, RefinedRule, SigmaRuleDoc, TestEvent

    hardened = GOOD_YAML.replace("      - '-ec '\n", "      - '-ec '\n      - '-ep bypass -e'\n")
    broken = SigmaRuleDoc.from_yaml(GOOD_YAML.replace("condition: selection_parent and selection_child", "condition: selection_nope"))
    resp = responses_all_good()
    resp["redteam"] = RedTeamVariants(variants=[TestEvent(id="V", label="positive", description="-ep bypass then -e", event={"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "CommandLine": "powershell -ep bypass -eQQBB"})], analysis="x")
    resp["refine"] = [RefinedRule(rule=broken, change_summary="oops"), RefinedRule(rule=SigmaRuleDoc.from_yaml(hardened), change_summary="Added -ep bypass -e variant.")]
    rule = Pipeline(settings, FakeLLM(resp)).run(RunInput(mode="text", value=REPORT_TEXT)).rules[0]
    assert [h.phase for h in rule.history] == ["initial", "redteam", "refine", "refine"]
    assert rule.status == "validated"


def test_pipeline_refine_can_correct_a_wrong_test_event_with_reason(settings):
    # The author's P1 carries the loaded DLL as ParentImage (a wrong event); refine corrects the event, not the rule.
    from rulesmith.models import RefinedRule, ReplacedTest, SigmaRuleDoc, TestEvent
    from tests.fixtures import GOOD_DRAFT, TESTS

    wrong = TESTS[0].model_copy(update={"event": {**TESTS[0].event, "ParentImage": "C:\\Users\\x\\AppData\\Local\\Temp\\x64dbg.dll"}})
    resp = responses_all_good()
    resp["author"] = GOOD_DRAFT.model_copy(update={"tests": [wrong, *TESTS[1:]]})
    fixed = TestEvent(id="P1", label="positive", description="Word spawns encoded PS (parent corrected)", event=TESTS[0].event)
    resp["refine"] = [RefinedRule(rule=SigmaRuleDoc.from_yaml(GOOD_YAML), change_summary="Rule unchanged.", replace_tests=[ReplacedTest(test=fixed, reason="ParentImage held the DLL path instead of the spawning binary")])]
    rule = Pipeline(settings, FakeLLM(resp)).run(RunInput(mode="text", value=REPORT_TEXT, enable_redteam=False)).rules[0]
    assert rule.status == "validated"
    assert [t.id for t in rule.replaced_tests] == ["P1"] and "[replaced: ParentImage held the DLL path" in rule.replaced_tests[0].description
    assert next(t for t in rule.tests if t.id == "P1").event["ParentImage"].endswith("WINWORD.EXE")
    assert "Corrected test event(s) P1" in rule.history[-1].change_summary


def test_normalize_rule_yaml_reduces_a_sequence_chain_to_its_most_specific_step():
    # "wmic spawns cmd, then cmd spawns encoded powershell" written as one rule: the two steps pin Image to
    # different binaries, so the chain is reduced to the more specific step and the note says so.
    import yaml

    chain = """
title: WMIC chain
logsource: {category: process_creation, product: windows}
detection:
  selection_stage1: {'ParentImage|endswith': '\\wmic.exe', 'Image|endswith': '\\cmd.exe'}
  selection_stage2: {'ParentImage|endswith': '\\cmd.exe', 'Image|endswith': '\\powershell.exe', 'CommandLine|contains': '-enc'}
  filter_admin: {'User|contains': 'svc_'}
  condition: selection_stage1 and selection_stage2 and not filter_admin
"""
    notes: list[str] = []
    det = yaml.safe_load(normalize_rule_yaml(chain, notes=notes))["detection"]
    assert "selection_stage1" not in det and "selection_stage2" in det
    assert det["condition"] == "selection_stage2 and not filter_admin"
    assert notes and "selection_stage1" in notes[0]


def test_pipeline_repairs_contains_all_before_asking_the_model(settings):
    # The first draft requires an unexpanded %SystemRoot% token no positive carries; the deterministic repair
    # drops it, the rule validates, and no refine call is spent.
    from tests.fixtures import GOOD_DRAFT

    broken_yaml = GOOD_YAML.replace(
        "    CommandLine|contains:\n      - '-enc'\n      - '-EncodedCommand'\n      - '-e '\n      - '-ec '\n",
        "    CommandLine|contains|all:\n      - '-e'\n      - '%SystemRoot%'\n",
    )
    assert broken_yaml != GOOD_YAML
    resp = responses_all_good()
    resp["author"] = GOOD_DRAFT.model_copy(update={"rule": SigmaRuleDoc.from_yaml(broken_yaml)})
    llm = FakeLLM(resp)
    rule = Pipeline(settings, llm).run(RunInput(mode="text", value=REPORT_TEXT, enable_redteam=False)).rules[0]
    assert [h.phase for h in rule.history] == ["initial", "repair"]
    assert rule.status == "validated"
    assert "%SystemRoot%" in rule.history[1].change_summary
    assert not [c for c in llm.calls if c["stage"] == "refine"]


def test_refine_refuses_corrections_that_add_fields_only_the_rule_wants():
    # Adding a field no other positive carries is bending the test to the rule, so the correction is dropped;
    # adding a field the siblings already have (a missing parent) is accepted.
    from rulesmith.models import RefinedRule, ReplacedTest, SigmaRuleDoc, TestEvent
    from rulesmith.refine import apply_replacements
    from tests.fixtures import TESTS

    p1 = TESTS[0]
    sneaky = TestEvent(id="P1", label="positive", description="fitted", event={**p1.event, "UserAgent": "evil/1.0"})
    refined = RefinedRule(rule=SigmaRuleDoc.from_yaml(GOOD_YAML), change_summary="x", replace_tests=[ReplacedTest(test=sneaky, reason="rule needs it")])
    out, replaced = apply_replacements(list(TESTS), refined)
    assert replaced == [] and out[0].event == p1.event
    stripped = p1.model_copy(update={"event": {k: v for k, v in p1.event.items() if k != "ParentImage"}})
    fixed = TestEvent(id="P1", label="positive", description="parent restored", event=p1.event)
    refined = RefinedRule(rule=SigmaRuleDoc.from_yaml(GOOD_YAML), change_summary="x", replace_tests=[ReplacedTest(test=fixed, reason="ParentImage was missing")])
    out, replaced = apply_replacements([stripped, *TESTS[1:]], refined)
    assert [t.id for t in replaced] == ["P1"] and out[0].event == p1.event


def test_refine_never_corrects_redteam_variants():
    from rulesmith.models import RefinedRule, ReplacedTest, SigmaRuleDoc, TestEvent
    from rulesmith.refine import apply_replacements
    from tests.fixtures import TESTS

    variant = TestEvent(id="R1", label="positive", description="quoted path", event={**TESTS[0].event, "CommandLine": "'powershell' -enc AAA"})
    edited = variant.model_copy(update={"event": TESTS[0].event})
    refined = RefinedRule(rule=SigmaRuleDoc.from_yaml(GOOD_YAML), change_summary="x", replace_tests=[ReplacedTest(test=edited, reason="fit")])
    out, replaced = apply_replacements([*TESTS, variant], refined)
    assert replaced == [] and out[-1].event == variant.event
