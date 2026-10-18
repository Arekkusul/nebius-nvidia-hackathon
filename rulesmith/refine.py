"""Stage 6: validation-driven refinement (Nemotron main tier)."""

from __future__ import annotations

import json

from .author import clean_tests, normalize_rule_yaml, rule_doc_to_yaml
from .config import TIER_MAIN
from .llm import BaseLLM
from .models import DetectionCandidate, RefinedRule, RuleDraft, TestEvent, UsageRecord, ValidationReport
from .prompts import REFINE_SYSTEM
from .sigmahq import SigmaHQExamples


def refine_rule(
    llm: BaseLLM,
    candidate: DetectionCandidate,
    draft: RuleDraft,
    report: ValidationReport,
    *,
    references: list[str] | None = None,
    examples: SigmaHQExamples | None = None,
) -> tuple[RuleDraft, RefinedRule, UsageRecord, list[TestEvent]]:
    """Ask the model to fix the rule given concrete validation evidence.

    Returns the updated draft (new YAML, merged tests), the model's change
    summary, usage, and any red-team variants the model retired as
    unreachable (already removed from the draft's tests, reason appended to
    their description).
    """
    failed_ids = {o.event_id for o in report.test_outcomes if not o.passed}
    failing = [t.model_dump() for t in draft.tests if t.id in failed_ids]
    issues = [i.model_dump() for i in report.issues if i.severity in ("error", "warning")]
    # Two SigmaHQ rules for the same logsource/technique remind the model how
    # the community keys on short invariant tokens; the author stage shows three.
    shots = SigmaHQExamples.render(examples.find(candidate.logsource, candidate.attack_technique_ids, candidate.title, k=2)) if examples else ""
    user = (
        f"RULE (YAML):\n{draft.sigma_yaml}\n\n"
        f"PLAN FOR THIS RULE:\n{json.dumps(candidate.model_dump(), indent=1)}\n\n"
        f"VALIDATION ISSUES:\n{json.dumps(issues, indent=1)}\n\n"
        f"TEST EVENTS THE RULE GOT WRONG (positive = must match, negative = must not):\n{json.dumps(failing, indent=1)}\n\n"
        f"BENIGN BASELINE EVENTS THE RULE FIRED ON ({report.benign_hits} total, first few shown):\n{json.dumps(report.benign_examples, indent=1)}\n\n"
        + (f"{shots}\n\n" if shots else "")
        + "Return the corrected complete rule."
    )
    refined, usage = llm.complete_structured(stage="refine", tier=TIER_MAIN, system=REFINE_SYSTEM, user=user, schema=RefinedRule, thinking=False)
    # Same path as authoring: structured rule in, normalised YAML out.
    new_yaml = normalize_rule_yaml(rule_doc_to_yaml(refined.rule), candidate=candidate, references=references)
    kept, retired = apply_retirements(draft.tests, refined)
    tests = clean_tests(kept + list(refined.additional_tests))
    updated = draft.model_copy(update={"sigma_yaml": new_yaml, "tests": tests})
    return updated, refined, usage, retired


def apply_retirements(tests: list[TestEvent], refined: RefinedRule) -> tuple[list[TestEvent], list[TestEvent]]:
    """Split ``tests`` into the ones that stay and the red-team variants retired by the model.

    Guard rails keep this honest: only red-team tests (ids starting with
    ``R``, positive evasions or benign look-alikes) can be retired, never the
    author's own tests, and at most half of the red-team tests in one pass,
    so a model cannot make a rule "pass" by discarding the whole red-team.
    Every retired test is kept on the final rule with its reason, so the
    analyst still sees it.
    """
    reasons = {r.id: r.reason.strip() for r in refined.retire_tests if r.id.startswith("R")}
    redteam_tests = [t for t in tests if t.id.startswith("R")]
    allowed = max(1, (len(redteam_tests) + 1) // 2) if redteam_tests else 0
    retired: list[TestEvent] = []
    kept: list[TestEvent] = []
    for t in tests:
        if t.id in reasons and t.id.startswith("R") and len(retired) < allowed:
            retired.append(t.model_copy(update={"description": f"{t.description} [retired: {reasons[t.id] or 'unreachable for this logsource'}]"}))
        else:
            kept.append(t)
    return kept, retired
