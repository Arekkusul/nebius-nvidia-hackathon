"""Stage 6: validation-driven refinement (Nemotron main tier)."""

from __future__ import annotations

import json

from .author import clean_tests, normalize_rule_yaml, rule_doc_to_yaml
from .config import TIER_MAIN
from .llm import BaseLLM
from .models import DetectionCandidate, RefinedRule, RuleDraft, UsageRecord, ValidationReport
from .prompts import REFINE_SYSTEM


def refine_rule(
    llm: BaseLLM,
    candidate: DetectionCandidate,
    draft: RuleDraft,
    report: ValidationReport,
    *,
    references: list[str] | None = None,
) -> tuple[RuleDraft, RefinedRule, UsageRecord]:
    """Ask the model to fix the rule given concrete validation evidence.

    Returns the updated draft (new YAML, merged tests), the model's change
    summary, and usage.
    """
    failed_ids = {o.event_id for o in report.test_outcomes if not o.passed}
    failing = [t.model_dump() for t in draft.tests if t.id in failed_ids]
    issues = [i.model_dump() for i in report.issues if i.severity in ("error", "warning")]
    user = (
        f"RULE (YAML):\n{draft.sigma_yaml}\n\n"
        f"PLAN FOR THIS RULE:\n{json.dumps(candidate.model_dump(), indent=1)}\n\n"
        f"VALIDATION ISSUES:\n{json.dumps(issues, indent=1)}\n\n"
        f"TEST EVENTS THE RULE GOT WRONG (positive = must match, negative = must not):\n{json.dumps(failing, indent=1)}\n\n"
        f"BENIGN BASELINE EVENTS THE RULE FIRED ON ({report.benign_hits} total, first few shown):\n{json.dumps(report.benign_examples, indent=1)}\n\n"
        "Return the corrected complete rule."
    )
    refined, usage = llm.complete_structured(stage="refine", tier=TIER_MAIN, system=REFINE_SYSTEM, user=user, schema=RefinedRule, thinking=False)
    # Same path as authoring: structured rule in, normalised YAML out.
    new_yaml = normalize_rule_yaml(rule_doc_to_yaml(refined.rule), candidate=candidate, references=references)
    tests = clean_tests(list(draft.tests) + list(refined.additional_tests))
    updated = draft.model_copy(update={"sigma_yaml": new_yaml, "tests": tests})
    return updated, refined, usage
