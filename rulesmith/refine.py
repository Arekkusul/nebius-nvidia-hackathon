"""Stage 6: validation-driven refinement (Nemotron main tier).

Sits after validate in the pipeline loop: each failed validation round hands
its evidence here, the corrected draft is validated again, and the pipeline
bounds the loop with ``max_refine_iterations`` (plus up to two passes after
the red-team).
"""

from __future__ import annotations

import json

from .author import clean_event, clean_tests, normalize_rule_yaml, rule_doc_to_yaml
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
) -> tuple[RuleDraft, RefinedRule, UsageRecord, list[TestEvent], list[TestEvent]]:
    """Ask the model to fix the rule given concrete validation evidence.

    Returns the updated draft (new YAML, merged tests), the model's change
    summary, usage, the red-team variants the model retired as unreachable
    (already removed from the draft's tests, reason appended to their
    description) and the original versions of any test events it corrected
    in place (reason appended likewise).
    """
    failed_ids = {o.event_id for o in report.test_outcomes if not o.passed}
    failing = [t.model_dump() for t in draft.tests if t.id in failed_ids]
    # Informational lint is noise in a repair prompt; only errors and warnings are shown.
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
    # Repair is a low-entropy task: two live refine calls on the same evidence went 7/7 and 5/8,
    # so sample colder than authoring (0.7) to make the fix reproducible.
    refined, usage = llm.complete_structured(stage="refine", tier=TIER_MAIN, system=REFINE_SYSTEM, user=user, schema=RefinedRule, thinking=False, temperature=0.3)
    # Same path as authoring: structured rule in, normalised YAML out. A note
    # from the normaliser (e.g. a chain reduced to one step) joins the summary.
    notes: list[str] = []
    new_yaml = normalize_rule_yaml(rule_doc_to_yaml(refined.rule), candidate=candidate, references=references, notes=notes)
    if notes:
        refined = refined.model_copy(update={"change_summary": " ".join([refined.change_summary, *notes]).strip()})
    corrected, replaced = apply_replacements(draft.tests, refined)
    kept, retired = apply_retirements(corrected, refined)
    tests = clean_tests(kept + list(refined.additional_tests))
    updated = draft.model_copy(update={"sigma_yaml": new_yaml, "tests": tests})
    return updated, refined, usage, retired, replaced


def apply_replacements(tests: list[TestEvent], refined: RefinedRule) -> tuple[list[TestEvent], list[TestEvent]]:
    """Swap in corrected test events; returns ``(tests, originals_replaced)``.

    A replacement must name an existing id and keep its label, and at most
    two events change per pass, so the model cannot rewrite the whole test
    set to fit a weak rule. Red-team variants (R*) are never corrected, only
    retired. A corrected positive may only introduce fields
    that the rule's other positive events already carry: adding a parent
    the sibling events have is a fix, adding a field only the rule wants is
    bending the test to the rule and is refused. The originals are returned
    with the reason appended so the final rule shows what changed and why.
    """
    by_id = {r.test.id: r for r in refined.replace_tests}
    out: list[TestEvent] = []
    replaced: list[TestEvent] = []
    for t in tests:
        r = by_id.get(t.id)
        # Red-team variants are adversarial by design: editing one to fit the rule defeats it.
        # They can only be retired (with the reason on display), never corrected.
        if r is not None and t.id.startswith("R"):
            r = None
        if r is not None and r.test.label == "positive" and not _introduces_only_known_fields(r.test, t, tests):
            r = None
        if r is not None and r.test.label == t.label and len(replaced) < 2:
            replaced.append(t.model_copy(update={"description": f"{t.description} [replaced: {r.reason.strip() or 'event was wrong'}]"}))
            out.append(r.test.model_copy(update={"event": clean_event(r.test.event)}))
        else:
            out.append(t)
    return out, replaced


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
    # Ceiling of half the red-team tests: with one or two variants, exactly one may go.
    allowed = max(1, (len(redteam_tests) + 1) // 2) if redteam_tests else 0
    retired: list[TestEvent] = []
    kept: list[TestEvent] = []
    for t in tests:
        if t.id in reasons and t.id.startswith("R") and len(retired) < allowed:
            retired.append(t.model_copy(update={"description": f"{t.description} [retired: {reasons[t.id] or 'unreachable for this logsource'}]"}))
        else:
            kept.append(t)
    return kept, retired


def _introduces_only_known_fields(new: TestEvent, old: TestEvent, tests: list[TestEvent]) -> bool:
    """True when every field the corrected positive adds exists in some other positive event."""
    known = {k.lower() for t in tests if t.label == "positive" and t.id != old.id for k in t.event}
    added = {k.lower() for k in new.event} - {k.lower() for k in old.event}
    return added <= known
