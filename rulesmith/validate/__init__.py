"""Deterministic validation of generated Sigma rules.

No LLM is involved here. A rule passes only if it parses, uses real fields
and ATT&CK ids, compiles to SQL, matches every positive test event, matches
no negative test event, and stays silent on the benign baseline corpus.
"""

from __future__ import annotations

from typing import Any

import yaml
from sigma.rule import SigmaRule

from ..models import RuleDraft, TestEvent, ValidationIssue, ValidationReport
from .attack import AttackIndex
from .corpus import BenignCorpus
from .runner import RuleRunner, compile_rule
from .sigma_check import _walk_items, check_rule

__all__ = ["AttackIndex", "BenignCorpus", "RuleRunner", "check_rule", "compile_rule", "explain_selections", "validate_rule"]


def explain_selections(raw_rule: dict[str, Any], event: dict[str, Any]) -> str:
    """Say which named selections of a rule match one event, and why not.

    Each selection is compiled on its own (``condition: <name>``) and run
    against the event. The result reads like
    ``selection_img=match; selection_proto=NO MATCH (event lacks Protocol)``,
    which is exactly the evidence the refine stage needs to fix the right
    side (rule or test) instead of guessing.
    """
    detection = raw_rule.get("detection") or {}
    event_keys = {k.lower() for k in event}
    notes: list[str] = []
    for name, body in detection.items():
        if name == "condition" or not isinstance(body, (dict, list)):
            continue
        sub = dict(raw_rule)
        sub["detection"] = {name: body, "condition": name}
        try:
            rule = SigmaRule.from_dict(sub)
            hit = bool(RuleRunner(compile_rule(rule)).match_indices([event]))
            fields = sorted({it.field for it in _walk_items(rule.detection.detections[name]) if it.field})
        except Exception as exc:  # noqa: BLE001 - a selection that will not compile on its own is reported by the linter
            notes.append(f"{name}=could not evaluate ({str(exc)[:80]})")
            continue
        missing = [f for f in fields if f.lower() not in event_keys]
        note = f"{name}={'match' if hit else 'NO MATCH'}"
        if not hit and missing:
            note += f" (event lacks {', '.join(missing)})"
        notes.append(note)
    return "; ".join(notes)


def validate_rule(
    draft: RuleDraft,
    *,
    corpus: BenignCorpus | None = None,
    attack: AttackIndex | None = None,
    expected_techniques: list[str] | None = None,
    max_benign_examples: int = 5,
) -> ValidationReport:
    """Run every check on one draft and return a structured report."""
    report = ValidationReport(candidate_id=draft.candidate_id)

    # 1. Parse + lint (fields, tags, ATT&CK ids, breadth heuristics).
    parsed, issues = check_rule(draft.sigma_yaml, attack=attack, expected_techniques=expected_techniques)
    report.issues.extend(issues)
    report.parse_ok = parsed is not None
    if parsed is None:
        report.passed = False
        return report

    # 2. Compile to SQL.
    try:
        sql = compile_rule(parsed)
    except Exception as exc:  # noqa: BLE001 - any backend failure is a rule problem
        report.issues.append(ValidationIssue(severity="error", code="compile_failed", message=f"SQLite backend could not compile the rule: {str(exc)[:300]}"))
        report.passed = False
        return report
    report.sql = sql

    # 3. Execute against the draft's own tests.
    runner = RuleRunner(sql)
    tests: list[TestEvent] = list(draft.tests)
    report.positives_total = sum(1 for t in tests if t.label == "positive")
    report.negatives_total = sum(1 for t in tests if t.label == "negative")
    if report.positives_total == 0:
        report.issues.append(ValidationIssue(severity="error", code="no_positive_tests", message="The rule has no positive test events, so nothing proves it fires."))
    try:
        outcomes = runner.run_tests(tests)
    except Exception as exc:  # noqa: BLE001 - a malformed event must not take the whole run down
        report.issues.append(ValidationIssue(severity="error", code="runner_failed", message=f"Could not execute the rule against the test events: {str(exc)[:300]}"))
        report.passed = False
        return report
    report.test_outcomes = outcomes
    report.positives_matched = sum(1 for o in outcomes if o.label == "positive" and o.matched)
    report.negatives_matched = sum(1 for o in outcomes if o.label == "negative" and o.matched)
    raw_rule = yaml.safe_load(draft.sigma_yaml)  # parsed once already; cheap
    for o in outcomes:
        if not o.passed:
            t = next(t for t in tests if t.id == o.event_id)
            why = explain_selections(raw_rule, t.event) if isinstance(raw_rule, dict) else ""
            detail = f" Per selection: {why}." if why else ""
            if o.label == "positive":
                report.issues.append(ValidationIssue(severity="error", code="positive_missed", message=f"Positive test {t.id} did not match: {t.description}.{detail}"))
            else:
                report.issues.append(ValidationIssue(severity="error", code="negative_matched", message=f"Negative (benign) test {t.id} matched: {t.description}.{detail}"))

    # 4. Execute against the benign baseline corpus for the rule's logsource.
    if corpus is not None:
        logsource = parsed.logsource
        benign = corpus.events_for(category=logsource.category, product=logsource.product, service=logsource.service)
        report.benign_total = len(benign)
        if benign:
            try:
                hits = runner.run_events(benign)
            except Exception as exc:  # noqa: BLE001 - same reasoning as above
                report.issues.append(ValidationIssue(severity="error", code="runner_failed", message=f"Could not execute the rule against the benign corpus: {str(exc)[:300]}"))
                report.passed = False
                return report
            report.benign_hits = len(hits)
            report.benign_examples = [corpus.strip_meta(e) for e in hits[:max_benign_examples]]
            if hits:
                report.issues.append(
                    ValidationIssue(
                        severity="error",
                        code="benign_noise",
                        message=f"Rule fired on {len(hits)} of {len(benign)} benign baseline events; it is too broad for production.",
                    )
                )

    report.passed = not any(i.severity == "error" for i in report.issues)
    return report
