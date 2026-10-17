"""Stage 4: rule authoring with tests (Nemotron main tier)."""

from __future__ import annotations

import json
import re
import uuid
from datetime import date
from typing import Any

import yaml

from .config import TIER_MAIN
from .llm import BaseLLM
from .models import DetectionCandidate, RuleDraft, TestEvent, ThreatReport, UsageRecord
from .prompts import AUTHOR_SYSTEM
from .validate.fields import FieldDictionary

AUTHOR_NAME = "RuleSmith (Nemotron via Nebius Token Factory)"
# Canonical SigmaHQ key order for pretty output.
KEY_ORDER = ["title", "id", "related", "status", "description", "references", "author", "date", "modified", "tags", "logsource", "detection", "fields", "falsepositives", "level"]


class _Dumper(yaml.SafeDumper):
    """YAML dumper that keeps block style and does not sort keys."""


def _str_presenter(dumper: yaml.SafeDumper, data: str):  # type: ignore[no-untyped-def]
    # Quote strings that contain YAML-sensitive characters so values like
    # '\rundll32.exe' or '*' round-trip unchanged.
    style = "'" if any(ch in data for ch in "\\*?:#{}[]&|>!%@`\"'") or data.strip() != data else None
    if "\n" in data:
        style = "|"
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


_Dumper.add_representer(str, _str_presenter)


def dump_rule(raw: dict[str, Any]) -> str:
    """Serialise a rule dict in canonical key order."""
    ordered = {k: raw[k] for k in KEY_ORDER if k in raw}
    ordered.update({k: v for k, v in raw.items() if k not in ordered})
    return yaml.dump(ordered, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=120, default_flow_style=False)


def normalize_rule_yaml(sigma_yaml: str, *, candidate: DetectionCandidate | None = None, references: list[str] | None = None) -> str:
    """Fill in housekeeping fields the model often gets wrong.

    Guarantees a UUID id, today's date, an author, a status, references and
    the planned ATT&CK tags. Leaves detection logic untouched. Returns the
    input unchanged if it is not parseable YAML (the validator will report).
    """
    try:
        raw = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError:
        return sigma_yaml
    if not isinstance(raw, dict):
        return sigma_yaml
    rid = str(raw.get("id", ""))
    try:
        uuid.UUID(rid)
    except ValueError:
        raw["id"] = str(uuid.uuid4())
    raw.setdefault("status", "experimental")
    raw.setdefault("author", AUTHOR_NAME)
    # Dates arrive as date objects from YAML or as strings from the model.
    d = raw.get("date")
    raw["date"] = d.isoformat() if isinstance(d, date) else (str(d) if d and re.match(r"^\d{4}-\d{2}-\d{2}$", str(d)) else date.today().isoformat())
    if "modified" in raw and isinstance(raw["modified"], date):
        raw["modified"] = raw["modified"].isoformat()
    refs = [r for r in (raw.get("references") or []) if isinstance(r, str) and r.strip()]
    for r in references or []:
        if r not in refs and not r.startswith("example://"):
            refs.append(r)
    if refs:
        raw["references"] = refs
    tags = [str(t).lower() for t in (raw.get("tags") or [])]
    if candidate:
        for tid in candidate.attack_technique_ids:
            tag = f"attack.{tid.lower()}"
            if tag not in tags:
                tags.append(tag)
    if tags:
        raw["tags"] = tags
    if candidate and not raw.get("title"):
        raw["title"] = candidate.title
    raw.setdefault("falsepositives", ["Unknown"])
    raw.setdefault("level", "medium")
    return dump_rule(raw)


def _dedupe_tests(tests: list[TestEvent]) -> list[TestEvent]:
    """Give duplicate ids a suffix instead of letting them collide."""
    seen: dict[str, int] = {}
    out = []
    for t in tests:
        base = t.id or ("P" if t.label == "positive" else "N")
        n = seen.get(base, 0)
        seen[base] = n + 1
        out.append(t if n == 0 else t.model_copy(update={"id": f"{base}_{n}"}))
    return out


def author_rule(
    llm: BaseLLM,
    report: ThreatReport,
    candidate: DetectionCandidate,
    *,
    references: list[str] | None = None,
    fields: FieldDictionary | None = None,
) -> tuple[RuleDraft, UsageRecord]:
    """Write one Sigma rule plus tests for a planned candidate."""
    fields = fields or FieldDictionary()
    behaviours = [b.model_dump() for b in report.behaviors if b.id in candidate.behavior_ids] or [b.model_dump() for b in report.behaviors[:3]]
    ls = candidate.logsource
    allowed = fields.known_fields(ls.category, ls.product, ls.service)
    field_note = f"Valid fields for {ls.product}/{ls.category or ls.service}: {', '.join(sorted(allowed))}" if allowed else "Field dictionary unavailable for this logsource; use the standard Sigma taxonomy."
    user = (
        f"CANDIDATE (JSON):\n{json.dumps(candidate.model_dump(), indent=1)}\n\n"
        f"BEHAVIOURS COVERED (JSON):\n{json.dumps(behaviours, indent=1)}\n\n"
        f"Report context: {report.title}. {report.summary}\n"
        f"References: {json.dumps([r for r in (references or []) if not r.startswith('example://')])}\n"
        f"{field_note}\n\n"
        "Write the rule and at least 3 positive and 3 negative test events. candidate_id must be "
        f"'{candidate.id}'."
    )
    draft, usage = llm.complete_structured(stage="author", tier=TIER_MAIN, system=AUTHOR_SYSTEM, user=user, schema=RuleDraft, thinking=False)
    draft.candidate_id = candidate.id
    draft.sigma_yaml = normalize_rule_yaml(draft.sigma_yaml, candidate=candidate, references=references)
    draft.tests = _dedupe_tests(draft.tests)
    return draft, usage
