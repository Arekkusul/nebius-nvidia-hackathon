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
from .models import (
    AuthoredRule,
    DetectionCandidate,
    RuleDraft,
    SigmaRuleDoc,
    TestEvent,
    ThreatReport,
    UsageRecord,
)
from .prompts import AUTHOR_SYSTEM
from .sigmahq import SigmaHQExamples
from .validate.attack import TACTIC_TAGS, AttackIndex
from .validate.fields import FieldDictionary
from .validate.sigma_check import contradictory_selection_groups

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


def rule_doc_to_yaml(doc: SigmaRuleDoc) -> str:
    """Render the model's structured rule as Sigma YAML text."""
    return dump_rule(doc.to_dict())


_TECHNIQUE_TAG_RX = re.compile(r"^t\d{4}(\.\d{3})?$")


def normalize_tags(tags: list[Any]) -> list[str]:
    """Coerce model-written tags into valid Sigma ``attack.*`` tags.

    Models frequently drop the namespace (``t1059.001``, ``execution``) or use
    spaces/underscores in tactic names (``defense_evasion``); pySigma rejects
    any tag without a namespace dot. Unknown namespace-less tags are dropped.
    """
    out: list[str] = []
    for raw in tags or []:
        # Keep only characters a Sigma tag can contain; models sometimes leak
        # JSON punctuation into a tag ("attack.t1547.001],").
        tag = re.sub(r"[^a-z0-9._-]", "", str(raw).strip().lower()).strip(".-")
        if not tag:
            continue
        if tag.startswith("attack."):
            body = tag[len("attack."):]
            body = body.replace("_", "-").replace(" ", "-")
            tag = f"attack.{body}"
        elif _TECHNIQUE_TAG_RX.match(tag):
            tag = f"attack.{tag}"
        elif tag.replace("_", "-").replace(" ", "-") in TACTIC_TAGS:
            tag = "attack." + tag.replace("_", "-").replace(" ", "-")
        elif "." not in tag:
            # No namespace and not something we can repair: pySigma would reject it.
            continue
        if tag not in out:
            out.append(tag)
    return out


def normalize_rule_yaml(sigma_yaml: str, *, candidate: DetectionCandidate | None = None, references: list[str] | None = None, notes: list[str] | None = None) -> str:
    """Fill in housekeeping fields the model often gets wrong.

    Guarantees a UUID id, today's date, an author, a status, references and
    the planned ATT&CK tags; tidies the detection block (see
    ``clean_detection``) and reduces an impossible multi-step chain to one
    step (see ``resolve_contradictions``), appending a human-readable note to
    ``notes`` when it does. Returns the input unchanged if it is not
    parseable YAML (the validator will report).
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
    tags = normalize_tags(raw.get("tags") or [])
    if candidate:
        # The plan's technique ids come from the extraction tier, which does
        # hallucinate ids. Only add ones the bundled ATT&CK index knows (or
        # their parent technique), otherwise the validator would flag an
        # error the refine stage can never clear.
        index = AttackIndex()
        for tid in candidate.attack_technique_ids:
            tid = index.normalize(tid)
            if index.techniques and not index.exists(tid):
                parent = index.parent(tid)
                if parent != tid and index.exists(parent):
                    tid = parent
                else:
                    continue
            tag = f"attack.{tid.lower()}"
            if tag not in tags:
                tags.append(tag)
    if tags:
        raw["tags"] = tags
    if candidate and not raw.get("title"):
        raw["title"] = candidate.title
    if isinstance(raw.get("detection"), dict):
        raw["detection"], note = resolve_contradictions(clean_detection(raw["detection"]))
        if note and notes is not None:
            notes.append(note)
    raw.setdefault("falsepositives", ["Unknown"])
    raw.setdefault("level", "medium")
    return dump_rule(raw)


def _is_double_escaped(value: str) -> bool:
    """True when every backslash in ``value`` is part of ``\\\\`` or ``\\"``.

    That is the signature of a string the model JSON-escaped twice (it wrote
    ``"C:\\\\Windows"`` meaning ``C:\\Windows``). A real Windows path has
    backslashes followed by letters, so it never looks like this; a UNC path
    written correctly (``\\\\server\\share``) has single backslashes too.
    """
    if "\\" not in value:
        return False
    i = 0
    while i < len(value):
        if value[i] == "\\":
            nxt = value[i + 1] if i + 1 < len(value) else ""
            if nxt not in ("\\", '"'):
                return False
            i += 2
        else:
            i += 1
    return True


def decode_double_escaped(value: str) -> str:
    """Undo one level of JSON escaping when the model applied two.

    Nemotron frequently emits ``"C:\\\\Windows\\\\cmd.exe"`` inside JSON (two
    literal backslashes per separator) and ``\\"`` for quotes. Sigma treats
    ``\\\\`` as one backslash, so such test events never match a correct rule.
    Only strings that are unambiguously double-escaped are touched.
    """
    if not _is_double_escaped(value):
        return value
    return value.replace("\\\\", "\\").replace('\\"', '"')


_DEFANG_RXS = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}| \[dot\] |\[dot\]", re.IGNORECASE), "."),
    (re.compile(r"\bhxxps?://", re.IGNORECASE), lambda m: m.group(0).lower().replace("hxxp", "http")),
    (re.compile(r"\[:\]|\[://\]"), lambda m: "://" if "//" in m.group(0) else ":"),
    (re.compile(r"\[@\]"), "@"),
]


def refang(value: str) -> str:
    """Turn defanged indicators (``evil[.]com``, ``hxxp://``) back into real ones.

    Reports defang IOCs so readers cannot click them; a detection rule or a
    test event must use the real form or it will never match telemetry.
    """
    for rx, repl in _DEFANG_RXS:
        value = rx.sub(repl, value)
    return value


def _clean_value(value: Any) -> Any:
    """Normalise one string (or list of strings) as the model wrote it."""
    if isinstance(value, str):
        return refang(decode_double_escaped(value))
    if isinstance(value, list):
        return [_clean_value(x) for x in value]
    return value


def clean_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalise one test event's values (double-escaping, defanged indicators)."""
    return {k: _clean_value(v) for k, v in event.items()}


def clean_detection(detection: dict[str, Any]) -> dict[str, Any]:
    """Tidy the model's detection block without changing its logic.

    * refangs indicator values (``[.]`` -> ``.``), because the report text
      the model copies from is defanged;
    * drops fields whose value is empty (``ConditionList: []``), which the
      model occasionally leaks and which can never match anything.
    Backslashes are left alone: Sigma reads ``\\\\`` as one backslash, so a
    double-escaped path still means the right thing in a rule.
    """
    out: dict[str, Any] = {}
    for name, body in detection.items():
        if name == "condition":
            out[name] = body
            continue
        if isinstance(body, dict):
            kept = {_clean_key(f): _refang_value(v) for f, v in body.items() if v not in (None, "", [], {})}
            out[name] = kept
        elif isinstance(body, list):
            out[name] = [{_clean_key(f): _refang_value(v) for f, v in item.items() if v not in (None, "", [], {})} if isinstance(item, dict) else _refang_value(item) for item in body]
        else:
            out[name] = _refang_value(body)
    return ensure_condition(out)


def resolve_contradictions(detection: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Reduce a sequence-as-one-rule to its most specific step.

    Models write "wmic spawns cmd, then cmd spawns hidden powershell" as two
    AND-ed selections that pin ``Image`` to different binaries; no event can
    satisfy that and three refine rounds in the live runs never fixed it. A
    Sigma rule matches one event, so the chain is cut down to the selection
    with the most field tests (the most specific step), filters are kept, and
    the note explains what was dropped so the analyst can add the other
    steps as separate rules. Returns ``(detection, "")`` when nothing conflicts.
    """
    groups = contradictory_selection_groups(detection)
    if not groups:
        return detection, ""
    drop: set[str] = set()
    kept_for: list[str] = []
    for _field, by_sel in groups:
        keep = max(by_sel, key=lambda n: (len(detection.get(n) or {}), n))
        kept_for.append(keep)
        drop |= set(by_sel) - {keep}
    names = [n for n in detection if n != "condition" and n not in drop]
    selections = [n for n in names if not n.startswith("filter")]
    filters = [n for n in names if n.startswith("filter")]
    new = {n: detection[n] for n in names}
    new["condition"] = " and ".join(selections) + ("" if not filters else " and not " + " and not ".join(filters))
    note = f"Reduced a multi-step chain to its most specific step ({', '.join(sorted(set(kept_for)))}); dropped {', '.join(sorted(drop))} because one Sigma rule matches one event. Add the other steps as separate rules if needed."
    return new, note


def _clean_key(field: str) -> str:
    """Strip quotes and whitespace the model sometimes leaks into a field key.

    ``'userAgent|contains'`` (with the quotes inside the key) makes pySigma
    report an unknown modifier ``contains'``; the intent is unambiguous.
    """
    return field.strip().strip("'\"").strip()


def ensure_condition(detection: dict[str, Any]) -> dict[str, Any]:
    """Add the obvious ``condition`` when the model forgot it.

    Every selection is required and every ``filter_*`` excluded, which is
    what the cheat-sheet asks for and what the model writes when it does
    remember. A detection with no selections is left alone for the linter.
    """
    if detection.get("condition"):
        return detection
    names = [n for n in detection if n != "condition"]
    selections = [n for n in names if not n.startswith("filter")]
    filters = [n for n in names if n.startswith("filter")]
    if not selections:
        return detection
    condition = " and ".join(selections)
    if filters:
        condition += " and not " + " and not ".join(filters)
    return {**detection, "condition": condition}


def _refang_value(value: Any) -> Any:
    if isinstance(value, str):
        return refang(value)
    if isinstance(value, list):
        return [_refang_value(x) for x in value]
    return value


def clean_tests(tests: list[TestEvent]) -> list[TestEvent]:
    """Apply event normalisation and id de-duplication to model-written tests."""
    return _dedupe_tests([t.model_copy(update={"event": clean_event(t.event)}) for t in tests])


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
    examples: SigmaHQExamples | None = None,
) -> tuple[RuleDraft, UsageRecord]:
    """Write one Sigma rule plus tests for a planned candidate.

    ``examples`` supplies a few SigmaHQ rules for the same logsource and
    technique as few-shot grounding; without it the model works from the
    cheat-sheet alone.
    """
    fields = fields or FieldDictionary()
    behaviours = [b.model_dump() for b in report.behaviors if b.id in candidate.behavior_ids] or [b.model_dump() for b in report.behaviors[:3]]
    ls = candidate.logsource
    allowed = fields.known_fields(ls.category, ls.product, ls.service)
    field_note = f"Valid fields for {ls.product}/{ls.category or ls.service}: {', '.join(sorted(allowed))}" if allowed else "Field dictionary unavailable for this logsource; use the standard Sigma taxonomy."
    # Three community rules for the same logsource/technique show the model
    # the field idioms that actually survive in production.
    shots = SigmaHQExamples.render(examples.find(ls, candidate.attack_technique_ids, candidate.title, k=3)) if examples else ""
    user = (
        f"CANDIDATE (JSON):\n{json.dumps(candidate.model_dump(), indent=1)}\n\n"
        f"BEHAVIOURS COVERED (JSON):\n{json.dumps(behaviours, indent=1)}\n\n"
        f"Report context: {report.title}. {report.summary}\n"
        f"References: {json.dumps([r for r in (references or []) if not r.startswith('example://')])}\n"
        f"{field_note}\n\n"
        + (f"{shots}\n\n" if shots else "")
        + "Write the rule and at least 3 positive and 3 negative test events. candidate_id must be "
        f"'{candidate.id}'."
    )
    authored, usage = llm.complete_structured(stage="author", tier=TIER_MAIN, system=AUTHOR_SYSTEM, user=user, schema=AuthoredRule, thinking=False)
    # The model hands back a structured rule; we own the YAML rendering and
    # the housekeeping fields, so the draft is always well-formed YAML.
    notes: list[str] = []
    sigma_yaml = normalize_rule_yaml(rule_doc_to_yaml(authored.rule), candidate=candidate, references=references, notes=notes)
    author_notes = " ".join([authored.author_notes, *notes]).strip()
    draft = RuleDraft(candidate_id=candidate.id, sigma_yaml=sigma_yaml, tests=clean_tests(authored.tests), author_notes=author_notes)
    return draft, usage
