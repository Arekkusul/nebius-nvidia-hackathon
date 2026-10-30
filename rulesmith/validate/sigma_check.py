"""Parse and lint a Sigma rule with pySigma plus RuleSmith's own checks.

This is the static half of the validate stage: it never executes the rule,
it only decides whether the rule is well-formed, uses real fields and ATT&CK
ids, and is not obviously too broad or logically impossible. ``runner`` does
the execution.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

import yaml
from sigma.exceptions import SigmaError
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

from ..models import ValidationIssue
from .attack import AttackIndex
from .fields import FieldDictionary

REQUIRED_KEYS = ["title", "logsource", "detection"]
RECOMMENDED_KEYS = ["id", "status", "description", "author", "date", "tags", "falsepositives", "level"]
# attack.t1059 or attack.t1059.001, capturing the technique id; tactic tags do not match.
_ATTACK_TAG_RX = re.compile(r"^attack\.(t\d{4}(\.\d{3})?)$", re.IGNORECASE)

# Image/ParentImage values that are so common a rule keyed only on them is noise.
_UBIQUITOUS_BINARIES = {"cmd.exe", "powershell.exe", "pwsh.exe", "svchost.exe", "explorer.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe", "mshta.exe", "msiexec.exe", "conhost.exe", "bash", "sh", "python3", "python"}


def _walk_items(det: SigmaDetection | SigmaDetectionItem) -> list[SigmaDetectionItem]:
    """Flatten a SigmaDetection tree into its leaf detection items."""
    if isinstance(det, SigmaDetectionItem):
        return [det]
    out: list[SigmaDetectionItem] = []
    for item in det.detection_items:
        out.extend(_walk_items(item))
    return out


def rule_fields(rule: SigmaRule) -> set[str]:
    """Every field name referenced anywhere in the detection section."""
    fields: set[str] = set()
    for det in rule.detection.detections.values():
        for item in _walk_items(det):
            if item.field:
                fields.add(item.field)
    return fields


def _selection_items(rule: SigmaRule) -> list[SigmaDetectionItem]:
    """Items from the non-filter selections (name does not start with 'filter')."""
    out: list[SigmaDetectionItem] = []
    for name, det in rule.detection.detections.items():
        if name.lower().startswith("filter"):
            continue
        out.extend(_walk_items(det))
    return out


_CONDITION_KEYWORDS = {"and", "or", "not", "of", "them", "all", "1", "any"}
# A word in a condition string: selection names, keywords and wildcard
# patterns like ``selection_*`` (hence ``*`` and ``|`` inside the class).
_CONDITION_IDENT_RX = re.compile(r"[A-Za-z_][A-Za-z0-9_.*|:\-]*")
# Keys of the old Sigma aggregation / correlation syntax. A "selection" made
# only of these is a time-window block the model smuggled in, not field tests.
_PSEUDO_SELECTION_KEYS = {"timeframe", "within", "value", "timespan", "group-by", "group_by", "selection", "condition", "count", "threshold", "window", "by", "aggregation"}


def _condition_issues(detection: dict[str, Any]) -> list[ValidationIssue]:
    """Catch the two ways models most often write an impossible Sigma rule.

    1. The condition names something that is not a selection (a field name,
       a value), which pySigma reports only as a parser position.
    2. Selections joined by AND pin the same field to different exact values
       (``eventName: CreateUser`` and ``eventName: CreateAccessKey``). That is
       a multi-event correlation written as a single-event rule; it can never
       match. Models do this for every "sequence of API calls" behaviour.
    """
    issues: list[ValidationIssue] = []
    condition = str(detection.get("condition", "") or "")
    names = {k for k in detection if k != "condition"}
    if not condition:
        issues.append(ValidationIssue(severity="error", code="no_condition", message="detection has no 'condition'."))
        return issues

    # 1. identifiers in the condition must be selection names or wildcard patterns of them
    for ident in _CONDITION_IDENT_RX.findall(condition):
        low = ident.lower()
        if low in _CONDITION_KEYWORDS or low.isdigit():
            continue
        if ident in names:
            continue
        if "*" in ident and any(re.fullmatch(ident.replace("*", ".*"), n) for n in names):
            continue
        issues.append(
            ValidationIssue(
                severity="error",
                code="condition_unknown_name",
                message=f"condition references '{ident}', which is not a selection name. The condition may only combine selection names ({', '.join(sorted(names)) or 'none defined'}) with and/or/not/1 of/all of; put field tests inside a selection.",
            )
        )

    # pseudo-selections (timeframe/within) betray a correlation written as a rule
    for name in names:
        body = detection.get(name)
        if isinstance(body, dict) and body and {k.lower() for k in body} <= _PSEUDO_SELECTION_KEYS:
            issues.append(
                ValidationIssue(
                    severity="error",
                    code="correlation_not_supported",
                    message=f"'{name}' is a time-window/correlation block, not a selection. A Sigma rule matches ONE event; sequences of events need one rule per step. Keep the single most distinctive event and drop the window.",
                )
            )

    # 2. contradictory AND: same field, different exact values, no OR anywhere in the condition
    for field, by_sel in contradictory_selection_groups(detection):
        detail = ", ".join(f"{sel} wants {field}{'|' + mod if mod else ''}={val}" for sel, (mod, val) in by_sel.items())
        issues.append(
            ValidationIssue(
                severity="error",
                code="contradictory_selections",
                message=f"Selections joined by AND pin '{field}' to different values ({detail}); one event cannot satisfy both. A Sigma rule matches ONE event, so a multi-step sequence must become one rule per step or a single rule for the most distinctive step.",
            )
        )
    return issues


def contradictory_selection_groups(detection: dict[str, Any]) -> list[tuple[str, dict[str, tuple[str, str]]]]:
    """Find AND-joined selections that pin one field to incompatible values.

    Returns ``[(field, {selection: (modifier, value)}), ...]``; empty when the
    condition contains OR / ``of`` (overlap is then legitimate) or nothing
    conflicts. Shared by the linter and by the author stage's automatic
    reduction of a multi-step chain to its most specific step.
    """
    condition = str(detection.get("condition", "") or "")
    names = {k for k in detection if k != "condition"}
    cond = f" {condition.lower()} "
    if " and " not in cond or " or " in cond or " of " in cond:
        return []
    # Selections that appear in the condition as a whole word (not as part of
    # a longer name or a wildcard) and are not negated.
    anded = [n for n in names if re.search(rf"(?<![\w*]){re.escape(n)}(?![\w*])", condition) and not re.search(rf"not\s+{re.escape(n)}\b", condition)]
    pinned: dict[str, dict[str, tuple[str, str]]] = {}  # field -> {selection: (modifier, value)}
    for n in anded:
        body = detection.get(n)
        if not isinstance(body, dict):
            continue
        for key, value in body.items():
            field, _, modifier = key.partition("|")
            # Exact, endswith and startswith pin a value; contains/re/lists can legitimately overlap.
            if modifier not in ("", "endswith", "startswith") or isinstance(value, (list, dict)) or value is None:
                continue
            pinned.setdefault(field, {})[n] = (modifier, str(value).lower())
    return [(field, by_sel) for field, by_sel in pinned.items() if len(by_sel) > 1 and not _values_compatible(list(by_sel.values()))]


def _values_compatible(pins: list[tuple[str, str]]) -> bool:
    """Can one event value satisfy every (modifier, value) pin at once?

    Exact values must be equal; ``endswith`` pins must be suffixes of one
    another (``\\cmd.exe`` and ``\\system32\\cmd.exe`` are fine, ``\\cmd.exe``
    and ``\\powershell.exe`` are not); likewise prefixes for ``startswith``.
    Mixed modifiers are assumed compatible (too uncertain to flag).
    """
    for i, (mod_a, val_a) in enumerate(pins):
        for mod_b, val_b in pins[i + 1 :]:
            if mod_a != mod_b:
                continue
            if mod_a == "" and val_a != val_b:
                return False
            if mod_a == "endswith" and not (val_a.endswith(val_b) or val_b.endswith(val_a)):
                return False
            if mod_a == "startswith" and not (val_a.startswith(val_b) or val_b.startswith(val_a)):
                return False
    return True


def check_rule(
    sigma_yaml: str,
    *,
    attack: AttackIndex | None = None,
    expected_techniques: list[str] | None = None,
    fields: FieldDictionary | None = None,
) -> tuple[SigmaRule | None, list[ValidationIssue]]:
    """Parse the YAML and collect issues. Returns (rule or None, issues)."""
    issues: list[ValidationIssue] = []
    attack = attack or AttackIndex()
    fields = fields or FieldDictionary()

    # --- YAML level -------------------------------------------------------
    try:
        raw: Any = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError as exc:
        issues.append(ValidationIssue(severity="error", code="yaml_invalid", message=f"YAML does not parse: {str(exc)[:300]}"))
        return None, issues
    if not isinstance(raw, dict):
        issues.append(ValidationIssue(severity="error", code="yaml_not_mapping", message="Rule must be a YAML mapping."))
        return None, issues
    for key in REQUIRED_KEYS:
        if key not in raw:
            issues.append(ValidationIssue(severity="error", code="missing_key", message=f"Required key '{key}' is missing."))
    if any(i.severity == "error" for i in issues):
        return None, issues
    for key in RECOMMENDED_KEYS:
        if key not in raw:
            issues.append(ValidationIssue(severity="warning", code="missing_recommended", message=f"Recommended key '{key}' is missing."))

    # --- Condition sanity (before pySigma, whose errors are cryptic) --------
    detection = raw.get("detection") if isinstance(raw.get("detection"), dict) else {}
    issues.extend(_condition_issues(detection))
    if any(i.severity == "error" for i in issues):
        return None, issues

    # --- pySigma level ----------------------------------------------------
    try:
        rule = SigmaRule.from_dict(raw)
    except SigmaError as exc:
        issues.append(ValidationIssue(severity="error", code="sigma_invalid", message=f"pySigma rejected the rule: {str(exc)[:300]}"))
        return None, issues
    except Exception as exc:  # noqa: BLE001 - surface anything else as a rule error
        issues.append(ValidationIssue(severity="error", code="sigma_invalid", message=f"Rule could not be loaded: {str(exc)[:300]}"))
        return None, issues

    # id must be a UUID so the rule can live in a SigmaHQ-style repo.
    rid = raw.get("id")
    if rid is not None:
        try:
            uuid.UUID(str(rid))
        except ValueError:
            issues.append(ValidationIssue(severity="warning", code="id_not_uuid", message="Rule id should be a UUID."))

    # --- ATT&CK tags ------------------------------------------------------
    tag_techniques: list[str] = []
    for tag in raw.get("tags") or []:
        m = _ATTACK_TAG_RX.match(str(tag))
        if m:
            tag_techniques.append(m.group(1).upper())
    if not tag_techniques:
        issues.append(ValidationIssue(severity="warning", code="no_attack_tag", message="No attack.tXXXX tag; add the ATT&CK technique."))
    for tid in tag_techniques:
        if not attack.is_valid_format(tid):
            issues.append(ValidationIssue(severity="error", code="attack_id_format", message=f"'{tid}' is not a valid ATT&CK technique id."))
        # Existence is only checked when the bundled index loaded; an empty index must not fail every rule.
        elif attack.techniques and not attack.exists(tid):
            issues.append(ValidationIssue(severity="error", code="attack_id_unknown", message=f"ATT&CK technique {tid} does not exist in the current ATT&CK release."))
        elif attack.is_deprecated(tid):
            issues.append(ValidationIssue(severity="warning", code="attack_id_deprecated", message=f"ATT&CK technique {tid} ({attack.name(tid)}) is deprecated or revoked."))
    if expected_techniques:
        expected = {attack.normalize(t) for t in expected_techniques}
        got = set(tag_techniques)
        # Accept the parent technique when the plan asked for a sub-technique.
        got_parents = {attack.parent(t) for t in got}
        if not (expected & got) and not ({attack.parent(t) for t in expected} & got_parents):
            issues.append(ValidationIssue(severity="warning", code="attack_tag_mismatch", message=f"Tags {sorted(got)} do not cover the planned techniques {sorted(expected)}."))

    # --- Field dictionary -------------------------------------------------
    ls = rule.logsource
    allowed = fields.known_fields(ls.category, ls.product, ls.service)
    used = rule_fields(rule)
    if allowed is None:
        issues.append(ValidationIssue(severity="info", code="logsource_unknown", message=f"No field dictionary for logsource {ls.product}/{ls.category or ls.service}; field names were not checked."))
    else:
        strict = fields.is_strict(ls.category)
        for f in sorted(used):
            if not fields.check(f, allowed):
                sev = "error" if strict else "warning"
                # A dozen known fields is enough to steer the refine prompt without flooding it.
                issues.append(ValidationIssue(severity=sev, code="unknown_field", message=f"Field '{f}' is not a known field for {ls.product}/{ls.category or ls.service}. Known fields include: {', '.join(sorted(allowed)[:12])}..."))
    if not used and not any(_walk_items(d) for d in rule.detection.detections.values()):
        issues.append(ValidationIssue(severity="error", code="empty_detection", message="Detection section has no selections."))

    # --- Breadth heuristics ------------------------------------------------
    # Filters are excluded on purpose: a filter_* block legitimately names a
    # ubiquitous binary to carve out benign activity.
    items = _selection_items(rule)
    if items and all(
        (it.field or "").lower() in {"image", "parentimage"}
        and all(str(v).lower().split("\\")[-1] in _UBIQUITOUS_BINARIES for v in it.value)
        for it in items
    ):
        issues.append(ValidationIssue(severity="error", code="over_broad", message="Detection keys only on a ubiquitous binary name (e.g. powershell.exe) with no command-line, parent or target constraint; this will fire constantly."))
    for it in items:
        for v in it.value:
            s = str(v)
            if s in {"*", "", "%"}:
                issues.append(ValidationIssue(severity="error", code="wildcard_only", message=f"Field '{it.field}' matches everything ('{s}')."))
            # pySigma names its modifier classes SigmaContainsModifier etc.; matching
            # on the class name avoids importing every modifier type.
            elif len(s.strip("*")) <= 2 and any(m.__class__.__name__.lower().startswith("sigmacontains") for m in it.modifiers):
                issues.append(ValidationIssue(severity="warning", code="short_contains", message=f"'{it.field}|contains: {s}' is very short and likely noisy."))

    # --- Level / status sanity ---------------------------------------------
    level = str(raw.get("level", "")).lower()
    if level and level not in {"informational", "low", "medium", "high", "critical"}:
        issues.append(ValidationIssue(severity="error", code="bad_level", message=f"level '{level}' is not a Sigma level."))
    status = str(raw.get("status", "")).lower()
    if status and status not in {"stable", "test", "experimental", "deprecated", "unsupported"}:
        issues.append(ValidationIssue(severity="error", code="bad_status", message=f"status '{status}' is not a Sigma status."))

    return rule, issues
