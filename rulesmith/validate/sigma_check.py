"""Parse and lint a Sigma rule with pySigma plus RuleSmith's own checks."""

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
                issues.append(ValidationIssue(severity=sev, code="unknown_field", message=f"Field '{f}' is not a known field for {ls.product}/{ls.category or ls.service}. Known fields include: {', '.join(sorted(allowed)[:12])}..."))
    if not used and not any(_walk_items(d) for d in rule.detection.detections.values()):
        issues.append(ValidationIssue(severity="error", code="empty_detection", message="Detection section has no selections."))

    # --- Breadth heuristics ------------------------------------------------
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
