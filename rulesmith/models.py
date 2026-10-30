"""Pydantic schemas shared by every pipeline stage.

These double as the JSON schemas handed to Nemotron through Token Factory's
``response_format={"type": "json_schema"}``. Keep field descriptions crisp:
the model reads them.

The sections below follow the pipeline order (extract -> plan -> author ->
validate -> refine/red-team) and end with the run-level containers that the
server, packager and eval harness consume.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, model_validator

# --------------------------------------------------------------------------
# Stage 2: behaviour extraction
# --------------------------------------------------------------------------

ObservableKind = Literal[
    "process_name",
    "command_line",
    "parent_process",
    "registry_key",
    "registry_value",
    "file_path",
    "file_name",
    "dll",
    "service_name",
    "scheduled_task",
    "named_pipe",
    "wmi",
    "powershell_script",
    "network_domain",
    "network_ip",
    "network_port",
    "url",
    "user_agent",
    "event_id",
    "cloud_api",
    "other",
]


class Observable(BaseModel):
    """A concrete, loggable artifact mentioned in the report."""

    kind: ObservableKind = Field(description="What sort of artifact this is.")
    value: str = Field(description="The literal value as written in the report, e.g. 'rundll32.exe' or '-EncodedCommand'.")
    note: str = Field(default="", description="Short context, e.g. 'used to launch the loader'.")


class LogSourceHint(BaseModel):
    """Where this behaviour would show up in telemetry, in Sigma terms."""

    category: str = Field(description="Sigma logsource category, e.g. process_creation, registry_set, network_connection, dns_query, file_event, image_load, ps_script, process_access, create_remote_thread.")
    product: str = Field(description="Sigma logsource product, e.g. windows, linux, macos, aws, azure, okta, m365.")
    service: str = Field(default="", description="Optional Sigma logsource service, e.g. sysmon, security, powershell, cloudtrail.")


class Behavior(BaseModel):
    """An attacker behaviour (TTP) worth detecting, grounded in the report."""

    id: str = Field(description="Short id like B1, B2 ...")
    description: str = Field(description="One or two sentences describing what the attacker does, in telemetry-relevant terms.")
    attack_technique_id: str = Field(description="MITRE ATT&CK technique id such as T1059.001. Use the most specific sub-technique you are confident in.")
    attack_tactic: str = Field(description="ATT&CK tactic name, e.g. Execution, Persistence, Defense Evasion.")
    observables: list[Observable] = Field(default_factory=list, description="Concrete artifacts a sensor would record.")
    logsource: LogSourceHint
    evidence: str = Field(description="Verbatim quote (max ~300 chars) from the report that supports this behaviour.")
    confidence: float = Field(ge=0.0, le=1.0, description="How confident you are the report really describes this behaviour.")
    detectable: bool = Field(description="True if endpoint/cloud telemetry could realistically observe this behaviour.")


class IOC(BaseModel):
    """Atomic indicator. Useful for blocklists, weak for durable detection."""

    type: Literal["sha256", "sha1", "md5", "ip", "domain", "url", "email", "filename", "mutex", "other"]
    value: str


# ---- IOC hygiene -----------------------------------------------------------
# The extraction model is asked for atomic values, but it still sometimes
# returns a description ("Tor exit node"), a placeholder ("hash not provided"),
# a mistyped value (an AWS account id as an ip) or a legitimate service the
# actor merely used (github.com). None of those belong on a blocklist, so every
# ThreatReport runs its IOC list through sanitize_iocs() on construction, which
# covers live extraction and recorded runs alike.

# Hex digests by type: anything else labelled as a hash is a description.
_HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64}
# One DNS label (RFC 1035 shape: 1-63 chars, no leading/trailing hyphen); the
# domain regex wants at least one label plus an alphabetic TLD, so a bare word
# such as "localhost" or a sentence never passes as a domain.
_HOST_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DOMAIN_RE = re.compile(rf"^(?:{_HOST_LABEL}\.)+[a-z]{{2,63}}$")
_EMAIL_RE = re.compile(r"^[^\s@]+@(?:[a-z0-9-]+\.)+[a-z]{2,63}$", re.IGNORECASE)
# Scheme plus anything without whitespace; hxxp(s) is the defanged form reports use.
_URL_RE = re.compile(r"^(?:https?|hxxps?|ftp)://[^\s]+$", re.IGNORECASE)
# Phrases that mean the model described an indicator instead of copying it.
_PLACEHOLDER_RE = re.compile(r"not provided|not given|not available|not disclosed|unknown|redacted|\bn/a\b|\btbd\b|\.\.\.", re.IGNORECASE)
# Infrastructure every organisation uses: flagging it would only create noise.
# Matched on the registered domain, so s3.amazonaws.com and raw.githubusercontent.com are covered.
_BENIGN_DOMAINS = {
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "amazonaws.com", "amazon.com", "awsstatic.com", "microsoft.com", "windows.net",
    "windowsupdate.com", "office.com", "office365.com", "live.com", "azure.com",
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "apple.com",
    "cloudfront.net", "cloudflare.com", "akamaihd.net", "digicert.com", "python.org",
    "pypi.org", "npmjs.com", "docker.com", "docker.io", "ubuntu.com", "debian.org",
    "centos.org", "sourceforge.net", "wikipedia.org", "mozilla.org",
}


def _refang(value: str) -> str:
    """Undo the usual defanging so 'evil[.]com' and 'hxxp://' can be validated."""
    v = value.strip()
    # "[.]", "[:]", "[@]" and the round-bracket and curly-bracket variants.
    v = re.sub(r"\[(\.|:|@)\]", r"\1", v)
    v = re.sub(r"\((\.|:|@)\)", r"\1", v)
    v = v.replace("{.}", ".")
    return re.sub(r"^hxxp", "http", v, flags=re.IGNORECASE)


def _registered_domain(host: str) -> str:
    """Rough registrable domain: the last two labels, or three for 'co.uk' style suffixes."""
    labels = host.lower().split(".")
    if len(labels) >= 3 and len(labels[-2]) <= 3 and labels[-1] in {"uk", "au", "nz", "jp", "br", "za", "in"}:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _ioc_is_valid(kind: str, value: str) -> bool:
    """True when `value` has the shape the declared type requires."""
    v = _refang(value)
    if not v or _PLACEHOLDER_RE.search(v):
        return False
    if kind in _HASH_LEN:
        return re.fullmatch(rf"[0-9a-fA-F]{{{_HASH_LEN[kind]}}}", v) is not None
    if kind == "ip":
        try:
            # Accept CIDR notation by validating only the address part.
            ipaddress.ip_address(v.split("/")[0])
            return True
        except ValueError:
            return False
    if kind == "domain":
        host = v.lower().rstrip(".")  # tolerate the fully-qualified trailing dot
        return _DOMAIN_RE.match(host) is not None and _registered_domain(host) not in _BENIGN_DOMAINS
    if kind == "url":
        if not _URL_RE.match(v):
            return False
        # Host = everything after "scheme://" up to the first "/", minus any
        # "user@" prefix and ":port" suffix.
        host = re.sub(r"^[a-z]+://", "", v, flags=re.IGNORECASE).split("/")[0].split("@")[-1].split(":")[0].lower()
        return _registered_domain(host) not in _BENIGN_DOMAINS
    if kind == "email":
        return _EMAIL_RE.match(v) is not None
    # filename, mutex, other: anything that reads as a sentence is a description, not a value.
    words = v.split()
    return len(words) <= 3 and not v.endswith((".", ":")) and "(" not in v


def sanitize_iocs(iocs: list[IOC]) -> list[IOC]:
    """Keep only well-formed, de-duplicated, attacker-relevant indicators."""
    seen: set[tuple[str, str]] = set()
    kept: list[IOC] = []
    for ioc in iocs:
        value = ioc.value.strip()
        key = (ioc.type, _refang(value).lower())
        if key in seen or not _ioc_is_valid(ioc.type, value):
            continue
        seen.add(key)
        kept.append(IOC(type=ioc.type, value=value))
    return kept


class ThreatReport(BaseModel):
    """Structured understanding of one threat-intel document."""

    title: str
    summary: str = Field(description="3-5 sentence executive summary of the campaign/malware and its kill chain.")
    threat_actors: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list, description="Targeted sectors, regions or platforms.")
    behaviors: list[Behavior] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)

    @model_validator(mode="after")
    def _clean_iocs(self) -> ThreatReport:
        """Drop descriptive, placeholder, mistyped or benign-service indicators."""
        self.iocs = sanitize_iocs(self.iocs)
        return self


# --------------------------------------------------------------------------
# Stage 3: detection planning
# --------------------------------------------------------------------------


class DetectionCandidate(BaseModel):
    """One rule the agent intends to write."""

    id: str = Field(description="Short id like D1, D2 ...")
    title: str = Field(description="Human-readable rule title in SigmaHQ style, e.g. 'Rundll32 Execution Of DLL From Temp Directory'.")
    behavior_ids: list[str] = Field(description="Behaviour ids this rule covers.")
    attack_technique_ids: list[str] = Field(description="ATT&CK technique ids covered.")
    logsource: LogSourceHint
    rationale: str = Field(description="Why this behaviour is worth a rule and how to keep it specific.")
    key_fields: list[str] = Field(description="Sigma/Sysmon field names the rule will key on, e.g. Image, CommandLine, ParentImage, TargetObject, DestinationHostname.")
    false_positive_risks: str = Field(description="Benign activity that could look similar and how the rule should avoid it.")
    priority: Literal["high", "medium", "low"]


class DetectionPlan(BaseModel):
    """Output of the planning stage."""

    candidates: list[DetectionCandidate]
    skipped: list[str] = Field(default_factory=list, description="Behaviour ids not turned into rules, each with a short reason, e.g. 'B4: only an IP indicator, no durable behaviour'.")
    notes: str = Field(default="", description="Overall strategy notes.")


# --------------------------------------------------------------------------
# Stage 4: rule authoring with tests
# --------------------------------------------------------------------------


class TestEvent(BaseModel):
    """A synthetic telemetry event used to prove the rule works."""

    __test__ = False  # keep pytest from trying to collect this class

    id: str = Field(description="Short id like P1 (positive) or N1 (negative).")
    label: Literal["positive", "negative"] = Field(description="positive = the rule MUST match; negative = benign look-alike the rule MUST NOT match.")
    description: str = Field(description="What this event represents and why it was chosen.")
    event: dict[str, Any] = Field(description="Flat JSON object with Sigma/Sysmon field names as keys (Image, CommandLine, ParentImage, User, TargetObject, Details, DestinationHostname, ...). Values are strings or numbers.")


class SigmaLogsource(BaseModel):
    """The Sigma ``logsource`` block."""

    category: str = Field(default="", description="Sigma logsource category, e.g. process_creation, registry_set, network_connection.")
    product: str = Field(default="", description="Sigma logsource product, e.g. windows, linux, aws.")
    service: str = Field(default="", description="Optional service, e.g. sysmon, security, cloudtrail. Empty when not needed.")


class SigmaRuleDoc(BaseModel):
    """A Sigma rule expressed as a JSON object instead of YAML text.

    The model fills this structure and RuleSmith serialises it to YAML. Asking
    Nemotron for a multi-line YAML string inside a JSON string field proved
    fragile under guided decoding (newlines went missing, braces leaked in),
    whereas a nested JSON object cannot have YAML syntax errors at all. The
    housekeeping keys (``id``, ``author``, ``date``) are deliberately absent:
    the code fills them in deterministically.
    """

    title: str = Field(description="SigmaHQ-style title: '<Binary> <Action> <Distinctive Context>'.")
    status: Literal["experimental", "test", "stable"] = Field(default="experimental")
    description: str = Field(description="One or two sentences on what the rule detects and why it matters.")
    references: list[str] = Field(default_factory=list, description="Source URLs.")
    tags: list[str] = Field(description="Lowercase Sigma tags in the attack namespace, e.g. ['attack.execution', 'attack.t1059.001'].")
    logsource: SigmaLogsource
    detection: dict[str, Any] = Field(
        description=(
            "The Sigma detection block as a JSON object: named selections (selection_*, filter_*) whose keys are "
            "'Field' or 'Field|modifier' and whose values are a string, a number or a list (OR), plus a 'condition' string. "
            "Example: {\"selection\": {\"Image|endswith\": \"\\\\rundll32.exe\", \"CommandLine|contains\": [\"AppData\", \"Temp\"]}, \"condition\": \"selection\"}"
        )
    )
    falsepositives: list[str] = Field(description="Plausible benign causes of a hit.")
    level: Literal["informational", "low", "medium", "high", "critical"]

    def to_dict(self) -> dict[str, Any]:
        """Plain dict in Sigma key order, with empty optional keys dropped."""
        out: dict[str, Any] = {"title": self.title, "status": self.status, "description": self.description}
        if self.references:
            out["references"] = list(self.references)
        out["tags"] = list(self.tags)
        logsource = {k: v for k, v in self.logsource.model_dump().items() if v}
        out["logsource"] = logsource
        out["detection"] = dict(self.detection)
        # SigmaHQ convention: the key is always present, "Unknown" when nothing is known.
        out["falsepositives"] = list(self.falsepositives) or ["Unknown"]
        out["level"] = self.level
        return out

    @classmethod
    def from_yaml(cls, sigma_yaml: str) -> SigmaRuleDoc:
        """Build a doc from YAML text (used by tests and fixtures). Extra keys are ignored."""
        raw = yaml.safe_load(sigma_yaml)
        if not isinstance(raw, dict):
            raise TypeError("Sigma rule YAML must be a mapping")
        return cls.model_validate(raw)


class AuthoredRule(BaseModel):
    """Output of the authoring stage for one candidate: the rule plus its tests."""

    candidate_id: str
    rule: SigmaRuleDoc
    tests: list[TestEvent] = Field(description="At least 3 positive and 3 negative test events.")
    author_notes: str = Field(default="", description="Design decisions, trade-offs, known limitations.")


class RuleDraft(BaseModel):
    """A Sigma rule (as normalised YAML text) together with its tests.

    This is the pipeline's working representation: the validator, converters
    and packager all consume ``sigma_yaml``.
    """

    candidate_id: str
    sigma_yaml: str
    tests: list[TestEvent]
    author_notes: str = ""


# --------------------------------------------------------------------------
# Stage 5: deterministic validation
# --------------------------------------------------------------------------


class ValidationIssue(BaseModel):
    """A problem found by the validator."""

    severity: Literal["error", "warning", "info"]
    code: str
    message: str


class TestOutcome(BaseModel):
    """Result of running one test event through the compiled rule."""

    event_id: str
    label: Literal["positive", "negative"]
    matched: bool
    passed: bool


class ValidationReport(BaseModel):
    """Everything the refine stage needs to know about a draft."""

    candidate_id: str
    parse_ok: bool = False
    sql: str = ""
    issues: list[ValidationIssue] = Field(default_factory=list)
    test_outcomes: list[TestOutcome] = Field(default_factory=list)
    positives_total: int = 0
    positives_matched: int = 0
    negatives_total: int = 0
    negatives_matched: int = 0
    benign_total: int = 0
    benign_hits: int = 0
    benign_examples: list[dict[str, Any]] = Field(default_factory=list)
    passed: bool = False

    @property
    def errors(self) -> list[ValidationIssue]:
        """Return only the error-severity issues (the ones that block ``passed``)."""
        return [i for i in self.issues if i.severity == "error"]

    def summary(self) -> str:
        """One-line human summary used in logs and the UI."""
        if not self.parse_ok:
            return "parse failed: " + "; ".join(i.message for i in self.errors)[:200]
        return (
            f"positives {self.positives_matched}/{self.positives_total}, "
            f"negatives blocked {self.negatives_total - self.negatives_matched}/{self.negatives_total}, "
            f"benign hits {self.benign_hits}/{self.benign_total}"
        )


# --------------------------------------------------------------------------
# Stage 6/7: refinement and red-team
# --------------------------------------------------------------------------


class RetiredTest(BaseModel):
    """A red-team variant the refine stage wants retired instead of chased.

    Some evasions the red-team labels catchable are not: the literal field
    value no longer contains anything the rule could key on without also
    matching benign activity (an environment-variable path, an 8.3 short
    name, quotes inside an Image path). Retiring them with a reason keeps the
    rule honest without weakening it to the point of noise.
    """

    id: str = Field(description="Id of the red-team test to retire (R1, R2, ...). Original positives (P*) cannot be retired.")
    reason: str = Field(description="One sentence: why this logsource and these fields cannot see the variant.")


class ReplacedTest(BaseModel):
    """A corrected version of an existing test event.

    Test events are model-written too, and sometimes they are the bug: a
    positive whose ParentImage is the loaded DLL instead of rundll32.exe, or
    a negative that repeats a positive. Refinement may correct such an event
    in place, keeping its id and label, with a reason the audit trail keeps.
    """

    test: TestEvent = Field(description="The corrected event; id and label must match an existing test.")
    reason: str = Field(description="One sentence: what was wrong with the original event.")


class RefinedRule(BaseModel):
    """Output of a refinement call: a corrected rule and any extra tests."""

    rule: SigmaRuleDoc = Field(description="The complete corrected rule (not a diff).")
    change_summary: str = Field(description="What changed and why, in one or two sentences.")
    additional_tests: list[TestEvent] = Field(default_factory=list, description="Optional extra test events if the fix warrants them.")
    retire_tests: list[RetiredTest] = Field(default_factory=list, description="Red-team variants (ids starting with R) that are unreachable for this logsource/fields and should be recorded for the analyst instead of tested. Leave empty when the rule can be fixed.")
    replace_tests: list[ReplacedTest] = Field(default_factory=list, description="Existing test events (any id) that were themselves wrong, corrected in place with a reason. Use only when the event, not the rule, is the bug; never weaken a positive below the behaviour in the report.")


class RedTeamVariants(BaseModel):
    """Evasion attempts the red-team stage wants the rule to survive."""

    variants: list[TestEvent] = Field(description="Positive events that preserve the attacker's goal while changing the surface form (aliases, casing, quoting, path tricks, encoding, LOLBin swaps) and that a well-written rule for this logsource CAN catch. Optionally a few benign look-alikes labelled negative.")
    out_of_scope: list[TestEvent] = Field(default_factory=list, description="Realistic evasions that this rule's logsource and fields fundamentally cannot see (e.g. a renamed binary when the rule keys on Image and OriginalFileName is unavailable). Recorded for the analyst; the rule is not required to match them.")
    analysis: str = Field(description="Which evasions are realistic and which the rule may legitimately not cover.")


# --------------------------------------------------------------------------
# Run-level output
# --------------------------------------------------------------------------


class IterationRecord(BaseModel):
    """Audit trail entry for one validate/refine cycle."""

    iteration: int
    phase: Literal["initial", "repair", "refine", "redteam", "revert"]
    summary: str
    passed: bool
    change_summary: str = ""


class FinalRule(BaseModel):
    """A rule as delivered to the user."""

    candidate_id: str
    title: str
    sigma_yaml: str
    status: Literal["validated", "needs_review", "failed"]
    attack_technique_ids: list[str] = Field(default_factory=list)
    tests: list[TestEvent] = Field(default_factory=list)
    validation: ValidationReport
    conversions: dict[str, str] = Field(default_factory=dict, description="Target name -> query text (splunk, elasticsearch, kusto, sqlite).")
    conversion_errors: dict[str, str] = Field(default_factory=dict)
    history: list[IterationRecord] = Field(default_factory=list)
    author_notes: str = ""
    redteam_analysis: str = ""
    retired_tests: list[TestEvent] = Field(default_factory=list, description="Red-team variants retired during refinement as unreachable; the reason is appended to each description.")
    replaced_tests: list[TestEvent] = Field(default_factory=list, description="Original versions of test events the refine stage corrected, with the reason appended to each description.")
    redteam_out_of_scope: list[TestEvent] = Field(default_factory=list, description="Evasions the red-team judged outside this rule's reach; shown to the analyst, not tested.")


class UsageRecord(BaseModel):
    """One LLM call's accounting record."""

    stage: str
    tier: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_s: float = 0.0
    cost_usd: float = 0.0
    thinking: bool = False


class RunMetrics(BaseModel):
    """Aggregated accounting for a run."""

    calls: list[UsageRecord] = Field(default_factory=list)

    @property
    def total_prompt_tokens(self) -> int:
        """Sum the prompt tokens of every call in the run."""
        return sum(c.prompt_tokens for c in self.calls)

    @property
    def total_completion_tokens(self) -> int:
        """Sum the completion tokens of every call in the run."""
        return sum(c.completion_tokens for c in self.calls)

    @property
    def total_cost_usd(self) -> float:
        """Sum the estimated cost of every call, rounded to whole micro-dollars."""
        return round(sum(c.cost_usd for c in self.calls), 6)

    @property
    def total_latency_s(self) -> float:
        """Sum the wall-clock time spent inside LLM calls.

        Candidates run in parallel, so this is model time, not the run's
        elapsed time; the ``done`` event carries the latter.
        """
        return round(sum(c.latency_s for c in self.calls), 2)

    def by_tier(self) -> dict[str, dict[str, Any]]:
        """Roll-up per tier so the UI can show which Nemotron did what."""
        out: dict[str, dict[str, Any]] = {}
        for c in self.calls:
            slot = out.setdefault(c.tier, {"model": c.model, "calls": 0, "prompt_tokens": 0, "completion_tokens": 0, "cost_usd": 0.0})
            slot["calls"] += 1
            slot["prompt_tokens"] += c.prompt_tokens
            slot["completion_tokens"] += c.completion_tokens
            slot["cost_usd"] = round(slot["cost_usd"] + c.cost_usd, 6)
        return out


class SourceInfo(BaseModel):
    """How the input was obtained."""

    mode: Literal["url", "text", "query", "example"]
    urls: list[str] = Field(default_factory=list)
    query: str = ""
    tavily_used: bool = False
    chars: int = 0


class RunResult(BaseModel):
    """Everything produced by one pipeline run."""

    run_id: str
    created_at: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    source: SourceInfo
    report: ThreatReport
    plan: DetectionPlan
    rules: list[FinalRule] = Field(default_factory=list)
    metrics: RunMetrics = Field(default_factory=RunMetrics)
    models: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)

    def stats(self) -> dict[str, Any]:
        """Headline numbers for the UI and the eval table.

        The recall/precision figures are over the rules' own test events (the
        positives the rule must catch and the benign look-alikes it must not),
        so they measure how far refinement got, not real-world accuracy. They
        are ``None`` when there were no tests to score.
        """
        validated = sum(1 for r in self.rules if r.status == "validated")
        total_pos = sum(r.validation.positives_total for r in self.rules)
        hit_pos = sum(r.validation.positives_matched for r in self.rules)
        total_neg = sum(r.validation.negatives_total for r in self.rules)
        hit_neg = sum(r.validation.negatives_matched for r in self.rules)
        benign_hits = sum(r.validation.benign_hits for r in self.rules)
        iterations = sum(len(r.history) for r in self.rules)
        return {
            "rules": len(self.rules),
            "validated": validated,
            "needs_review": sum(1 for r in self.rules if r.status == "needs_review"),
            "failed": sum(1 for r in self.rules if r.status == "failed"),
            "behaviors": len(self.report.behaviors),
            "positive_recall": round(hit_pos / total_pos, 3) if total_pos else None,
            "negative_precision": round(1 - hit_neg / total_neg, 3) if total_neg else None,
            "benign_hits": benign_hits,
            "iterations": iterations,
            "cost_usd": self.metrics.total_cost_usd,
            "prompt_tokens": self.metrics.total_prompt_tokens,
            "completion_tokens": self.metrics.total_completion_tokens,
            "latency_s": self.metrics.total_latency_s,
        }


def strict_schema(model: type[BaseModel]) -> dict[str, Any]:
    """Return a JSON schema suitable for constrained decoding.

    Adds ``additionalProperties: false`` to every object so the model cannot
    invent keys, which keeps pydantic validation strict and failures loud.
    """
    schema = model.model_json_schema()

    def _tighten(node: Any) -> None:
        if isinstance(node, dict):
            # Free-form event payloads (TestEvent.event) have no "properties" and keep additionalProperties.
            if node.get("type") == "object" and "additionalProperties" not in node and "properties" in node:
                node["additionalProperties"] = False
            for v in node.values():
                _tighten(v)
        elif isinstance(node, list):
            for v in node:
                _tighten(v)

    _tighten(schema)
    return schema
