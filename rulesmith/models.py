"""Pydantic schemas shared by every pipeline stage.

These double as the JSON schemas handed to Nemotron through Token Factory's
``response_format={"type": "json_schema"}``. Keep field descriptions crisp:
the model reads them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

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


class ThreatReport(BaseModel):
    """Structured understanding of one threat-intel document."""

    title: str
    summary: str = Field(description="3-5 sentence executive summary of the campaign/malware and its kill chain.")
    threat_actors: list[str] = Field(default_factory=list)
    malware_families: list[str] = Field(default_factory=list)
    targets: list[str] = Field(default_factory=list, description="Targeted sectors, regions or platforms.")
    behaviors: list[Behavior] = Field(default_factory=list)
    iocs: list[IOC] = Field(default_factory=list)


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


class RuleDraft(BaseModel):
    """A Sigma rule together with its tests."""

    candidate_id: str
    sigma_yaml: str = Field(description="Complete Sigma rule as YAML text (title, id, status, description, references, author, date, tags, logsource, detection, falsepositives, level).")
    tests: list[TestEvent]
    author_notes: str = Field(default="", description="Design decisions, trade-offs, known limitations.")


class AuthoredRules(BaseModel):
    """Output of the authoring stage: one draft per candidate."""

    rules: list[RuleDraft]


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


class RefinedRule(BaseModel):
    """Output of a refinement call: a corrected rule and any extra tests."""

    sigma_yaml: str = Field(description="The full corrected Sigma rule YAML.")
    change_summary: str = Field(description="What changed and why, in one or two sentences.")
    additional_tests: list[TestEvent] = Field(default_factory=list, description="Optional extra test events if the fix warrants them.")


class RedTeamVariants(BaseModel):
    """Evasion attempts the red-team stage wants the rule to survive."""

    variants: list[TestEvent] = Field(description="Positive events that preserve the attacker's goal while changing the surface form (aliases, casing, quoting, path tricks, encoding, LOLBin swaps).")
    analysis: str = Field(description="Which evasions are realistic and which the rule may legitimately not cover.")


# --------------------------------------------------------------------------
# Run-level output
# --------------------------------------------------------------------------


class IterationRecord(BaseModel):
    """Audit trail entry for one validate/refine cycle."""

    iteration: int
    phase: Literal["initial", "refine", "redteam"]
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
        return sum(c.prompt_tokens for c in self.calls)

    @property
    def total_completion_tokens(self) -> int:
        return sum(c.completion_tokens for c in self.calls)

    @property
    def total_cost_usd(self) -> float:
        return round(sum(c.cost_usd for c in self.calls), 6)

    @property
    def total_latency_s(self) -> float:
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
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source: SourceInfo
    report: ThreatReport
    plan: DetectionPlan
    rules: list[FinalRule] = Field(default_factory=list)
    metrics: RunMetrics = Field(default_factory=RunMetrics)
    models: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)

    def stats(self) -> dict[str, Any]:
        """Headline numbers for the UI and the eval table."""
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
            if node.get("type") == "object" and "additionalProperties" not in node:
                # Free-form event payloads (TestEvent.event) keep additionalProperties.
                if "properties" in node:
                    node["additionalProperties"] = False
            for v in node.values():
                _tighten(v)
        elif isinstance(node, list):
            for v in node:
                _tighten(v)

    _tighten(schema)
    return schema
