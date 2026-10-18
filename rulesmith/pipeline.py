"""The RuleSmith agent loop.

ingest -> extract -> plan -> for each candidate:
    author -> validate -> (refine -> validate)* -> red-team -> validate -> (refine -> validate)? -> convert

Every step emits an event so the web UI can stream progress, and every LLM
call is accounted in ``RunResult.metrics``.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .author import author_rule, dump_rule, repair_all_lists
from .config import Settings
from .convert import convert_rule_all
from .extract import extract_report
from .ingest import IngestError, Ingestor, IngestResult
from .llm import BaseLLM, LLMError
from .models import (
    DetectionCandidate,
    FinalRule,
    IterationRecord,
    RuleDraft,
    RunMetrics,
    RunResult,
    ThreatReport,
    UsageRecord,
    ValidationReport,
)
from .plan import plan_detections
from .redteam import redteam_rule
from .refine import refine_rule
from .sigmahq import SigmaHQExamples
from .validate import AttackIndex, BenignCorpus, validate_rule
from .validate.fields import FieldDictionary

log = logging.getLogger(__name__)

EventCallback = Callable[[dict[str, Any]], None]


@dataclass
class RunInput:
    """What the user asked for."""

    mode: str  # url | text | query | example
    value: str = ""
    urls: list[str] = field(default_factory=list)
    max_rules: int | None = None
    max_refine_iterations: int | None = None
    enable_redteam: bool | None = None


class Pipeline:
    """Runs the agent end to end. Construct once, call ``run`` per request."""

    def __init__(
        self,
        settings: Settings,
        llm: BaseLLM,
        *,
        ingestor: Ingestor | None = None,
        corpus: BenignCorpus | None = None,
        attack: AttackIndex | None = None,
        fields: FieldDictionary | None = None,
        examples: SigmaHQExamples | None = None,
        on_event: EventCallback | None = None,
        max_workers: int = 3,
    ) -> None:
        self.settings = settings
        self.llm = llm
        self.ingestor = ingestor or Ingestor(settings)
        self.corpus = corpus if corpus is not None else BenignCorpus()
        self.attack = attack or AttackIndex()
        self.fields = fields or FieldDictionary()
        # SigmaHQ few-shot grounding for the author and refine stages (empty index = no examples).
        self.examples = examples if examples is not None else SigmaHQExamples()
        self.on_event = on_event
        self.max_workers = max_workers
        self._lock = threading.Lock()

    # ----------------------------------------------------------------- events

    def _emit(self, type_: str, stage: str, message: str, **data: Any) -> None:
        """Send a progress event to the listener (thread-safe)."""
        evt = {"type": type_, "stage": stage, "message": message, "ts": time.time(), **data}
        log.info("[%s] %s: %s", type_, stage, message)
        if self.on_event:
            with self._lock:
                try:
                    self.on_event(evt)
                except Exception:
                    log.exception("event listener failed")

    def _record(self, metrics: RunMetrics, usage: UsageRecord) -> None:
        with self._lock:
            metrics.calls.append(usage)

    # ------------------------------------------------------------------- run

    def run(self, inp: RunInput) -> RunResult:
        """Execute the whole agent for one input."""
        run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]
        metrics = RunMetrics()
        warnings: list[str] = []
        max_rules = inp.max_rules or self.settings.max_rules
        max_iter = self.settings.max_refine_iterations if inp.max_refine_iterations is None else inp.max_refine_iterations
        redteam_on = self.settings.enable_redteam if inp.enable_redteam is None else inp.enable_redteam
        started = time.perf_counter()

        # 1. Ingest -------------------------------------------------------
        self._emit("stage", "ingest", "Fetching the report", status="running")
        ingest = self._ingest(inp)
        self._emit("stage", "ingest", f"Got {ingest.source.chars:,} characters" + (" via Tavily" if ingest.source.tavily_used else ""), status="done", source=ingest.source.model_dump())

        # 2. Extract ------------------------------------------------------
        models = self.llm.resolve_models() if hasattr(self.llm, "resolve_models") else dict(getattr(self.llm, "models", {}))
        self._emit("stage", "extract", f"Extracting behaviours with {models.get('fast', 'fast tier')}", status="running")
        report, usage = extract_report(self.llm, ingest.text, source_hint=", ".join(ingest.source.urls))
        self._record(metrics, usage)
        self._emit("stage", "extract", f"{len(report.behaviors)} behaviours, {len(report.iocs)} IOCs", status="done", report=report.model_dump(), usage=usage.model_dump())
        if not report.behaviors:
            raise PipelineError("No detectable behaviours were found in the report.")

        # 3. Plan ---------------------------------------------------------
        self._emit("stage", "plan", f"Planning detections with {models.get('reasoning', 'reasoning tier')} (thinking on)", status="running")
        plan, usage = plan_detections(self.llm, report, max_rules=max_rules)
        self._record(metrics, usage)
        self._emit("stage", "plan", f"{len(plan.candidates)} rule candidates, {len(plan.skipped)} behaviours skipped", status="done", plan=plan.model_dump(), usage=usage.model_dump())
        if not plan.candidates:
            raise PipelineError("The planner found nothing worth a rule.")

        # 4-7. Per-candidate loop, in parallel -------------------------------
        self._emit("stage", "rules", f"Authoring, testing and hardening {len(plan.candidates)} rules", status="running")
        refs = [u for u in ingest.source.urls if not u.startswith("example://")]
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = [pool.submit(self._process_candidate, report, cand, refs, metrics, max_iter, redteam_on, warnings) for cand in plan.candidates]
            rules = [f.result() for f in futures]
        rules.sort(key=lambda r: ({"validated": 0, "needs_review": 1, "failed": 2}[r.status], r.candidate_id))
        self._emit("stage", "rules", f"{sum(1 for r in rules if r.status == 'validated')}/{len(rules)} rules validated", status="done")

        result = RunResult(run_id=run_id, source=ingest.source, report=report, plan=plan, rules=rules, metrics=metrics, models=models, warnings=warnings)
        self._save(result)
        self._emit("done", "done", f"Finished in {time.perf_counter() - started:.1f}s", stats=result.stats(), run_id=run_id)
        return result

    # --------------------------------------------------------------- helpers

    def _ingest(self, inp: RunInput) -> IngestResult:
        try:
            if inp.mode == "url":
                return self.ingestor.from_urls(inp.urls or [inp.value])
            if inp.mode == "query":
                return self.ingestor.from_query(inp.value)
            if inp.mode == "example":
                return self.ingestor.from_example(inp.value)
            return self.ingestor.from_text(inp.value)
        except IngestError as exc:
            raise PipelineError(str(exc)) from exc

    def _validate(self, draft: RuleDraft, candidate: DetectionCandidate) -> ValidationReport:
        return validate_rule(draft, corpus=self.corpus, attack=self.attack, expected_techniques=candidate.attack_technique_ids)

    def _process_candidate(
        self,
        report: ThreatReport,
        candidate: DetectionCandidate,
        refs: list[str],
        metrics: RunMetrics,
        max_iter: int,
        redteam_on: bool,
        warnings: list[str],
    ) -> FinalRule:
        """Author one rule and push it through validation, refinement and red-team.

        Any unexpected exception is converted into a failed rule plus a run
        warning, so one bad candidate never loses the other rules' work.
        """
        cid = candidate.id
        try:
            return self._process_candidate_inner(report, candidate, refs, metrics, max_iter, redteam_on, warnings)
        except Exception as exc:
            log.exception("candidate %s crashed", cid)
            warnings.append(f"{cid}: unexpected error: {exc}")
            self._emit("rule", cid, f"Unexpected error: {exc}", status="failed", title=candidate.title)
            empty = ValidationReport(candidate_id=cid, parse_ok=False)
            return FinalRule(candidate_id=cid, title=candidate.title, sigma_yaml="", status="failed", attack_technique_ids=candidate.attack_technique_ids, validation=empty)

    def _process_candidate_inner(
        self,
        report: ThreatReport,
        candidate: DetectionCandidate,
        refs: list[str],
        metrics: RunMetrics,
        max_iter: int,
        redteam_on: bool,
        warnings: list[str],
    ) -> FinalRule:
        """The real per-candidate loop; see ``_process_candidate``."""
        cid = candidate.id
        history: list[IterationRecord] = []
        redteam_analysis = ""
        redteam_out_of_scope: list = []
        retired_tests: list = []  # red-team variants the refine stage proved unreachable
        replaced_tests: list = []  # original versions of test events the refine stage corrected
        try:
            self._emit("rule", cid, f"Authoring '{candidate.title}'", status="authoring", title=candidate.title)
            draft, usage = author_rule(self.llm, report, candidate, references=refs, fields=self.fields, examples=self.examples)
            self._record(metrics, usage)
        except LLMError as exc:
            warnings.append(f"{cid}: authoring failed: {exc}")
            self._emit("rule", cid, f"Authoring failed: {exc}", status="failed", title=candidate.title)
            empty = ValidationReport(candidate_id=cid, parse_ok=False)
            return FinalRule(candidate_id=cid, title=candidate.title, sigma_yaml="", status="failed", attack_technique_ids=candidate.attack_technique_ids, validation=empty, history=history)

        vreport = self._validate(draft, candidate)
        history.append(IterationRecord(iteration=0, phase="initial", summary=vreport.summary(), passed=vreport.passed))
        draft, vreport = self._auto_repair(cid, candidate, draft, vreport, history, 0)
        # Best draft seen so far. Refinement can regress (a "fix" that no longer
        # compiles), so the loop never hands back something worse than this.
        best_draft, best_score = draft, _draft_score(vreport)
        self._emit("rule", cid, f"Validation: {vreport.summary()}", status="validated" if vreport.passed else "refining", title=candidate.title, passed=vreport.passed, issues=[i.model_dump() for i in vreport.issues])

        # Refine loop: bounded, evidence-driven.
        iteration = 0
        while not vreport.passed and iteration < max_iter:
            iteration += 1
            try:
                draft, refined, usage, retired, replaced = refine_rule(self.llm, candidate, draft, vreport, references=refs, examples=self.examples)
                self._record(metrics, usage)
            except LLMError as exc:
                warnings.append(f"{cid}: refine #{iteration} failed: {exc}")
                break
            best_draft, best_score = self._note_test_changes(cid, candidate, retired, replaced, retired_tests, replaced_tests, best_draft, best_score, draft)
            vreport = self._validate(draft, candidate)
            history.append(IterationRecord(iteration=iteration, phase="refine", summary=vreport.summary(), passed=vreport.passed, change_summary=_with_test_changes(refined.change_summary, retired, replaced)))
            self._emit("rule", cid, f"Refine #{iteration}: {refined.change_summary} -> {vreport.summary()}", status="validated" if vreport.passed else "refining", title=candidate.title, passed=vreport.passed)
            draft, vreport = self._auto_repair(cid, candidate, draft, vreport, history, iteration)
            if _draft_score(vreport) >= best_score:
                best_draft, best_score = draft, _draft_score(vreport)

        # Red-team: only worth it when the rule parses and compiles.
        if redteam_on and vreport.parse_ok and vreport.sql:
            try:
                variants, rt, usage = redteam_rule(self.llm, candidate, draft)
                self._record(metrics, usage)
                redteam_analysis = rt.analysis
                redteam_out_of_scope = list(rt.out_of_scope)
                if variants:
                    draft = draft.model_copy(update={"tests": list(draft.tests) + variants})
                    vreport = self._validate(draft, candidate)
                    # The test set grew; the best draft is now judged on the same tests.
                    best_draft = best_draft.model_copy(update={"tests": draft.tests})
                    best_score = _draft_score(self._validate(best_draft, candidate)) if best_draft.sigma_yaml != draft.sigma_yaml else _draft_score(vreport)
                    if _draft_score(vreport) >= best_score:
                        best_draft, best_score = draft, _draft_score(vreport)
                    history.append(IterationRecord(iteration=iteration, phase="redteam", summary=f"{len(variants)} evasion variants -> {vreport.summary()}", passed=vreport.passed))
                    self._emit("rule", cid, f"Red-team: {len(variants)} evasions, {vreport.positives_matched}/{vreport.positives_total} positives caught", status="validated" if vreport.passed else "refining", title=candidate.title, passed=vreport.passed)
                    # Up to two hardening passes after the red-team: one reply that does
                    # not parse should not end the rule as needs_review.
                    for _ in range(2):
                        if vreport.passed:
                            break
                        iteration += 1
                        try:
                            draft, refined, usage, retired, replaced = refine_rule(self.llm, candidate, draft, vreport, references=refs, examples=self.examples)
                            self._record(metrics, usage)
                            best_draft, best_score = self._note_test_changes(cid, candidate, retired, replaced, retired_tests, replaced_tests, best_draft, best_score, draft)
                            vreport = self._validate(draft, candidate)
                            history.append(IterationRecord(iteration=iteration, phase="refine", summary=vreport.summary(), passed=vreport.passed, change_summary=_with_test_changes(refined.change_summary, retired, replaced)))
                            self._emit("rule", cid, f"Hardened: {refined.change_summary} -> {vreport.summary()}", status="validated" if vreport.passed else "needs_review", title=candidate.title, passed=vreport.passed)
                            draft, vreport = self._auto_repair(cid, candidate, draft, vreport, history, iteration)
                            if _draft_score(vreport) >= best_score:
                                best_draft, best_score = draft, _draft_score(vreport)
                        except LLMError as exc:
                            warnings.append(f"{cid}: post-redteam refine failed: {exc}")
                            break
            except LLMError as exc:
                warnings.append(f"{cid}: red-team failed: {exc}")

        # Roll back to the best draft if the last refinement made things worse.
        if best_draft.sigma_yaml != draft.sigma_yaml and _draft_score(vreport) < best_score:
            draft = best_draft.model_copy(update={"tests": draft.tests})
            vreport = self._validate(draft, candidate)
            history.append(IterationRecord(iteration=iteration, phase="revert", summary=vreport.summary(), passed=vreport.passed, change_summary="Last refinement regressed; kept the best earlier draft."))
            self._emit("rule", cid, f"Reverted to best draft -> {vreport.summary()}", status="validated" if vreport.passed else "needs_review", title=candidate.title, passed=vreport.passed)

        status = "validated" if vreport.passed else ("needs_review" if vreport.parse_ok else "failed")
        conversions, conv_errors = convert_rule_all(draft.sigma_yaml) if vreport.parse_ok else ({}, {})
        title = _title_from_yaml(draft.sigma_yaml) or candidate.title
        techniques = sorted({t.upper() for t in candidate.attack_technique_ids} | set(_tags_from_yaml(draft.sigma_yaml)))
        final = FinalRule(
            candidate_id=cid,
            title=title,
            sigma_yaml=draft.sigma_yaml,
            status=status,
            attack_technique_ids=techniques,
            tests=draft.tests,
            validation=vreport,
            conversions=conversions,
            conversion_errors=conv_errors,
            history=history,
            author_notes=draft.author_notes,
            redteam_analysis=redteam_analysis,
            redteam_out_of_scope=redteam_out_of_scope,
            retired_tests=retired_tests,
            replaced_tests=replaced_tests,
        )
        self._emit("rule", cid, f"{status}: {vreport.summary()}", status=status, title=title, rule=final.model_dump())
        return final

    def _auto_repair(self, cid: str, candidate: DetectionCandidate, draft: RuleDraft, vreport: ValidationReport, history: list[IterationRecord], iteration: int) -> tuple[RuleDraft, ValidationReport]:
        """Deterministic, evidence-driven repair of ``contains|all`` lists (no LLM).

        Runs only when the rule parses and still misses positives. The repair
        is recorded as its own history phase so the audit trail shows that the
        code, not the model, changed the rule, and what it changed.
        """
        if vreport.passed or not vreport.parse_ok or vreport.positives_matched >= vreport.positives_total:
            return draft, vreport
        try:
            raw = yaml.safe_load(draft.sigma_yaml)
        except yaml.YAMLError:
            return draft, vreport
        if not isinstance(raw, dict) or not isinstance(raw.get("detection"), dict):
            return draft, vreport
        positives = [t.event for t in draft.tests if t.label == "positive"]
        detection, notes = repair_all_lists(raw["detection"], positives)
        if not notes:
            return draft, vreport
        raw["detection"] = detection
        repaired = draft.model_copy(update={"sigma_yaml": dump_rule(raw)})
        report = self._validate(repaired, candidate)
        # Keep the repair only if it helps; the positives are the yardstick.
        if _draft_score(report) < _draft_score(vreport):
            return draft, vreport
        history.append(IterationRecord(iteration=iteration, phase="repair", summary=report.summary(), passed=report.passed, change_summary=" ".join(notes)))
        self._emit("rule", cid, f"Repair: {' '.join(notes)} -> {report.summary()}", status="validated" if report.passed else "refining", title=candidate.title, passed=report.passed)
        return repaired, report

    def _note_test_changes(self, cid: str, candidate: DetectionCandidate, retired: list, replaced: list, retired_tests: list, replaced_tests: list, best_draft: RuleDraft, best_score: tuple, draft: RuleDraft) -> tuple[RuleDraft, tuple]:
        """Record retired and corrected tests and re-judge the best draft on the changed test set.

        Returns the (possibly re-scored) best draft and score. When the tests
        did not change the inputs come back unchanged.
        """
        if not retired and not replaced:
            return best_draft, best_score
        retired_tests.extend(retired)
        replaced_tests.extend(replaced)
        if retired:
            self._emit("rule", cid, "Retired red-team variant(s) as unreachable for this logsource: " + "; ".join(f"{t.id}: {t.description.rsplit('[retired: ', 1)[-1].rstrip(']')}" for t in retired), status="refining", title=candidate.title)
        if replaced:
            self._emit("rule", cid, "Corrected test event(s): " + "; ".join(f"{t.id}: {t.description.rsplit('[replaced: ', 1)[-1].rstrip(']')}" for t in replaced), status="refining", title=candidate.title)
        # The yardstick changed, so the best-so-far draft must be scored on the same tests.
        best_draft = best_draft.model_copy(update={"tests": draft.tests})
        return best_draft, _draft_score(self._validate(best_draft, candidate))

    def _save(self, result: RunResult) -> None:
        """Persist the run for replay/download; failures are non-fatal."""
        try:
            self.settings.runs_dir.mkdir(parents=True, exist_ok=True)
            path = Path(self.settings.runs_dir) / f"{result.run_id}.json"
            path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        except OSError as exc:  # pragma: no cover
            log.warning("could not save run: %s", exc)


class PipelineError(RuntimeError):
    """A user-facing failure (bad input, nothing detectable)."""


def _with_test_changes(change_summary: str, retired: list, replaced: list) -> str:
    """Append retired and corrected test ids to a refine change summary for the audit trail."""
    if retired:
        change_summary = f"{change_summary} Retired {', '.join(t.id for t in retired)} as unreachable."
    if replaced:
        change_summary = f"{change_summary} Corrected test event(s) {', '.join(t.id for t in replaced)}."
    return change_summary


def _draft_score(v: ValidationReport) -> tuple[int, int, float, int]:
    """Rank validation reports: parses > passes > share of tests right > fewer benign hits.

    Using the share of tests (not the count) keeps scores comparable when the
    red-team stage grows the test set.
    """
    total = v.positives_total + v.negatives_total
    right = v.positives_matched + (v.negatives_total - v.negatives_matched)
    share = right / total if total else 0.0
    return (int(v.parse_ok), int(v.passed), round(share, 4), -v.benign_hits)


def _title_from_yaml(sigma_yaml: str) -> str:
    import yaml

    try:
        raw = yaml.safe_load(sigma_yaml)
        return str(raw.get("title", "")) if isinstance(raw, dict) else ""
    except yaml.YAMLError:
        return ""


def _tags_from_yaml(sigma_yaml: str) -> list[str]:
    import re

    import yaml

    try:
        raw = yaml.safe_load(sigma_yaml)
    except yaml.YAMLError:
        return []
    if not isinstance(raw, dict):
        return []
    out = []
    for t in raw.get("tags") or []:
        m = re.match(r"^attack\.(t\d{4}(?:\.\d{3})?)$", str(t), re.IGNORECASE)
        if m:
            out.append(m.group(1).upper())
    return out


# Recorded runs shipped with the repository: the web UI replays them, the CLI
# can re-package them, and the eval harness rewrites them with --record.
RECORDED_RUNS_DIR = Path(__file__).resolve().parents[1] / "examples" / "runs"


def load_run(path: Path) -> RunResult:
    """Load a saved run (used by replay mode and the eval harness)."""
    return RunResult.model_validate(json.loads(path.read_text(encoding="utf-8")))


def recorded_run_path(run_id: str) -> Path | None:
    """Path of a recorded run by id (file stem), or None when there is no such run.

    The id is reduced to a safe character set first so a request can never
    escape the recorded-runs directory.
    """
    safe = "".join(ch for ch in run_id if ch.isalnum() or ch in "-_")
    path = RECORDED_RUNS_DIR / f"{safe}.json"
    return path if safe and path.exists() else None
