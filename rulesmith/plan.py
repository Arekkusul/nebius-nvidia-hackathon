"""Stage 3: detection planning (Nemotron reasoning tier, thinking on)."""

from __future__ import annotations

import json

from .config import TIER_REASONING
from .llm import BaseLLM
from .models import DetectionPlan, ThreatReport, UsageRecord
from .prompts import PLAN_SYSTEM


def plan_detections(llm: BaseLLM, report: ThreatReport, *, max_rules: int) -> tuple[DetectionPlan, UsageRecord]:
    """Decide which behaviours become rules and how each rule stays specific."""
    behaviours = [b.model_dump() for b in report.behaviors]
    user = (
        f"Report title: {report.title}\nSummary: {report.summary}\n"
        f"Actors: {', '.join(report.threat_actors) or 'n/a'}; Malware: {', '.join(report.malware_families) or 'n/a'}\n\n"
        f"BEHAVIOURS (JSON):\n{json.dumps(behaviours, indent=1)}\n\n"
        f"Plan at most {max_rules} rule candidates, best first. Cover the highest-signal behaviours; skip the rest with reasons."
    )
    plan, usage = llm.complete_structured(stage="plan", tier=TIER_REASONING, system=PLAN_SYSTEM, user=user, schema=DetectionPlan, thinking=True)
    # Hard cap regardless of what the model returned.
    plan.candidates = plan.candidates[:max_rules]
    return plan, usage
