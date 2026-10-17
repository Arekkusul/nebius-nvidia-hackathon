"""Stage 2: behaviour extraction (Nemotron fast tier, thinking off)."""

from __future__ import annotations

from .config import TIER_FAST
from .llm import BaseLLM
from .models import ThreatReport, UsageRecord
from .prompts import EXTRACT_SYSTEM


def extract_report(llm: BaseLLM, text: str, *, source_hint: str = "") -> tuple[ThreatReport, UsageRecord]:
    """Turn raw report text into a structured ThreatReport."""
    user = (
        (f"Source: {source_hint}\n\n" if source_hint else "")
        + "THREAT REPORT:\n<<<\n"
        + text
        + "\n>>>\n\nExtract the behaviours, observables and IOCs as specified."
    )
    return llm.complete_structured(stage="extract", tier=TIER_FAST, system=EXTRACT_SYSTEM, user=user, schema=ThreatReport, thinking=False)
