"""Stage 2: behaviour extraction (Nemotron fast tier, thinking off).

Sits between ingest and plan in the pipeline: the clean report text goes in,
and the structured ``ThreatReport`` every later stage reasons over comes out.
"""

from __future__ import annotations

from .config import TIER_FAST
from .llm import BaseLLM
from .models import ThreatReport, UsageRecord
from .prompts import EXTRACT_SYSTEM


def extract_report(llm: BaseLLM, text: str, *, source_hint: str = "") -> tuple[ThreatReport, UsageRecord]:
    """Turn raw report text into a structured ThreatReport.

    Extraction is close reading rather than reasoning, so the fast tier with
    thinking off keeps the longest prompt of the run cheap. ``source_hint``
    (a URL or example id) is shown to the model only as provenance.
    """
    # The report is fenced in <<< >>> so the model can tell quoted content from instructions.
    user = (
        (f"Source: {source_hint}\n\n" if source_hint else "")
        + "THREAT REPORT:\n<<<\n"
        + text
        + "\n>>>\n\nExtract the behaviours, observables and IOCs as specified."
    )
    return llm.complete_structured(stage="extract", tier=TIER_FAST, system=EXTRACT_SYSTEM, user=user, schema=ThreatReport, thinking=False)
