"""Stage 7: adversarial variant generation (Nemotron reasoning tier, thinking on)."""

from __future__ import annotations

import json

from .author import clean_event
from .config import TIER_REASONING
from .llm import BaseLLM
from .models import DetectionCandidate, RedTeamVariants, RuleDraft, TestEvent, UsageRecord
from .prompts import REDTEAM_SYSTEM


def redteam_rule(llm: BaseLLM, candidate: DetectionCandidate, draft: RuleDraft) -> tuple[list[TestEvent], RedTeamVariants, UsageRecord]:
    """Generate evasion variants as extra tests; returns the new tests too.

    Variants are positives by design, but the model may also hand back benign
    look-alikes labelled negative to prove specificity; those labels are kept.
    """
    positives = [t.model_dump() for t in draft.tests if t.label == "positive"][:3]
    user = (
        f"RULE (YAML):\n{draft.sigma_yaml}\n\n"
        f"TARGET BEHAVIOUR:\n{candidate.rationale}\nTechniques: {', '.join(candidate.attack_technique_ids)}\n\n"
        f"EXISTING POSITIVE TESTS (for field names and realism):\n{json.dumps(positives, indent=1)}\n\n"
        "Produce the evasion variants and your analysis."
    )
    result, usage = llm.complete_structured(stage="redteam", tier=TIER_REASONING, system=REDTEAM_SYSTEM, user=user, schema=RedTeamVariants, thinking=True)
    existing = {t.id for t in draft.tests}
    variants: list[TestEvent] = []
    for i, v in enumerate(result.variants, start=1):
        vid = f"R{i}"
        while vid in existing:
            vid += "_"
        existing.add(vid)
        variants.append(v.model_copy(update={"id": vid, "event": clean_event(v.event)}))
    return variants, result, usage
