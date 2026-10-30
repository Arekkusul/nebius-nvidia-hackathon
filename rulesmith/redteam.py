"""Stage 7: adversarial variant generation (Nemotron reasoning tier, thinking on).

Runs after the refine loop on every rule that parses and compiles: the
variants returned here are appended to the rule's tests, and the pipeline
validates (and, if needed, refines) again before packaging.
"""

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
    # Three positives are enough to show the model the field names and value style.
    positives = [t.model_dump() for t in draft.tests if t.label == "positive"][:3]
    user = (
        f"RULE (YAML):\n{draft.sigma_yaml}\n\n"
        f"TARGET BEHAVIOUR:\n{candidate.rationale}\nTechniques: {', '.join(candidate.attack_technique_ids)}\n\n"
        f"EXISTING POSITIVE TESTS (for field names and realism):\n{json.dumps(positives, indent=1)}\n\n"
        "Produce the evasion variants and your analysis."
    )
    result, usage = llm.complete_structured(stage="redteam", tier=TIER_REASONING, system=REDTEAM_SYSTEM, user=user, schema=RedTeamVariants, thinking=True)
    # Variants get ids R1, R2, ...; the author's tests are P*/N* by convention
    # only, so a trailing underscore keeps a clashing id unique.
    existing = {t.id for t in draft.tests}
    variants: list[TestEvent] = []
    for i, v in enumerate(result.variants, start=1):
        vid = f"R{i}"
        while vid in existing:
            vid += "_"
        existing.add(vid)
        variants.append(v.model_copy(update={"id": vid, "event": clean_event(v.event)}))
    # Out-of-scope evasions are kept on the result for reporting; they get
    # their own id space so they never collide with real tests.
    result.out_of_scope = [v.model_copy(update={"id": f"X{i}", "label": "positive", "event": clean_event(v.event)}) for i, v in enumerate(result.out_of_scope, start=1)]
    return variants, result, usage
