"""Live smoke test against Nebius Token Factory (and Tavily when configured).

Skipped unless NEBIUS_API_KEY is set, so the normal suite stays offline.
Run it explicitly with:  NEBIUS_API_KEY=... pytest tests/test_live.py -s
"""

from __future__ import annotations

import os

import pytest
from pydantic import BaseModel

from rulesmith.config import TIER_FAST, TIER_MAIN, TIER_REASONING, Settings
from rulesmith.llm import TokenFactoryLLM

pytestmark = pytest.mark.skipif(not os.getenv("NEBIUS_API_KEY"), reason="NEBIUS_API_KEY not set")


class Answer(BaseModel):
    technique_id: str
    technique_name: str
    confidence: float


@pytest.fixture(scope="module")
def llm():
    return TokenFactoryLLM(Settings.from_env())


def test_models_resolve_to_nemotron(llm):
    models = llm.resolve_models()
    print("\nresolved:", models)
    for tier in (TIER_FAST, TIER_MAIN, TIER_REASONING):
        assert "nemotron" in models[tier].lower(), f"{tier} resolved to non-Nemotron model {models[tier]}"


@pytest.mark.parametrize("tier,thinking", [(TIER_FAST, False), (TIER_MAIN, False), (TIER_REASONING, True)])
def test_structured_output_each_tier(llm, tier, thinking):
    parsed, usage = llm.complete_structured(
        stage="live",
        tier=tier,
        system="You map attacker behaviours to MITRE ATT&CK technique ids.",
        user="rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 C:\\Users\\Public\\lsass.dmp full",
        schema=Answer,
        thinking=thinking,
        max_tokens=4000,
    )
    print(f"\n{tier} ({usage.model}, thinking={thinking}): {parsed} tokens={usage.prompt_tokens}/{usage.completion_tokens} ${usage.cost_usd:.5f} {usage.latency_s}s")
    assert parsed.technique_id.upper().startswith("T1003"), parsed
    assert usage.completion_tokens > 0


@pytest.mark.skipif(not os.getenv("TAVILY_API_KEY"), reason="TAVILY_API_KEY not set")
def test_tavily_extract_live():
    from rulesmith.ingest import Ingestor

    res = Ingestor(Settings.from_env()).from_urls(["https://attack.mitre.org/techniques/T1003/001/"])
    assert res.source.tavily_used and "LSASS" in res.text
