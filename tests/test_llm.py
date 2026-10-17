"""Tests for the Token Factory client wrapper (no network)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import BaseModel

from rulesmith.config import TIER_FAST, TIER_MAIN, TIER_REASONING, Settings
from rulesmith.llm import FakeLLM, LLMError, TokenFactoryLLM, extract_json, strip_thinking


class Pair(BaseModel):
    a: int
    b: str


def _resp(text: str, prompt=10, completion=5):
    """Build an object shaped like an OpenAI chat completion."""
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=text))],
        usage=SimpleNamespace(prompt_tokens=prompt, completion_tokens=completion),
    )


class StubClient:
    """Minimal stand-in for ``openai.OpenAI`` with scripted behaviour."""

    def __init__(self, replies, models=None, reject_modes=()):
        self.replies = list(replies)
        self.reject_modes = set(reject_modes)
        self.kwargs_log = []
        self.models = SimpleNamespace(list=lambda: SimpleNamespace(data=[SimpleNamespace(id=m) for m in (models or [])]))
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.kwargs_log.append(kwargs)
        rf = kwargs.get("response_format", {}).get("type", "none")
        if rf in self.reject_modes:
            exc = RuntimeError("response_format not supported")
            exc.status_code = 400
            raise exc
        return self.replies.pop(0)


def settings():
    return Settings(nebius_api_key="x", model_overrides={TIER_FAST: "nvidia/a", TIER_MAIN: "nvidia/b", TIER_REASONING: "nvidia/Nemotron-3-Ultra-550b-a55b"})


def test_strip_thinking_and_fences():
    assert strip_thinking("<think>blah\nblah</think>```json\n{\"a\":1}\n```") == '{"a":1}'
    assert strip_thinking("<think>unterminated") == ""
    assert strip_thinking("plain") == "plain"


def test_extract_json_tolerates_prose():
    assert extract_json('Sure! Here it is: {"a": 1, "b": "x"} hope that helps') == {"a": 1, "b": "x"}
    with pytest.raises(LLMError):
        extract_json("no json here")


def test_structured_call_passes_thinking_and_schema():
    stub = StubClient([_resp('{"a": 1, "b": "ok"}')])
    llm = TokenFactoryLLM(settings(), client=stub)
    parsed, usage = llm.complete_structured(stage="s", tier=TIER_REASONING, system="sys", user="u", schema=Pair, thinking=True)
    assert parsed == Pair(a=1, b="ok")
    kw = stub.kwargs_log[0]
    assert kw["extra_body"]["chat_template_kwargs"]["enable_thinking"] is True
    assert kw["response_format"]["type"] == "json_schema"
    assert kw["response_format"]["json_schema"]["schema"]["additionalProperties"] is False
    assert "JSON Schema" in kw["messages"][0]["content"]
    assert usage.prompt_tokens == 10 and usage.completion_tokens == 5
    assert usage.model == "nvidia/Nemotron-3-Ultra-550b-a55b"
    # Ultra pricing: 10 * $1 + 5 * $3 per 1M tokens
    assert usage.cost_usd == pytest.approx((10 * 1.0 + 5 * 3.0) / 1e6)


def test_json_schema_rejected_falls_back_to_json_object_and_remembers():
    stub = StubClient([_resp('{"a": 2, "b": "y"}'), _resp('{"a": 3, "b": "z"}')], reject_modes={"json_schema"})
    llm = TokenFactoryLLM(settings(), client=stub)
    p1, _ = llm.complete_structured(stage="s", tier=TIER_FAST, system="", user="", schema=Pair)
    p2, _ = llm.complete_structured(stage="s", tier=TIER_FAST, system="", user="", schema=Pair)
    assert (p1.a, p2.a) == (2, 3)
    modes = [k.get("response_format", {}).get("type") for k in stub.kwargs_log]
    # first call: json_schema rejected -> json_object; second call goes straight to json_object
    assert modes == ["json_schema", "json_object", "json_object"]


def test_invalid_json_triggers_one_repair_call():
    stub = StubClient([_resp('{"a": "not-int", "b": "y"}', 7, 3), _resp('{"a": 5, "b": "fixed"}', 9, 4)])
    llm = TokenFactoryLLM(settings(), client=stub)
    parsed, usage = llm.complete_structured(stage="s", tier=TIER_MAIN, system="", user="", schema=Pair)
    assert parsed == Pair(a=5, b="fixed")
    assert len(stub.kwargs_log) == 2
    assert "did not validate" in stub.kwargs_log[1]["messages"][-1]["content"]
    # tokens from both calls are accounted
    assert usage.prompt_tokens == 16 and usage.completion_tokens == 7


def test_repair_failure_raises():
    stub = StubClient([_resp("garbage"), _resp("still garbage")])
    llm = TokenFactoryLLM(settings(), client=stub)
    with pytest.raises(LLMError):
        llm.complete_structured(stage="s", tier=TIER_MAIN, system="", user="", schema=Pair)


def test_non_format_errors_propagate():
    stub = StubClient([])
    def boom(**kwargs):
        exc = RuntimeError("rate limited")
        exc.status_code = 429
        raise exc
    stub.chat.completions.create = boom
    llm = TokenFactoryLLM(settings(), client=stub)
    with pytest.raises(RuntimeError, match="rate limited"):
        llm.complete_structured(stage="s", tier=TIER_MAIN, system="", user="", schema=Pair)


def test_resolve_models_from_catalog_case_insensitive():
    catalog = ["nvidia/nemotron-3_5-lightning", "nvidia/nemotron-3-super-120b-a12b", "nvidia/Nemotron-3-Ultra-550b-a55b-fast", "Qwen/Qwen3"]
    stub = StubClient([], models=catalog)
    s = Settings(nebius_api_key="x")
    llm = TokenFactoryLLM(s, client=stub)
    models = llm.resolve_models()
    assert models[TIER_FAST] == "nvidia/nemotron-3_5-lightning"
    assert models[TIER_MAIN] == "nvidia/nemotron-3-super-120b-a12b"
    # exact Ultra id missing, regex fallback picks the -fast variant
    assert models[TIER_REASONING] == "nvidia/Nemotron-3-Ultra-550b-a55b-fast"


def test_resolve_models_respects_partial_overrides():
    catalog = ["nvidia/Nemotron-3_5-Lightning", "nvidia/nemotron-3-super-120b-a12b"]
    stub = StubClient([], models=catalog)
    s = Settings(nebius_api_key="x", model_overrides={TIER_REASONING: "nvidia/custom-ultra"})
    llm = TokenFactoryLLM(s, client=stub)
    models = llm.resolve_models()
    assert models[TIER_REASONING] == "nvidia/custom-ultra"
    assert models[TIER_FAST] == "nvidia/Nemotron-3_5-Lightning"
    # no Ultra in catalog and no override for main -> super
    assert models[TIER_MAIN] == "nvidia/nemotron-3-super-120b-a12b"


def test_fake_llm_scripts_lists_and_callables():
    fake = FakeLLM({"s": [{"a": 1, "b": "x"}, Pair(a=2, b="y")], "c": lambda sys_, user: {"a": len(user), "b": "cb"}})
    p1, _ = fake.complete_structured(stage="s", tier=TIER_FAST, system="", user="", schema=Pair)
    p2, _ = fake.complete_structured(stage="s", tier=TIER_FAST, system="", user="", schema=Pair)
    p3, u = fake.complete_structured(stage="c", tier=TIER_MAIN, system="", user="abcd", schema=Pair)
    assert (p1.a, p2.a, p3.a) == (1, 2, 4)
    assert u.model == "fake/nemotron-super"
    with pytest.raises(LLMError):
        fake.complete_structured(stage="s", tier=TIER_FAST, system="", user="", schema=Pair)
    with pytest.raises(LLMError):
        fake.complete_structured(stage="missing", tier=TIER_FAST, system="", user="", schema=Pair)
