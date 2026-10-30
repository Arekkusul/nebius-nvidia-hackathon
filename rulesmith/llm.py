"""Token Factory client wrapper.

This is the LLM client layer: every pipeline stage (extract, plan, author,
refine, red-team) talks to Nemotron only through :class:`BaseLLM`.

Responsibilities:
* talk to Nebius Token Factory through the OpenAI-compatible API;
* resolve which Nemotron model serves each tier (fast / main / reasoning);
* request strict JSON via ``response_format={"type": "json_schema"}`` and fall
  back gracefully when a model or endpoint does not support it;
* toggle Nemotron's reasoning trace per call (``enable_thinking``);
* strip ``<think>`` blocks, repair invalid JSON with one more model call, and
  validate everything with pydantic;
* record tokens, latency and estimated cost for every call.

Nothing else in the codebase imports ``openai`` directly, which keeps the
pipeline testable with :class:`FakeLLM`.
"""

from __future__ import annotations

import json
import logging
import re
import time
from collections.abc import Callable
from typing import Any, Protocol, TypeVar

from pydantic import BaseModel, ValidationError

from .config import (
    DEFAULT_MODEL_PREFERENCES,
    MODEL_PATTERNS,
    TIER_FAST,
    TIER_MAIN,
    TIER_REASONING,
    Settings,
    estimate_cost_usd,
    match_model,
)
from .models import UsageRecord, strict_schema

log = logging.getLogger(__name__)

T = TypeVar("T", bound=BaseModel)

# Nemotron (and most reasoning models) wrap their trace in <think> tags when the
# serving stack does not split it out. We never want that in parsed output.
_THINK_RX = re.compile(r"<think>.*?</think>", re.DOTALL)
# Some servers leave an unterminated <think> when max_tokens is hit.
_OPEN_THINK_RX = re.compile(r"<think>.*\Z", re.DOTALL)
# Markdown code fences around JSON are common even with JSON mode off.
_FENCE_RX = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


class LLMError(RuntimeError):
    """Raised when a call cannot produce a valid structured result."""


class BaseLLM(Protocol):
    """The interface every pipeline stage codes against."""

    models: dict[str, str]

    def complete_structured(
        self,
        *,
        stage: str,
        tier: str,
        system: str,
        user: str,
        schema: type[T],
        thinking: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> tuple[T, UsageRecord]:
        """Ask the model for one object of type ``schema`` and return it with its usage record.

        ``stage`` is only an accounting label; ``tier`` picks the model.
        Implementations raise :class:`LLMError` when no valid object can be
        produced, and never return a partially validated result.
        """
        ...


def strip_thinking(text: str) -> str:
    """Remove reasoning traces and code fences, leaving the payload."""
    if not text:
        return ""
    text = _THINK_RX.sub("", text)
    text = _OPEN_THINK_RX.sub("", text)
    m = _FENCE_RX.search(text)
    if m:
        text = m.group(1)
    return text.strip()


def extract_json(text: str) -> Any:
    """Parse JSON from model output, tolerating prose around it.

    Tries a clean parse first, then the widest ``{...}`` or ``[...]`` span.
    """
    cleaned = strip_thinking(text)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    # Fallback for "Here is the JSON: {...} Hope this helps": take the span from
    # the first bracket to the last one and let json.loads judge it.
    starts = [i for i in (cleaned.find("{"), cleaned.find("[")) if i >= 0]
    if not starts:
        raise LLMError("no JSON object found in model output")
    start = min(starts)
    end = max(cleaned.rfind("}"), cleaned.rfind("]"))
    if end <= start:
        raise LLMError("unterminated JSON in model output")
    return json.loads(cleaned[start : end + 1])


def _default_temperature(tier: str, thinking: bool) -> float:
    """Sampling defaults from the Nemotron model cards.

    Super/Lightning recommend 1.0; tool-ish structured output on Nano prefers
    0.6. We bias lower for structured work because determinism matters more
    than creativity when writing detection logic.
    """
    if thinking:
        return 1.0
    return 0.6 if tier == TIER_FAST else 0.7


class TokenFactoryLLM:
    """Production client backed by the OpenAI SDK pointed at Token Factory."""

    def __init__(self, settings: Settings, client: Any | None = None) -> None:
        self.settings = settings
        if client is None:
            # Imported lazily so the package imports without the SDK in tests.
            from openai import OpenAI

            client = OpenAI(
                api_key=settings.nebius_api_key,
                base_url=settings.nebius_base_url,
                timeout=settings.request_timeout_s,
                max_retries=settings.max_retries,
            )
        self.client = client
        self.models: dict[str, str] = {}
        # Per-model memory of which response_format shapes are rejected, so we
        # do not pay for a failed request on every call.
        self._json_mode: dict[str, str] = {}

    # ------------------------------------------------------------------ models

    def list_models(self) -> list[str]:
        """Return model ids from ``GET /v1/models``."""
        resp = self.client.models.list()
        ids: list[str] = []
        for m in getattr(resp, "data", resp) or []:
            mid = getattr(m, "id", None) or (m.get("id") if isinstance(m, dict) else None)
            if mid:
                ids.append(mid)
        return ids

    def resolve_models(self) -> dict[str, str]:
        """Decide which model id serves each tier.

        Explicit overrides win. Otherwise we look at the live catalog so the
        app keeps working when Nebius renames a model.
        """
        overrides = {k: v for k, v in self.settings.model_overrides.items() if v}
        tiers = [TIER_FAST, TIER_MAIN, TIER_REASONING]
        if all(t in overrides for t in tiers):
            self.models = {t: overrides[t] for t in tiers}
            return self.models

        try:
            available = self.list_models()
        except Exception as exc:  # noqa: BLE001 - any catalog failure falls back to preferred ids
            log.warning("could not list models (%s); using preferred ids blindly", exc)
            available = []

        resolved: dict[str, str] = {}
        for tier in tiers:
            if tier in overrides:
                resolved[tier] = overrides[tier]
                continue
            pick = match_model(available, DEFAULT_MODEL_PREFERENCES[tier], MODEL_PATTERNS[tier]) if available else None
            resolved[tier] = pick or DEFAULT_MODEL_PREFERENCES[tier][0]
        if available and not any("nemotron" in m.lower() for m in resolved.values()):
            log.warning("no Nemotron model found in catalog; resolved %s", resolved)
        self.models = resolved
        return resolved

    def model_for(self, tier: str) -> str:
        """Model id for a tier, resolving lazily on first use."""
        if not self.models:
            self.resolve_models()
        return self.models[tier]

    # ------------------------------------------------------------------- calls

    def _request(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        schema: dict[str, Any] | None,
        thinking: bool,
        temperature: float,
        max_tokens: int,
    ) -> Any:
        """Send one chat completion, downgrading JSON mode if rejected."""
        # Nemotron's chat template reads enable_thinking; Token Factory passes
        # extra_body through to the server untouched.
        extra_body: dict[str, Any] = {"chat_template_kwargs": {"enable_thinking": thinking}}
        # Start from the strictest mode this model is known to accept and work
        # down the ladder: json_schema (constrained decoding) > json_object > plain.
        mode = self._json_mode.get(model, "json_schema") if schema else "none"
        attempts = ["json_schema", "json_object", "none"] if schema else ["none"]
        attempts = attempts[attempts.index(mode) :]
        last_exc: Exception | None = None
        for attempt in attempts:
            kwargs: dict[str, Any] = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "extra_body": extra_body,
            }
            if attempt == "json_schema":
                kwargs["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {"name": schema.get("title", "Output"), "schema": schema, "strict": True},
                }
            elif attempt == "json_object":
                kwargs["response_format"] = {"type": "json_object"}
            try:
                resp = self.client.chat.completions.create(**kwargs)
                self._json_mode[model] = attempt
                return resp
            except Exception as exc:
                last_exc = exc
                msg = str(exc).lower()
                status = getattr(exc, "status_code", None)
                # Only downgrade on client-side rejections of the format; a
                # rate limit or server error should propagate.
                if status in (400, 422) or "response_format" in msg or "json_schema" in msg or "guided" in msg:
                    log.info("model %s rejected %s mode (%s); downgrading", model, attempt, str(exc)[:120])
                    continue
                raise
        raise LLMError(f"all JSON modes rejected for {model}: {last_exc}")

    def complete_structured(
        self,
        *,
        stage: str,
        tier: str,
        system: str,
        user: str,
        schema: type[T],
        thinking: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> tuple[T, UsageRecord]:
        """Call the model and return a validated pydantic object plus usage.

        If the first answer does not validate, the model is asked once to fix
        its own JSON against the error message. That single repair call fixes
        the vast majority of schema slips without inflating cost.
        """
        model = self.model_for(tier)
        json_schema = strict_schema(schema)
        temp = _default_temperature(tier, thinking) if temperature is None else temperature
        limit = max_tokens or (self.settings.max_tokens_reasoning if thinking else self.settings.max_tokens_default)
        # Restating the schema in the prompt measurably improves adherence on
        # Token Factory (their docs say so too), so we always do both.
        sys_prompt = (
            f"{system}\n\nRespond with a single JSON object that conforms exactly to this JSON Schema. "
            f"Do not add commentary before or after the JSON.\n{json.dumps(json_schema)}"
        )
        messages = [{"role": "system", "content": sys_prompt}, {"role": "user", "content": user}]

        usage = UsageRecord(stage=stage, tier=tier, model=model, thinking=thinking)
        started = time.perf_counter()
        resp = self._request(model=model, messages=messages, schema=json_schema, thinking=thinking, temperature=temp, max_tokens=limit)
        text = self._content(resp)
        self._account(usage, resp)

        try:
            parsed = schema.model_validate(extract_json(text))
        except (ValidationError, LLMError, json.JSONDecodeError) as exc:
            log.info("stage %s: invalid JSON from %s (%s); requesting repair", stage, model, str(exc)[:200])
            # The bad answer goes back as the model's own prior turn, trimmed so a
            # runaway output cannot blow the context window of the repair call. The
            # repair runs with thinking off and a low temperature: it is an
            # editing task, not a reasoning one.
            repair_messages = messages + [
                {"role": "assistant", "content": strip_thinking(text)[:20000]},
                {
                    "role": "user",
                    "content": (
                        "Your previous answer did not validate against the schema. Error:\n"
                        f"{str(exc)[:1500]}\n\nReturn the corrected JSON object only."
                    ),
                },
            ]
            resp2 = self._request(model=model, messages=repair_messages, schema=json_schema, thinking=False, temperature=0.2, max_tokens=limit)
            text2 = self._content(resp2)
            self._account(usage, resp2)
            try:
                parsed = schema.model_validate(extract_json(text2))
            except (ValidationError, LLMError, json.JSONDecodeError) as exc2:
                raise LLMError(f"stage {stage}: model output failed validation twice: {str(exc2)[:500]}") from exc2
        usage.latency_s = round(time.perf_counter() - started, 3)
        usage.cost_usd = round(estimate_cost_usd(model, usage.prompt_tokens, usage.completion_tokens), 6)
        return parsed, usage

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _content(resp: Any) -> str:
        """Pull the assistant text out of a chat completion response."""
        choice = resp.choices[0]
        msg = choice.message
        content = getattr(msg, "content", None)
        if isinstance(content, list):  # some servers return content parts
            content = "".join(part.get("text", "") if isinstance(part, dict) else str(part) for part in content)
        return content or ""

    @staticmethod
    def _account(usage: UsageRecord, resp: Any) -> None:
        """Accumulate token usage from a response (repair calls add on)."""
        u = getattr(resp, "usage", None)
        if u is None:
            return
        usage.prompt_tokens += int(getattr(u, "prompt_tokens", 0) or 0)
        usage.completion_tokens += int(getattr(u, "completion_tokens", 0) or 0)


class FakeLLM:
    """Deterministic stand-in for tests and offline demos.

    ``responses`` maps a stage name to either a ready pydantic object, a dict,
    a list of them (consumed in order, so a refine loop can be scripted), or a
    callable ``(system, user) -> object``.
    """

    def __init__(self, responses: dict[str, Any] | None = None, models: dict[str, str] | None = None) -> None:
        self.responses: dict[str, Any] = responses or {}
        self.models = models or {
            TIER_FAST: "fake/nemotron-lightning",
            TIER_MAIN: "fake/nemotron-super",
            TIER_REASONING: "fake/nemotron-ultra",
        }
        self.calls: list[dict[str, Any]] = []

    def resolve_models(self) -> dict[str, str]:
        """Return the fixed fake model map (no catalog lookup)."""
        return self.models

    def complete_structured(
        self,
        *,
        stage: str,
        tier: str,
        system: str,
        user: str,
        schema: type[T],
        thinking: bool = False,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> tuple[T, UsageRecord]:
        """Return the scripted response for ``stage``, recording the call for assertions.

        Raises :class:`LLMError` (like the real client) when the stage has no
        script or a list script is exhausted, so tests can exercise the
        pipeline's failure paths too.
        """
        self.calls.append({"stage": stage, "tier": tier, "system": system, "user": user, "thinking": thinking})
        if stage not in self.responses:
            raise LLMError(f"FakeLLM has no scripted response for stage '{stage}'")
        item = self.responses[stage]
        if isinstance(item, list):
            if not item:
                raise LLMError(f"FakeLLM ran out of responses for stage '{stage}'")
            item = item.pop(0)
        if isinstance(item, Callable) and not isinstance(item, BaseModel):
            item = item(system, user)
        # Dicts are validated like real model output, so a mistyped fixture fails loudly.
        parsed = item if isinstance(item, schema) else schema.model_validate(item)
        # Rough token counts (about four characters per token) keep the metrics
        # roll-ups non-zero and plausible in offline demos.
        usage = UsageRecord(
            stage=stage,
            tier=tier,
            model=self.models[tier],
            prompt_tokens=len(system) // 4 + len(user) // 4,
            completion_tokens=len(parsed.model_dump_json()) // 4,
            latency_s=0.01,
            cost_usd=0.0,
            thinking=thinking,
        )
        return parsed, usage
