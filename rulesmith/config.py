"""Runtime configuration for RuleSmith.

Everything is read from environment variables (a local ``.env`` is loaded if
present) so the same code runs on a laptop, in Docker, on a Hugging Face Space,
or on a Nebius Serverless Endpoint without changes.

This is the settings layer: it owns the model-tier names, the default model
ids and prices, and the :class:`Settings` object every other module reads.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# Load a .env file from the current working directory if there is one.
# Real environment variables always win over the file.
load_dotenv(override=False)

# Model tiers. Each pipeline stage declares which tier it wants; the tier maps
# to a concrete Nemotron model id. This is the "Ultra for reasoning, Nano/Super
# for everyday calls" routing the hackathon organisers recommend.
TIER_FAST = "fast"            # extraction, summaries: cheap, thinking off
TIER_MAIN = "main"            # rule authoring and refinement
TIER_REASONING = "reasoning"  # planning and adversarial red-team: thinking on

# Default Nemotron ids on Token Factory. Casing differs between Nebius pages,
# so these are only *preferences*; ``llm.resolve_models`` matches them
# case-insensitively against the live ``/v1/models`` list and falls back to
# pattern matching if a preferred id is missing.
DEFAULT_MODEL_PREFERENCES: dict[str, list[str]] = {
    TIER_FAST: [
        "nvidia/Nemotron-3_5-Lightning",
        "nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B",
        "nvidia/nvidia-nemotron-3-nano-30b-a3b",
    ],
    TIER_MAIN: [
        "nvidia/nemotron-3-super-120b-a12b",
        "nvidia/Nemotron-3-Super-120B-A12B",
    ],
    TIER_REASONING: [
        "nvidia/Nemotron-3-Ultra-550b-a55b",
        "nvidia/nemotron-3-ultra-550b-a55b",
    ],
}

# Regex fallbacks used when none of the preferred ids exist in the catalog.
# Order matters: the first pattern that matches an available model wins.
MODEL_PATTERNS: dict[str, list[str]] = {
    TIER_FAST: [r"nemotron.*lightning", r"nemotron.*nano", r"nemotron.*super(?!.*vl)"],
    TIER_MAIN: [r"nemotron.*super(?!.*vl)", r"nemotron.*lightning", r"nemotron.*ultra"],
    TIER_REASONING: [r"nemotron.*ultra", r"nemotron.*super(?!.*vl)", r"nemotron.*lightning"],
}

# Public list prices (USD per 1M tokens) used only for the cost estimate shown
# in the UI. Keys are matched case-insensitively as substrings of the model id,
# in dict order, so the more specific "super-vl" must stay above "super".
PRICING_PER_MTOK: dict[str, tuple[float, float]] = {
    "lightning": (0.06, 0.24),
    "nano": (0.06, 0.24),
    "super-vl": (0.30, 0.90),
    "super": (0.30, 0.90),
    "ultra": (1.00, 3.00),
}


def estimate_cost_usd(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    """Estimate the cost of one call from the public price list.

    Unknown models cost 0 so the estimate is never *higher* than reality for
    the Nemotron tiers we route to.
    """
    key = model.lower()
    for needle, (pin, pout) in PRICING_PER_MTOK.items():
        if needle in key:
            return (prompt_tokens * pin + completion_tokens * pout) / 1_000_000
    return 0.0


def _env_bool(name: str, default: bool) -> bool:
    """Parse a boolean environment variable leniently."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float) -> float:
    """Read a float from the environment, falling back on blanks or junk."""
    try:
        return float(os.getenv(name, "").strip() or default)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    """Parse an integer environment variable, falling back on garbage."""
    raw = os.getenv(name)
    try:
        return int(raw) if raw not in (None, "") else default
    except ValueError:
        return default


@dataclass
class Settings:
    """All tunables in one place. Construct with ``Settings.from_env()``."""

    nebius_api_key: str = ""
    nebius_base_url: str = "https://api.tokenfactory.nebius.com/v1/"
    tavily_api_key: str = ""

    # Explicit model overrides per tier (empty string = auto-resolve).
    model_overrides: dict[str, str] = field(default_factory=dict)

    # The refine loop is bounded so a rule that will never pass cannot burn
    # tokens forever; each pass is a main-tier call, so this is also a cost knob.
    max_refine_iterations: int = 3
    max_rules: int = 6
    enable_redteam: bool = True
    runs_dir: Path = Path("runs")
    # Hosted demo without a spend cap: only the bundled example reports may be run.
    demo_locked: bool = False
    # Public live demo: cap the Token Factory spend of this process (0 = no cap) and the rules per run.
    demo_budget_usd: float = 0.0
    demo_max_rules: int = 3
    # Rate limits for a budgeted public demo: live runs per rolling hour for the whole
    # process and per client address. They bound the spend per hour even on hosts
    # that restart the process (and so reset the in-memory budget) when it idles.
    demo_runs_per_hour: int = 12
    demo_runs_per_ip_per_hour: int = 3

    # Request-level knobs.
    request_timeout_s: float = 180.0
    max_retries: int = 3
    # Reasoning models can emit long traces; give them room.
    max_tokens_reasoning: int = 16000
    max_tokens_default: int = 8000

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from environment variables."""
        return cls(
            nebius_api_key=os.getenv("NEBIUS_API_KEY", "").strip(),
            # A variable that is set but blank (common in hosted dashboards) still gets the default.
            nebius_base_url=os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/").strip()
            or "https://api.tokenfactory.nebius.com/v1/",
            tavily_api_key=os.getenv("TAVILY_API_KEY", "").strip(),
            model_overrides={
                TIER_FAST: os.getenv("RULESMITH_MODEL_FAST", "").strip(),
                TIER_MAIN: os.getenv("RULESMITH_MODEL_MAIN", "").strip(),
                TIER_REASONING: os.getenv("RULESMITH_MODEL_REASONING", "").strip(),
            },
            max_refine_iterations=_env_int("RULESMITH_MAX_REFINE_ITERATIONS", 3),
            max_rules=_env_int("RULESMITH_MAX_RULES", 6),
            enable_redteam=_env_bool("RULESMITH_ENABLE_REDTEAM", True),
            runs_dir=Path(os.getenv("RULESMITH_RUNS_DIR", "runs")),
            demo_locked=_env_bool("RULESMITH_DEMO_LOCKED", False),
            demo_budget_usd=_env_float("RULESMITH_DEMO_BUDGET_USD", 0.0),
            demo_max_rules=_env_int("RULESMITH_DEMO_MAX_RULES", 3),
            demo_runs_per_hour=_env_int("RULESMITH_DEMO_RUNS_PER_HOUR", 12),
            demo_runs_per_ip_per_hour=_env_int("RULESMITH_DEMO_RUNS_PER_IP_PER_HOUR", 3),
        )

    @property
    def has_llm(self) -> bool:
        """True when a Token Factory key is configured."""
        return bool(self.nebius_api_key)

    @property
    def has_tavily(self) -> bool:
        """True when Tavily can be used for search/extract."""
        return bool(self.tavily_api_key)


def match_model(available: list[str], preferences: list[str], patterns: list[str]) -> str | None:
    """Pick a model id from ``available`` using preferences first, then regexes.

    Matching is case-insensitive because Nebius lists the same model with
    different casing in different places (``Nemotron-3_5-Lightning`` vs
    ``nemotron-3-super-120b-a12b``).
    """
    lowered = {m.lower(): m for m in available}
    for pref in preferences:
        hit = lowered.get(pref.lower())
        if hit:
            return hit
    for pat in patterns:
        rx = re.compile(pat, re.IGNORECASE)
        # Prefer non "-fast" variants only if nothing else matches; keep order stable.
        for m in available:
            if rx.search(m):
                return m
    return None
