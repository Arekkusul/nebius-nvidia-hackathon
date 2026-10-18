"""Few-shot grounding on the SigmaHQ community rules.

Nemotron writes better Sigma when it can see how the community wrote rules
for the same log source and technique: which fields carry the signal, how
short the ``contains`` tokens are, when ``contains|all`` is right and when
it is not, what a Kerberoasting or ``rundll32`` rule actually looks like.
This module picks a handful of such rules from the slimmed SigmaHQ index in
``data/sigmahq_examples.json`` (built by ``scripts/build_sigmahq_index.py``)
and renders them as YAML for the author and refine prompts.

Retrieval is deliberately simple and deterministic: same logsource first,
then ATT&CK technique overlap, then title-word overlap. No embeddings, no
network, so it works offline and costs nothing.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .models import LogSourceHint

DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "sigmahq_examples.json"

# Words that appear in almost every title and carry no retrieval signal.
_STOPWORDS = {
    "a", "an", "and", "as", "at", "by", "for", "from", "in", "of", "on", "or", "the", "to", "via", "with",
    "potential", "suspicious", "possible", "detects", "detected", "detection", "execution", "activity", "usage",
    "use", "command", "process", "file", "new", "windows", "linux", "aws", "hacktool", "uncommon",
}

_WORD_RX = re.compile(r"[a-z0-9]+")


def _words(text: str) -> set[str]:
    """Lower-case content words of a title or description."""
    return {w for w in _WORD_RX.findall(text.lower()) if w not in _STOPWORDS and len(w) > 2}


def _technique_keys(ids: list[str]) -> set[str]:
    """``T1059.001`` -> {'t1059.001', 't1059'} so a sub-technique matches its parent too."""
    out: set[str] = set()
    for tid in ids:
        t = tid.lower().strip()
        if not t:
            continue
        out.add(t)
        out.add(t.split(".")[0])
    return out


@lru_cache(maxsize=1)
def _load(path: Path) -> list[dict[str, Any]]:
    """Read the index once per process; an absent file just disables examples."""
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return list(data.get("rules", []))


class SigmaHQExamples:
    """Finds SigmaHQ rules similar to a planned detection."""

    def __init__(self, rules: list[dict[str, Any]] | None = None) -> None:
        self.rules = rules if rules is not None else _load(DATA_PATH)

    def __len__(self) -> int:
        return len(self.rules)

    def find(self, logsource: LogSourceHint, techniques: list[str], title: str = "", *, k: int = 3) -> list[dict[str, Any]]:
        """Return up to ``k`` rules, best match first.

        Scoring: the logsource must match on product plus category (or
        service, for category-less sources such as the Security log or
        CloudTrail); within that, a shared ATT&CK technique counts most,
        then shared title words, then rule maturity (stable > test > experimental).
        """
        product = (logsource.product or "").lower()
        category = (logsource.category or "").lower()
        service = (logsource.service or "").lower()
        wanted = _technique_keys(techniques)
        title_words = _words(title)
        maturity = {"stable": 2, "test": 1, "experimental": 0}
        scored: list[tuple[float, dict[str, Any]]] = []
        for rule in self.rules:
            ls = rule.get("logsource") or {}
            if (ls.get("product") or "").lower() != product:
                continue
            same_category = bool(category) and (ls.get("category") or "").lower() == category
            same_service = bool(service) and (ls.get("service") or "").lower() == service
            if not (same_category or same_service):
                continue
            tags = {t[len("attack."):] for t in rule.get("tags", []) if t.startswith("attack.t")}
            tag_keys = _technique_keys(list(tags))
            score = 0.0
            # Exact (sub)technique beats a parent-only match.
            score += 4.0 * len({t for t in wanted if "." in t} & tag_keys)
            score += 2.0 * len({t for t in wanted if "." not in t} & tag_keys)
            score += 1.0 * len(title_words & _words(rule.get("title", "")))
            # Maturity only breaks ties; a rule with nothing in common is never an example.
            if score > 0:
                scored.append((score + 0.1 * maturity.get(rule.get("status", ""), 0), rule))
        scored.sort(key=lambda s: (-s[0], s[1].get("title", "")))
        return [r for _, r in scored[:k]]

    @staticmethod
    def render(rules: list[dict[str, Any]]) -> str:
        """Format examples as YAML snippets for a prompt (empty string if none)."""
        if not rules:
            return ""
        blocks = []
        for r in rules:
            doc = {k: r[k] for k in ("title", "logsource", "tags", "detection", "level") if k in r}
            # The index keeps the logsource definition text; it is not useful here.
            doc["logsource"] = {k: v for k, v in doc.get("logsource", {}).items() if k != "definition"}
            blocks.append(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=120).strip())
        return "REFERENCE RULES FROM SIGMAHQ (same logsource/technique; copy the field idioms and token style, not the titles):\n" + "\n---\n".join(blocks)
