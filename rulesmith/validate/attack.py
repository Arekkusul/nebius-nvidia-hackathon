"""MITRE ATT&CK technique index for validating ids the model emits."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "attack_techniques.json"
TECHNIQUE_RX = re.compile(r"^T\d{4}(\.\d{3})?$")

# Sigma spellings of the ATT&CK tactics (``attack.<tactic>`` tags).
TACTIC_TAGS = frozenset({
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
})


class AttackIndex:
    """Lookup of technique id -> name/tactics, loaded from the bundled JSON."""

    def __init__(self, techniques: dict[str, dict] | None = None) -> None:
        self.techniques = techniques if techniques is not None else _load(DATA_PATH)

    def normalize(self, tid: str) -> str:
        """Upper-case and strip whitespace so 't1059.001' validates."""
        return tid.strip().upper()

    def is_valid_format(self, tid: str) -> bool:
        return bool(TECHNIQUE_RX.match(self.normalize(tid)))

    def exists(self, tid: str) -> bool:
        return self.normalize(tid) in self.techniques

    def is_deprecated(self, tid: str) -> bool:
        info = self.techniques.get(self.normalize(tid))
        return bool(info and info.get("deprecated"))

    def name(self, tid: str) -> str:
        info = self.techniques.get(self.normalize(tid))
        return info["name"] if info else ""

    def tactics(self, tid: str) -> list[str]:
        info = self.techniques.get(self.normalize(tid))
        return list(info.get("tactics", [])) if info else []

    def parent(self, tid: str) -> str:
        """Return the parent technique id for a sub-technique (T1059.001 -> T1059)."""
        return self.normalize(tid).split(".")[0]


@lru_cache(maxsize=1)
def _load(path: Path) -> dict[str, dict]:
    """Load the technique index once per process."""
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))
