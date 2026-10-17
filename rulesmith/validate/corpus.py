"""Benign baseline corpus: realistic telemetry a production rule must ignore."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "benign_corpus.jsonl"

# Sigma categories that are observed through the same underlying telemetry.
# A rule on registry_event should be tested against registry_set events, etc.
CATEGORY_ALIASES: dict[str, set[str]] = {
    "registry_event": {"registry_set", "registry_add", "registry_delete", "registry_rename", "registry_event"},
    "registry_set": {"registry_set", "registry_event"},
    "registry_add": {"registry_add", "registry_event"},
    "registry_delete": {"registry_delete", "registry_event"},
    "file_event": {"file_event"},
    "ps_script": {"ps_script"},
}


class BenignCorpus:
    """In-memory view of the JSONL corpus with logsource filtering."""

    def __init__(self, events: list[dict[str, Any]] | None = None) -> None:
        self.events = events if events is not None else self.load(DATA_PATH)

    @staticmethod
    def load(path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        out: list[dict[str, Any]] = []
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def events_for(self, *, category: str | None, product: str | None, service: str | None = None) -> list[dict[str, Any]]:
        """Events relevant to a logsource. Unknown logsources get an empty list."""
        cat = (category or "").lower()
        prod = (product or "").lower()
        svc = (service or "").lower()
        wanted = CATEGORY_ALIASES.get(cat, {cat} if cat else set())
        out = []
        for e in self.events:
            e_cat = str(e.get("_category", "")).lower()
            e_prod = str(e.get("_product", "")).lower()
            e_svc = str(e.get("_service", "")).lower()
            if prod and e_prod != prod:
                continue
            if cat and e_cat not in wanted:
                # Service-only logsources (e.g. aws/cloudtrail) carry the
                # service name in the category slot of the corpus.
                if not (svc and e_svc == svc):
                    continue
            if not cat and svc and e_svc != svc:
                continue
            out.append(e)
        return out

    @staticmethod
    def strip_meta(event: dict[str, Any]) -> dict[str, Any]:
        """Drop underscore-prefixed bookkeeping keys before showing an event."""
        return {k: v for k, v in event.items() if not k.startswith("_")}

    def __len__(self) -> int:
        return len(self.events)
