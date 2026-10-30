"""Field dictionary: which telemetry fields exist for a Sigma logsource.

Hallucinated field names are the single most common failure mode reported in
the literature on LLM-written Sigma rules. The dictionary turns that failure
into an explicit validation error the refine stage can act on.

Reference data for the validate stage; the author stage also reads it to put
the real field list for the target logsource into the prompt.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "field_schemas.json"

# Categories where we are confident the dictionary is complete enough to make
# an unknown field an *error* rather than a warning.
STRICT_CATEGORIES = {
    "process_creation",
    "network_connection",
    "registry_event",
    "registry_set",
    "registry_add",
    "registry_delete",
    "registry_rename",
    "file_event",
    "file_delete",
    "file_change",
    "file_rename",
    "image_load",
    "driver_load",
    "dns_query",
    "process_access",
    "create_remote_thread",
    "pipe_created",
    "wmi_event",
    "ps_script",
    "ps_module",
    "ps_classic_start",
}


@lru_cache(maxsize=1)
def _load(path: Path) -> dict[str, list[str]]:
    """Load the field schemas once per process, dropping the file's ``_comment``-style metadata keys."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return {k: v for k, v in data.items() if not k.startswith("_")}


class FieldDictionary:
    """Answers 'is this field plausible for this logsource?'."""

    def __init__(self, schemas: dict[str, list[str]] | None = None) -> None:
        self.schemas = schemas if schemas is not None else _load(DATA_PATH)

    def known_fields(self, category: str | None, product: str | None, service: str | None) -> set[str] | None:
        """Return the allowed field set, or None if the logsource is unknown to us."""
        cat = (category or "").lower()
        prod = (product or "").lower()
        svc = (service or "").lower()
        # Candidate schema keys, most specific first: "windows/process_creation",
        # "aws/service:cloudtrail", then the product-less generic categories.
        keys: list[str] = []
        if prod and cat:
            keys.append(f"{prod}/{cat}")
        if prod and svc:
            keys.append(f"{prod}/service:{svc}")
        if cat and not prod:
            keys.append(cat)  # product-less categories like proxy, webserver, dns
        if cat in {"proxy", "webserver", "dns", "firewall", "antivirus"}:
            keys.append(cat)  # these generic schemas apply whatever the product
        found: set[str] = set()
        matched = False
        for k in keys:
            if k in self.schemas:
                matched = True
                found.update(self.schemas[k])
        if not matched:
            return None
        # Product-wide ("windows/*") and universal ("common") fields are only
        # added once a specific logsource matched, so an unknown logsource
        # stays "unknown" rather than getting a tiny, misleading field set.
        if prod and f"{prod}/*" in self.schemas:
            found.update(self.schemas[f"{prod}/*"])
        found.update(self.schemas.get("common", []))
        return found

    def is_strict(self, category: str | None) -> bool:
        """Tell whether an unknown field in this category is an error (True) or only a warning."""
        return (category or "").lower() in STRICT_CATEGORIES

    def check(self, field: str, allowed: set[str]) -> bool:
        """Case-insensitive membership with dotted-prefix support (cloud logs)."""
        f = field.strip()
        lowered = {a.lower() for a in allowed}
        if f.lower() in lowered:
            return True
        # A dictionary entry ending in "." (e.g. "requestParameters.") allows any
        # nested key under it; cloud logs have too many to list one by one.
        for a in allowed:
            if a.endswith(".") and f.lower().startswith(a.lower()):
                return True
        return False
