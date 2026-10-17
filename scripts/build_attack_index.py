"""Build data/attack_techniques.json from the MITRE ATT&CK STIX bundle.

Run: python scripts/build_attack_index.py [path-or-url]

Only technique ids, names, tactics and a deprecated flag are kept, so the
checked-in file stays small (~150 KB) while covering every enterprise
technique. The validator uses it to reject hallucinated technique ids.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

DEFAULT_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)
OUT = Path(__file__).resolve().parents[1] / "data" / "attack_techniques.json"


def load_bundle(src: str) -> dict:
    """Load the STIX bundle from a URL or a local file."""
    if src.startswith("http"):
        with urllib.request.urlopen(src, timeout=120) as resp:
            return json.load(resp)
    return json.loads(Path(src).read_text(encoding="utf-8"))


def build(bundle: dict) -> dict[str, dict]:
    """Reduce STIX attack-pattern objects to a compact id -> info map."""
    out: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext_id = next(
            (r.get("external_id") for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"),
            None,
        )
        if not ext_id:
            continue
        tactics = sorted({p.get("phase_name", "") for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"})
        out[ext_id] = {
            "name": obj.get("name", ""),
            "tactics": tactics,
            "deprecated": bool(obj.get("x_mitre_deprecated") or obj.get("revoked")),
        }
    return dict(sorted(out.items()))


def main() -> None:
    src = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    index = build(load_bundle(src))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(index, indent=0, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"wrote {len(index)} techniques to {OUT}")


if __name__ == "__main__":
    main()
