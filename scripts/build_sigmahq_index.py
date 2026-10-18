"""Build ``data/sigmahq_examples.json`` from a SigmaHQ checkout.

The author and refine stages show Nemotron a few real SigmaHQ rules for the
same logsource and technique as the rule it is writing. Grounding on the
community corpus is the cheapest way to teach the model the field idioms
(short invariant tokens, ``contains`` versus ``contains|all``, how
Kerberoasting or ``rundll32`` rules are actually shaped) without fine-tuning,
which Token Factory does not offer for Nemotron today.

    git clone --depth 1 https://github.com/SigmaHQ/sigma.git /tmp/sigma
    python scripts/build_sigmahq_index.py /tmp/sigma

Only the curated ``rules/`` tree is used (not deprecated, unsupported or
emerging-threat rules). The rules are released under the Detection Rule
License 1.1; the index keeps each rule's id and title so attribution is
preserved.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "sigmahq_examples.json"

# Fields copied per rule. Everything else (author, references, dates) is
# dropped to keep the index small enough to ship in the repo.
KEEP = ("id", "title", "status", "logsource", "tags", "detection", "falsepositives", "level")


def slim(rule: dict) -> dict | None:
    """Reduce one SigmaHQ rule to the fields the prompts need, or None to skip it."""
    if not isinstance(rule, dict) or "detection" not in rule or "logsource" not in rule:
        return None
    if rule.get("status") == "deprecated":
        return None
    out = {k: rule[k] for k in KEEP if k in rule}
    # Only ATT&CK tags matter for retrieval; cve./detection. tags are noise here.
    out["tags"] = [t for t in (rule.get("tags") or []) if isinstance(t, str) and t.startswith("attack.")]
    out["falsepositives"] = [str(f) for f in (rule.get("falsepositives") or [])][:2]
    return out


def main(checkout: Path) -> None:
    rules_dir = checkout / "rules"
    if not rules_dir.is_dir():
        sys.exit(f"{rules_dir} not found; pass the path of a SigmaHQ checkout")
    rules: list[dict] = []
    for path in sorted(rules_dir.rglob("*.yml")):
        try:
            doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        entry = slim(doc)
        if entry:
            rules.append(entry)
    payload = {
        "_comment": "Slimmed SigmaHQ rules (https://github.com/SigmaHQ/sigma, Detection Rule License 1.1) used as "
        "few-shot examples for the author and refine stages. Rebuild with scripts/build_sigmahq_index.py.",
        "rules": rules,
    }
    OUT.write_text(json.dumps(payload, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
    print(f"wrote {OUT} ({len(rules)} rules, {OUT.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/sigma"))
