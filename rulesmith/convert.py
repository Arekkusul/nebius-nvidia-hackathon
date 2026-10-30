"""Convert validated Sigma rules into SIEM queries with pySigma backends.

Called by the pipeline once a rule leaves the refine/red-team loop, just
before packaging: each target backend renders the rule, and a target that
fails reports its error alongside the queries that worked.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sigma.rule import SigmaRule

from .validate.runner import compile_rule

# Each target parses the YAML fresh because pySigma pipelines mutate the rule
# object in place (the Microsoft XDR pipeline renames fields, for example).
TARGETS: dict[str, dict[str, Any]] = {
    "splunk": {"label": "Splunk SPL", "ext": "spl"},
    "elasticsearch": {"label": "Elastic (Lucene)", "ext": "lucene"},
    "kusto": {"label": "Microsoft Defender XDR / Sentinel (KQL)", "ext": "kql"},
    "sqlite": {"label": "SQLite (Zircolite)", "ext": "sql"},
}


# Backends are imported inside each converter: they are heavy packages, and a
# missing one then surfaces as that target's error rather than breaking the module.
def _splunk(rule: SigmaRule) -> str:
    """Render the rule as Splunk SPL."""
    from sigma.backends.splunk import SplunkBackend

    return SplunkBackend().convert_rule(rule)[0]


def _elastic(rule: SigmaRule) -> str:
    """Render the rule as an Elasticsearch Lucene query."""
    from sigma.backends.elasticsearch import LuceneBackend

    return LuceneBackend().convert_rule(rule)[0]


def _kusto(rule: SigmaRule) -> str:
    """Render the rule as KQL; the XDR pipeline maps Sigma fields onto Defender tables."""
    from sigma.backends.kusto import KustoBackend
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

    return KustoBackend(processing_pipeline=microsoft_xdr_pipeline()).convert_rule(rule)[0]


# "sqlite" reuses the validator's compiler, so the query shipped to the analyst
# is exactly the one the test events were run against.
_CONVERTERS: dict[str, Callable[[SigmaRule], str]] = {
    "splunk": _splunk,
    "elasticsearch": _elastic,
    "kusto": _kusto,
    "sqlite": compile_rule,
}


def convert_rule_all(sigma_yaml: str, targets: list[str] | None = None) -> tuple[dict[str, str], dict[str, str]]:
    """Return (queries, errors) keyed by target name.

    A target that cannot express the rule (unsupported logsource for the XDR
    pipeline, say) reports an error instead of aborting the others.
    """
    queries: dict[str, str] = {}
    errors: dict[str, str] = {}
    for target in targets or list(TARGETS):
        fn = _CONVERTERS.get(target)
        if fn is None:
            errors[target] = "unknown target"
            continue
        try:
            rule = SigmaRule.from_yaml(sigma_yaml)
            queries[target] = fn(rule)
        except Exception as exc:  # noqa: BLE001 - surface per-target failures
            errors[target] = f"{type(exc).__name__}: {str(exc)[:300]}"
    return queries, errors
