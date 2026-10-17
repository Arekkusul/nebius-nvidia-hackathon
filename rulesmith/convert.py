"""Convert validated Sigma rules into SIEM queries with pySigma backends."""

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


def _splunk(rule: SigmaRule) -> str:
    from sigma.backends.splunk import SplunkBackend

    return SplunkBackend().convert_rule(rule)[0]


def _elastic(rule: SigmaRule) -> str:
    from sigma.backends.elasticsearch import LuceneBackend

    return LuceneBackend().convert_rule(rule)[0]


def _kusto(rule: SigmaRule) -> str:
    from sigma.backends.kusto import KustoBackend
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

    return KustoBackend(processing_pipeline=microsoft_xdr_pipeline()).convert_rule(rule)[0]


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
