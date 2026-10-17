"""Execute a compiled Sigma rule against JSON events using in-memory SQLite.

The pySigma SQLite backend turns a rule into ``SELECT * FROM logs WHERE ...``.
We materialise the events as one wide table (TEXT columns, NOCASE collation,
so Sigma's case-insensitive semantics hold) and ask SQLite which rows match.
This is the same approach Zircolite uses in production, which means a rule
that passes here behaves the same way on real EVTX data.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from sigma.backends.sqlite import sqliteBackend
from sigma.rule import SigmaRule

from ..models import TestEvent, TestOutcome

TABLE = "logs"
FULLTEXT_FIELD = "_sigma_fulltext"
_IDENT_RX = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\- ]*$")

# Column names the backend may reference. We parse them from the SQL so the
# table always has every column the WHERE clause needs (SQLite fails to
# prepare a query that mentions a missing column).
_COLUMN_RX = re.compile(r"`([^`]+)`|\b([A-Za-z_][A-Za-z0-9_.]*)\s*(?:LIKE|GLOB|REGEXP|=|!=|<>|>=|<=|>|<|IS\b|IN\b)", re.IGNORECASE)
_SQL_KEYWORDS = {"select", "from", "where", "and", "or", "not", "null", "is", "in", "like", "escape", "glob", "regexp", "coalesce", "true", "false", "cast", "as", "text", "integer"}


def compile_rule(rule: SigmaRule) -> str:
    """Convert a parsed Sigma rule into one SQLite WHERE query."""
    backend = sqliteBackend(table=TABLE, fulltext_field=FULLTEXT_FIELD, collate_nocase=True)
    queries = backend.convert_rule(rule)
    if not queries:
        raise ValueError("backend produced no query")
    return queries[0]


def _regexp(pattern: str, value: Any) -> bool:
    """REGEXP implementation for SQLite; NULL never matches."""
    if value is None:
        return False
    try:
        return re.search(pattern, str(value), re.IGNORECASE) is not None
    except re.error:
        return False


def _columns_in_sql(sql: str) -> set[str]:
    cols: set[str] = set()
    for quoted, bare in _COLUMN_RX.findall(sql):
        name = quoted or bare
        if name and name.lower() not in _SQL_KEYWORDS and not name.isdigit():
            cols.add(name)
    return cols


class RuleRunner:
    """Run one compiled rule against arbitrary event dicts."""

    def __init__(self, sql: str) -> None:
        self.sql = sql
        self.sql_columns = _columns_in_sql(sql)

    def _build(self, events: list[dict[str, Any]]) -> sqlite3.Connection:
        """Create the wide table and insert the events.

        SQLite column names are case-insensitive, so ``CommandLine`` and
        ``commandline`` must map to one column or CREATE TABLE fails with
        "duplicate column name". Model-written test events do mix casing, so
        keys are merged case-insensitively; the spelling the rule's SQL uses
        wins, otherwise the first spelling seen.
        """
        canonical: dict[str, str] = {}  # lowercase key -> column name used in the table
        for c in self.sql_columns:
            canonical.setdefault(c.lower(), c)
        for e in events:
            for k in e:
                if not k.startswith("_"):
                    canonical.setdefault(k.lower(), k)
        canonical.setdefault(FULLTEXT_FIELD.lower(), FULLTEXT_FIELD)
        ordered = sorted(canonical.values())
        conn = sqlite3.connect(":memory:")
        conn.create_function("regexp", 2, _regexp)
        col_sql = ", ".join(f'"{c}" TEXT COLLATE NOCASE' for c in ordered)
        conn.execute(f'CREATE TABLE {TABLE} (_row INTEGER PRIMARY KEY, {col_sql})')
        placeholders = ", ".join("?" for _ in ordered)
        col_list = ", ".join(f'"{c}"' for c in ordered)
        rows = []
        for i, e in enumerate(events):
            # Lower-cased view of the event so lookups match the merged columns.
            payload = {k.lower(): v for k, v in e.items() if not k.startswith("_")}
            fulltext = " ".join(str(v) for v in payload.values() if v is not None)
            row: list[Any] = []
            for c in ordered:
                if c == FULLTEXT_FIELD:
                    row.append(fulltext)
                else:
                    v = payload.get(c.lower())
                    if isinstance(v, bool):
                        v = "true" if v else "false"
                    elif isinstance(v, (list, dict)):
                        v = str(v)
                    row.append(None if v is None else str(v) if not isinstance(v, (int, float)) else v)
            rows.append((i, *row))
        conn.executemany(f"INSERT INTO {TABLE} (_row, {col_list}) VALUES (?, {placeholders})", rows)
        return conn

    def match_indices(self, events: list[dict[str, Any]]) -> set[int]:
        """Indices of events the rule matches."""
        if not events:
            return set()
        conn = self._build(events)
        try:
            sql = self.sql
            # The backend emits SELECT *; narrow to the row id for speed.
            if sql.upper().startswith("SELECT * FROM"):
                sql = "SELECT _row FROM" + sql[len("SELECT * FROM") :]
            cur = conn.execute(sql)
            return {int(r[0]) for r in cur.fetchall()}
        finally:
            conn.close()

    def run_events(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Return the events that matched."""
        hits = self.match_indices(events)
        return [e for i, e in enumerate(events) if i in hits]

    def run_tests(self, tests: list[TestEvent]) -> list[TestOutcome]:
        """Evaluate labelled test events; a test passes when matched == expected."""
        hits = self.match_indices([t.event for t in tests])
        outcomes = []
        for i, t in enumerate(tests):
            matched = i in hits
            expected = t.label == "positive"
            outcomes.append(TestOutcome(event_id=t.id, label=t.label, matched=matched, passed=(matched == expected)))
        return outcomes
