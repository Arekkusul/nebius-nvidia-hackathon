"""Turn a URL, a search query, pasted text or a bundled example into clean report text.

Tavily is the web layer: ``search`` discovers recent reporting for a query and
``extract`` returns clean markdown for a URL (far better than scraping a
vendor blog by hand). Without a Tavily key we fall back to a plain HTTP fetch
with HTML stripping so the app still works, just with less polish.
"""

from __future__ import annotations

import html
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from .config import Settings
from .models import SourceInfo

log = logging.getLogger(__name__)

EXAMPLES_DIR = Path(__file__).resolve().parents[1] / "examples" / "reports"
MAX_CHARS = 60_000  # ~15k tokens; comfortably inside every Nemotron context window
_TAG_RX = re.compile(r"<(script|style|nav|footer|header|noscript)[^>]*>.*?</\1>", re.DOTALL | re.IGNORECASE)
_HTML_RX = re.compile(r"<[^>]+>")
_WS_RX = re.compile(r"[ \t\r\f\v]+")
_NL_RX = re.compile(r"\n\s*\n+")


class IngestError(RuntimeError):
    """Raised when no usable text could be obtained."""


@dataclass
class IngestResult:
    """Clean text plus provenance."""

    text: str
    source: SourceInfo
    candidates: list[dict[str, Any]] = field(default_factory=list)  # search hits when mode == query


def clean_text(raw: str) -> str:
    """Normalise whitespace and cap length. Works on markdown or plain text."""
    text = raw.replace(" ", " ")
    text = _WS_RX.sub(" ", text)
    text = _NL_RX.sub("\n\n", text)
    text = text.strip()
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + "\n\n[truncated]"
    return text


def strip_html(page: str) -> str:
    """Very small HTML-to-text used only on the no-Tavily fallback path."""
    page = _TAG_RX.sub(" ", page)
    page = re.sub(r"</(p|div|li|h[1-6]|tr|br|section|article)>", "\n", page, flags=re.IGNORECASE)
    page = _HTML_RX.sub(" ", page)
    return clean_text(html.unescape(page))


def list_examples() -> list[dict[str, str]]:
    """Bundled example reports, used by the UI picker and the eval harness."""
    out = []
    for p in sorted(EXAMPLES_DIR.glob("*.md")):
        first = p.read_text(encoding="utf-8").splitlines()[0].lstrip("# ").strip() if p.stat().st_size else p.stem
        out.append({"id": p.stem, "title": first})
    return out


class Ingestor:
    """Resolves any supported input into report text."""

    def __init__(self, settings: Settings, tavily_client: Any | None = None, http: httpx.Client | None = None) -> None:
        self.settings = settings
        self._tavily = tavily_client
        self._http = http

    # ------------------------------------------------------------- clients

    @property
    def tavily(self) -> Any | None:
        """Lazily construct the Tavily client when a key is configured."""
        if self._tavily is None and self.settings.has_tavily:
            from tavily import TavilyClient

            self._tavily = TavilyClient(api_key=self.settings.tavily_api_key)
        return self._tavily

    @property
    def http(self) -> httpx.Client:
        if self._http is None:
            self._http = httpx.Client(timeout=30.0, follow_redirects=True, headers={"User-Agent": "RuleSmith/0.1 (+https://github.com/Arekkusul/nebius-nvidia-hackathon)"})
        return self._http

    # ------------------------------------------------------------- public

    def from_text(self, text: str) -> IngestResult:
        cleaned = clean_text(text)
        if len(cleaned) < 200:
            raise IngestError("Report text is too short to analyse (need at least ~200 characters).")
        return IngestResult(text=cleaned, source=SourceInfo(mode="text", chars=len(cleaned)))

    def from_example(self, example_id: str) -> IngestResult:
        safe = re.sub(r"[^A-Za-z0-9_-]", "", example_id)
        path = EXAMPLES_DIR / f"{safe}.md"
        if not path.exists():
            raise IngestError(f"Unknown example '{example_id}'.")
        cleaned = clean_text(path.read_text(encoding="utf-8"))
        return IngestResult(text=cleaned, source=SourceInfo(mode="example", urls=[f"example://{safe}"], chars=len(cleaned)))

    def from_urls(self, urls: list[str]) -> IngestResult:
        urls = [u.strip() for u in urls if u and u.strip()]
        if not urls:
            raise IngestError("No URL provided.")
        for u in urls:
            if not re.match(r"^https?://", u, re.IGNORECASE):
                raise IngestError(f"Only http(s) URLs are supported: {u}")
        texts: list[str] = []
        tavily_used = False
        if self.tavily is not None:
            try:
                resp = self.tavily.extract(urls=urls, extract_depth="advanced", format="markdown")
                for item in resp.get("results", []):
                    content = item.get("raw_content") or ""
                    if content.strip():
                        texts.append(f"# Source: {item.get('url', '')}\n\n{content}")
                for failed in resp.get("failed_results", []) or []:
                    log.warning("tavily extract failed for %s: %s", failed.get("url"), failed.get("error"))
                tavily_used = bool(texts)
            except Exception as exc:  # noqa: BLE001 - degrade to plain fetch
                log.warning("tavily extract error (%s); falling back to direct fetch", exc)
        if not texts:
            for u in urls:
                try:
                    r = self.http.get(u)
                    r.raise_for_status()
                    body = r.text
                    text = strip_html(body) if "html" in r.headers.get("content-type", "").lower() or "<html" in body[:2000].lower() else clean_text(body)
                    if text:
                        texts.append(f"# Source: {u}\n\n{text}")
                except Exception as exc:  # noqa: BLE001
                    log.warning("direct fetch failed for %s: %s", u, exc)
        if not texts:
            raise IngestError("Could not retrieve readable content from the URL(s).")
        combined = clean_text("\n\n".join(texts))
        return IngestResult(text=combined, source=SourceInfo(mode="url", urls=urls, tavily_used=tavily_used, chars=len(combined)))

    def from_query(self, query: str, max_results: int = 5) -> IngestResult:
        """Discover recent reporting with Tavily search, then extract the best hits."""
        query = query.strip()
        if not query:
            raise IngestError("Empty search query.")
        if self.tavily is None:
            raise IngestError("Search mode needs a TAVILY_API_KEY; paste a URL or report text instead.")
        resp = self.tavily.search(
            query=f"{query} threat report TTPs",
            search_depth="advanced",
            topic="general",
            max_results=max_results,
            include_raw_content=False,
            time_range="year",
        )
        hits = [h for h in resp.get("results", []) if h.get("url")]
        if not hits:
            raise IngestError("Tavily found no reporting for that query.")
        # Prefer high-score hits from primary sources over aggregators.
        hits.sort(key=lambda h: float(h.get("score", 0)), reverse=True)
        chosen = hits[:3]
        result = self.from_urls([h["url"] for h in chosen])
        result.source = SourceInfo(mode="query", query=query, urls=[h["url"] for h in chosen], tavily_used=True, chars=len(result.text))
        result.candidates = [{"title": h.get("title", ""), "url": h["url"], "score": h.get("score", 0)} for h in hits]
        return result
