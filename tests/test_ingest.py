"""Tests for ingestion (Tavily mocked, HTTP mocked)."""

from __future__ import annotations

import httpx
import pytest

from rulesmith.config import Settings
from rulesmith.ingest import IngestError, Ingestor, clean_text, strip_html

LONG = "The actor used rundll32 to load a DLL from the temp folder. " * 10


class FakeTavily:
    def __init__(self, extract_results=None, search_results=None, fail=False):
        self.extract_results = extract_results or []
        self.search_results = search_results or []
        self.fail = fail
        self.calls = []

    def extract(self, **kwargs):
        self.calls.append(("extract", kwargs))
        if self.fail:
            raise RuntimeError("tavily down")
        return {"results": self.extract_results, "failed_results": []}

    def search(self, **kwargs):
        self.calls.append(("search", kwargs))
        return {"results": self.search_results}


def test_clean_text_and_strip_html():
    assert clean_text("a  \t b\n\n\n\nc") == "a b\n\nc"
    assert strip_html("<html><script>x()</script><p>Hello&amp;bye</p><div>two</div></html>") == "Hello&bye\n two"
    assert clean_text("x" * 70_000).endswith("[truncated]")


def test_from_text_rejects_short():
    ing = Ingestor(Settings())
    with pytest.raises(IngestError):
        ing.from_text("too short")
    res = ing.from_text(LONG)
    assert res.source.mode == "text" and res.source.chars == len(res.text)


def test_from_urls_prefers_tavily_and_records_provenance():
    tav = FakeTavily(extract_results=[{"url": "https://a.example/report", "raw_content": LONG}])
    ing = Ingestor(Settings(tavily_api_key="t"), tavily_client=tav)
    res = ing.from_urls(["https://a.example/report"])
    assert res.source.tavily_used and res.source.mode == "url"
    assert "# Source: https://a.example/report" in res.text
    assert tav.calls[0][1]["extract_depth"] == "advanced"


def test_from_urls_falls_back_to_http_when_tavily_fails():
    def handler(request):
        return httpx.Response(200, headers={"content-type": "text/html"}, text=f"<html><body><h1>Report</h1><p>{LONG}</p></body></html>")

    http = httpx.Client(transport=httpx.MockTransport(handler))
    ing = Ingestor(Settings(tavily_api_key="t"), tavily_client=FakeTavily(fail=True), http=http)
    res = ing.from_urls(["https://b.example/x"])
    assert not res.source.tavily_used
    assert "rundll32" in res.text and "<p>" not in res.text


def test_from_urls_validates_scheme_and_handles_total_failure():
    ing = Ingestor(Settings())
    with pytest.raises(IngestError):
        ing.from_urls(["ftp://nope"])
    http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    ing = Ingestor(Settings(), http=http)
    with pytest.raises(IngestError):
        ing.from_urls(["https://c.example/x"])


def test_from_query_requires_tavily_and_chains_to_extract():
    with pytest.raises(IngestError):
        Ingestor(Settings()).from_query("qilin ransomware")
    tav = FakeTavily(
        search_results=[{"url": "https://low.example", "score": 0.2, "title": "low"}, {"url": "https://hi.example", "score": 0.9, "title": "hi"}],
        extract_results=[{"url": "https://hi.example", "raw_content": LONG}],
    )
    ing = Ingestor(Settings(tavily_api_key="t"), tavily_client=tav)
    res = ing.from_query("qilin ransomware")
    assert res.source.mode == "query" and res.source.query == "qilin ransomware"
    assert res.source.urls[0] == "https://hi.example", "highest score first"
    assert [c[0] for c in tav.calls] == ["search", "extract"]
    assert res.candidates[0]["title"] == "hi"


def test_from_example_unknown():
    with pytest.raises(IngestError):
        Ingestor(Settings()).from_example("../../etc/passwd")
