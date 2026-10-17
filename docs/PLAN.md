# RuleSmith — Project Plan

> Threat intel in. Tested, deployable detection rules out.
> Built for the Nebius x NVIDIA Global AI Hackathon (deadline 30 Oct 2026, 10:00 PT).

## 1. What the research found

### Hackathon facts (from the official Devpost rules, fetched 17 Oct 2026)
- **Hard requirements:** runtime call to Nebius Token Factory (or run on Nebius AI Cloud) **and** at least one NVIDIA open model.
  Calling Nemotron through Token Factory satisfies both. The rest of the app can live anywhere.
- **Must submit:** public repo with a detectable OSS license (MIT), README with setup, a hosted demo URL that
  stays up and free until judging ends (15 Dec 2026), a public YouTube video ≤ 3 min, a project description,
  and a **feedback section** on Token Factory / NVIDIA models (required, and worth a $100 bonus prize).
- **Judging:** pass/fail theme fit, then 1–5 on four equally weighted criteria:
  Technological Implementation, Design (complete product, not a PoC), Potential Impact, Quality of the Idea
  (creative, non-obvious use of Token Factory + Nemotron, genuine understanding of the problem space).
  Ties break in that order, so implementation quality matters most.
- **Prizes:** $20k / $10k / $6k overall; Jetson Orin Nano per track; $3k Best Use of Tavily (needs a
  functional runtime Tavily call); $100 x10 Most Valuable Feedback. A project can win one overall OR one
  track award, plus one bonus award.
- **Organizer hints:** "a multi-step autonomous workflow that chains tools end to end stands out";
  "an agent that plans, writes, tests, and iterates ... with minimal human input"; use Ultra for reasoning
  and Nano/Super for fast calls; name the project like a human; make the required tools impossible to miss.
- **Field size:** 24,107 registered participants. Generic chatbots, RAG-over-PDF and code-completion
  wrappers will be the bulk of entries.

### Token Factory technical facts
- OpenAI-compatible: `https://api.tokenfactory.nebius.com/v1/`, `NEBIUS_API_KEY` bearer token.
- Function calling and `response_format: {"type": "json_schema"}` are supported; docs recommend also
  restating the schema in the prompt. Models are tagged "JSON mode" in the catalog.
- Nemotron on Token Factory (public, shared endpoints):
  `nvidia/Nemotron-3_5-Lightning` (30B/3B active, 1M ctx, $0.06/$0.24 per 1M),
  `nvidia/nemotron-3-super-120b-a12b` (120B/12B, 256K, $0.30/$0.90),
  `nvidia/Nemotron-3-Ultra-550b-a55b` (550B/55B, 1M, $1/$3),
  `nvidia/Nemotron-3.5-Super-VL` (vision), Nemotron 3 Nano 30B-A3B.
  IDs are resolved at runtime against `GET /v1/models` because casing differs between sources.
- Nemotron reasoning is on by default; toggle with `extra_body={"chat_template_kwargs": {"enable_thinking": false}}`.
  Recommended sampling: temp 1.0 / top_p 0.95 (Super, Lightning), temp 0.6 / top_p 0.95 for tool calling (Nano).
- Rate limits auto-scale in 15-minute windows; watch `x-ratelimit-remaining-*` headers.
- Token Factory **Sandboxes** (code execution with checkpoints/branches) exist but are Beta and gated by an
  access request, so this project does not depend on them.
- Fine-tuning is available but no Nemotron base is in the fine-tunable list today (feedback item).

### Problem-space facts
- Turning a threat-intel report into SIEM detections is a manual, multi-hour job for detection engineers.
- Published research (LLMCloudHunter 2024, AutoSigma Aug 2026, Sigma-Hunter Oct 2026) shows LLMs produce
  invalid YAML, wrong log sources, unsupported fields and over-broad logic; the mitigation everyone
  reaches for is an LLM judge, **not execution**.
- Microsoft released **CTI-REALM** (Mar 2026), a benchmark for exactly this workflow. Best frontier
  models score ~0.64 reward. This is an open, recognised, hard problem.
- pySigma has a maintained SQLite backend (the engine behind Zircolite), so a generated rule can be
  *executed* against telemetry in-process. That is the lever nobody in the field is using.

## 2. The idea

**RuleSmith** is an autonomous detection-engineering agent. Give it a threat report (URL, PDF text, or
just a query like "latest Qilin ransomware TTPs") and it:

1. **Ingests** the intel with Tavily (`search` for discovery, `extract` for clean full text).
2. **Extracts behaviours** with Nemotron 3.5 Lightning (fast, thinking off, strict JSON schema):
   ATT&CK technique, observables, log source, evidence quote. IOCs are separated from behaviours
   because behaviours are what you detect.
3. **Plans** with Nemotron 3 Ultra (thinking on): which behaviours are detectable, which Sigma
   logsource/fields to use, how specific to be.
4. **Authors** Sigma rules *and their tests* with Nemotron 3 Super: positive events that must match,
   benign look-alike events that must not.
5. **Validates by execution**, no LLM involved: pySigma parse + lint, field-dictionary check,
   ATT&CK ID check, compile to SQLite, run against the test events **and a 2k-event benign baseline
   corpus**, score TP/FN/FP.
6. **Refines** in a bounded loop: failures go back to Super with the exact failing events.
7. **Red-teams** with Ultra: generates the evasions an attacker would try (flag aliases, casing,
   path tricks, encoding), adds them as tests, and hardens the rule again.
8. **Packages**: Sigma YAML, Splunk SPL, Elastic, Microsoft KQL (via pySigma backends), test events,
   ATT&CK Navigator layer, evidence-linked markdown report, zip download.

Every run shows which Nemotron tier did what, token usage, estimated cost, iterations, and the
measured test results. The eval harness runs the bundled reports and prints the table in the README.

### Why it can win
- **Technological Implementation:** three Nemotron tiers routed by job, strict JSON schema outputs,
  thinking toggled per stage, a real execution-based test loop, Tavily runtime calls, measurable numbers.
- **Design:** a complete product: web UI with live agent stream, downloadable pack, CLI, Docker,
  hosted demo with replay mode so judges never hit a dead key.
- **Potential Impact:** a specific audience (SOC / detection engineers), a specific pain (hours per
  report), and a demonstrated result (rules that provably fire on the behaviour and stay quiet on
  benign telemetry).
- **Quality of the Idea:** detection-as-code with an adversarial self-play loop is non-obvious, and
  the problem space is backed by current research and a Microsoft benchmark.
- **Track:** Best Apps and Agents (safest theme fit: "a workflow that runs itself"). Bonus: Best Use
  of Tavily.

## 3. Architecture

```
rulesmith/
  config.py        settings, model routing (fast / main / reasoning), pricing table
  llm.py           Token Factory client: json_schema with fallback, thinking toggle, retries, usage
  models.py        pydantic schemas for every stage
  ingest.py        Tavily search/extract, httpx fallback, text cleaning
  extract.py       stage 2  (Lightning)
  plan.py          stage 3  (Ultra)
  author.py        stage 4  (Super)
  refine.py        stage 6  (Super)
  redteam.py       stage 7  (Ultra)
  validate/        sigma_check.py, fields.py, runner.py (sqlite), corpus.py, attack.py
  convert.py       pySigma backends -> SPL / Elastic / KQL
  package.py       zip, Navigator layer, report
  pipeline.py      orchestrator with event callbacks (SSE) and metrics
  cli.py           `rulesmith run ...`, `rulesmith eval`
  server/          FastAPI + static SPA
data/              benign corpus, field dictionary, ATT&CK technique index
examples/reports/  bundled threat reports for offline demo + eval
eval/              benchmark harness
tests/             pytest, FakeLLM, no network required
```

## 4. Testing strategy
- Every deterministic component has unit tests (validator, runner, corpus, fields, converters, packaging).
- The agent stages are tested with a `FakeLLM` that returns schema-valid canned outputs, including
  deliberately broken rules to exercise the refine loop.
- API tests use FastAPI's TestClient including the SSE stream.
- A live smoke test (skipped without keys) exercises Token Factory and Tavily end to end.
- `rulesmith eval` runs the bundled reports and reports pass rate, FP rate, iterations, cost.

## 5. Delivery checklist (Devpost)
- [ ] MIT LICENSE visible in About
- [ ] README: setup, how Nemotron + Token Factory + Tavily are used, architecture, eval table
- [ ] FEEDBACK.md: specific feedback on Token Factory and Nemotron
- [ ] SUBMISSION.md: Devpost description, Built With list, 3-minute video script
- [x] Hosted demo (Hugging Face static Space, replay mode): https://huggingface.co/spaces/Arekkusul/rulesmith
- [ ] Demo video on YouTube (≤ 3 min, no copyrighted music)
