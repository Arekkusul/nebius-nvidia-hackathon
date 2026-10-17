# RuleSmith

**Threat intel in. Tested detections out.**

RuleSmith is an autonomous detection-engineering agent. Give it a threat-intelligence report (a URL, pasted text, or just "latest Qilin ransomware TTPs") and it extracts the attacker behaviours, plans which ones deserve detections, writes Sigma rules *and the test events that prove them*, executes those rules against the tests and a 2,390-event benign baseline, fixes what fails, red-teams its own rules with evasion variants, and ships a deployable pack: Sigma YAML, Splunk SPL, Elastic Lucene, Microsoft KQL, tests, an ATT&CK Navigator layer and an evidence-linked report.

Every model call is an **NVIDIA Nemotron** model served by **Nebius Token Factory**. The web layer is **Tavily**.

Built for the [Nebius x NVIDIA Global AI Hackathon](https://nebiusglobalaihackathon.devpost.com/) (Best Apps and Agents track).

- Hosted demo: _coming with the submission_
- Demo video: _coming with the submission_
- Plan and research notes: [docs/PLAN.md](docs/PLAN.md) · Tool feedback: [FEEDBACK.md](FEEDBACK.md)

## Why this exists

Turning a vendor report into SIEM detections is a manual, multi-hour job for every SOC on the planet: read the report, work out which behaviours are observable, write the logic, guess the field names, write tests nobody has time for, and hope it is not too noisy. Microsoft's **CTI-REALM** benchmark (March 2026) measures exactly this workflow and frontier models score around 0.64. Published systems (LLMCloudHunter, AutoSigma, Sigma-Hunter) all report the same failure modes: invalid YAML, hallucinated fields, wrong log sources, over-broad logic. Their fix is an LLM judge.

RuleSmith's fix is **execution**. A rule is not done when a model says it looks right; it is done when it compiles, fires on every attack event, stays silent on every benign look-alike, and survives a red-team pass.

## How it works

```
 report URL / text / search query
          │
          ▼
 ┌────────────────┐   Tavily Search + Extract (or direct fetch)
 │ 1  Ingest      │
 └───────┬────────┘
         ▼
 ┌────────────────┐   Nemotron 3.5 Lightning · thinking OFF · strict JSON schema
 │ 2  Extract     │   behaviours, ATT&CK ids, observables, evidence quotes, IOCs
 └───────┬────────┘
         ▼
 ┌────────────────┐   Nemotron 3 Ultra · thinking ON
 │ 3  Plan        │   which behaviours deserve rules, logsource, fields, FP risks
 └───────┬────────┘
         ▼   (per candidate, in parallel)
 ┌────────────────┐   Nemotron 3 Super
 │ 4  Author      │   Sigma rule + positive & negative test events
 └───────┬────────┘
         ▼
 ┌────────────────┐   NO LLM. pySigma parse · field dictionary · ATT&CK index ·
 │ 5  Validate    │   compile to SQLite · run tests · run 2,390 benign events
 └───────┬────────┘
         ▼ fails?
 ┌────────────────┐   Nemotron 3 Super gets the exact events it got wrong
 │ 6  Refine      │   (bounded loop, default 3 iterations)      ──► back to 5
 └───────┬────────┘
         ▼
 ┌────────────────┐   Nemotron 3 Ultra · thinking ON
 │ 7  Red-team    │   evasion variants (flag aliases, casing, paths, sibling
 └───────┬────────┘   LOLBins) added as tests ──► 5 ──► one more 6 if needed
         ▼
 ┌────────────────┐   Sigma · Splunk · Elastic · KQL · tests.jsonl ·
 │ 8  Package     │   ATT&CK Navigator layer · report.md · zip
 └────────────────┘
```

### Where Nemotron and Token Factory do the work

| Tier | Model (Token Factory id) | Stage | Why this tier |
|---|---|---|---|
| fast | `nvidia/Nemotron-3_5-Lightning` | Extract | 1M context, cheapest, thinking off: structured extraction does not need a trace |
| main | `nvidia/nemotron-3-super-120b-a12b` | Author, Refine | strong tool/JSON adherence for rule YAML + test events; runs most often |
| reasoning | `nvidia/Nemotron-3-Ultra-550b-a55b` | Plan, Red-team | the two places where judgement matters: what to detect, and how an attacker would evade it |

All calls go through Token Factory's OpenAI-compatible endpoint with `response_format={"type": "json_schema"}` (falling back to `json_object` if a model rejects it) and `chat_template_kwargs.enable_thinking` toggled per stage. Model ids are resolved at startup against `GET /v1/models`, so renames do not break the app. Token usage and estimated cost per tier are shown for every run.

### Where Tavily does the work

- `search` discovers recent reporting for a free-text query ("Qilin ransomware affiliate TTPs"), ranked by score.
- `extract` (advanced depth, markdown) turns vendor blogs and advisories into clean text, far better than scraping.

Without a Tavily key the app still works on URLs (direct fetch) and pasted text; search mode is disabled.

### What "validated" means

A rule is **validated** only if all of these hold:

1. pySigma parses it and the SQLite backend compiles it.
2. Every field exists for that logsource (dictionary of ~110 logsources; unknown fields in core Sysmon categories are errors).
3. Every `attack.tXXXX` tag exists in the current ATT&CK release (867 techniques bundled).
4. Every positive test event matches, including the red-team evasion variants.
5. No negative (benign look-alike) test event matches.
6. Zero hits on the benign baseline corpus for that logsource. The corpus deliberately contains SCCM and Intune running encoded PowerShell, installers writing Run keys, admins running `whoami`/`net`/`schtasks`, and `rundll32` launching real control-panel DLLs. A rule that cannot tell those apart is **needs_review**, not validated.

The validator is the same approach Zircolite uses on real EVTX data, so passing here means the rule behaves the same way in production.

## Quick start

```bash
git clone https://github.com/Arekkusul/nebius-nvidia-hackathon.git
cd nebius-nvidia-hackathon
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env         # add NEBIUS_API_KEY (and TAVILY_API_KEY if you have one)
rulesmith models             # shows which Nemotron model each tier resolved to
rulesmith run --example macro_loader_campaign --out ./pack
rulesmith serve              # web UI on http://localhost:7860
```

Get a Token Factory key at https://tokenfactory.nebius.com (hackathon credits: code `NEBIUS-DEVPOST-GLOBAL26`). Get a Tavily key at https://app.tavily.com.

### Docker

```bash
docker build -t rulesmith .
docker run -p 7860:7860 -e NEBIUS_API_KEY=... -e TAVILY_API_KEY=... rulesmith
```

### Hosted demo on Hugging Face Spaces

```bash
HF_TOKEN=hf_... ./deploy/huggingface/push_space.sh <user>/rulesmith
```

Then add `NEBIUS_API_KEY` (and optionally `TAVILY_API_KEY`) as Space secrets. Set `RULESMITH_DEMO_LOCKED=true` to restrict visitors to the bundled example reports and the recorded replays, so judges can explore without burning your credits.

### CLI

```
rulesmith run --example <id> [--out DIR] [--max-rules N] [--iterations N] [--no-redteam] [--json]
rulesmith run --url https://... [--url https://...]
rulesmith run --query "Scattered Spider help-desk social engineering 2026"
rulesmith run --text-file report.md
rulesmith examples
rulesmith models
rulesmith serve [--port 7860]
```

### API

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | configured keys, resolved models |
| GET | `/api/examples` | bundled example reports |
| POST | `/api/runs` | start a run `{mode: url|text|query|example, value, urls, max_rules, max_refine_iterations, enable_redteam}` |
| GET | `/api/runs/{id}/events` | Server-Sent Events stream of the agent's progress |
| GET | `/api/runs/{id}` | status and full result JSON |
| GET | `/api/runs/{id}/download` | zip pack |
| GET | `/api/runs/{id}/report.md` · `/navigator.json` | report, ATT&CK Navigator layer |
| GET | `/api/replays` · `/api/replays/{id}` | recorded runs for the demo |

Interactive docs at `/api/docs`.

## Evaluation

`python eval/run_eval.py --record` runs the five bundled reports (Windows loader, ransomware affiliate, Linux cryptominer, AWS credential abuse, LSASS/lateral movement) and writes `eval/results.md`. The table reports, per report: behaviours extracted, rules written, rules validated, first-try pass rate, attack events caught, benign look-alikes blocked, baseline false positives, refine cycles, red-team variants, tokens and cost.

Results from the recorded runs: see [eval/results.md](eval/results.md).

## Repository layout

```
rulesmith/
  config.py        settings, model tiers, pricing
  llm.py           Token Factory client (json_schema + fallback, thinking toggle, repair, usage)
  models.py        pydantic schemas = JSON schemas handed to Nemotron
  prompts.py       stage prompts and the Sigma cheat-sheet
  ingest.py        Tavily search/extract, direct fetch fallback
  extract.py plan.py author.py refine.py redteam.py   the five Nemotron stages
  validate/        sigma_check.py fields.py attack.py runner.py (SQLite) corpus.py
  convert.py       pySigma backends: Splunk, Elastic, Kusto, SQLite
  package.py       Navigator layer, report.md, zip
  pipeline.py      orchestrator + event stream + metrics
  cli.py           command line
  server/          FastAPI API + static UI
data/              benign_corpus.jsonl (2,390 events), field_schemas.json, attack_techniques.json
examples/reports/  five synthetic reports for offline demo and eval
examples/runs/     recorded runs used by replay mode
eval/              benchmark harness
scripts/           corpus and ATT&CK index generators
tests/             47 tests, no network needed
```

## Testing

```bash
pytest -q
```

The suite covers the Token Factory client (JSON-mode fallback, repair loop, model resolution), every validator component, the SQLite runner, ingestion with Tavily mocked, the full pipeline through a scripted fake model (including a too-broad rule that must be refined using benign-corpus evidence and a red-team variant that forces a hardening pass), conversions, packaging, the API including the SSE stream, and the CLI.

## Limitations and honest notes

- Test events and the benign corpus are synthetic. The corpus is realistic and adversarially chosen, but a rule that passes here still deserves a look at your own telemetry before it goes to production. That is why the pack ships the tests: run them against your SIEM.
- The field dictionary covers ~110 logsources. For logsources it does not know, field names are not checked (reported as info).
- Extraction is only as good as the report. Marketing-heavy posts with no concrete observables produce few detectable behaviours, and the agent will say so.
- KQL conversion uses the Microsoft Defender XDR pipeline; logsources it does not map (e.g. `wmi_event`) report a conversion error for that target only.

## License

MIT. See [LICENSE](LICENSE).
