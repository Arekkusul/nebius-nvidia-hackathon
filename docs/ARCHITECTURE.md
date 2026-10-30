# Architecture

This page is for people who want to read or change the code. For what RuleSmith
does and how to run it, start with the [README](../README.md).

## One run, end to end

```
 input (url | text | query | example)
   │
   ▼
 ingest.py      Tavily extract/search, or a direct HTTP fetch        → IngestResult (text + source)
   │
   ▼
 extract.py     Nemotron fast tier, thinking off                     → ThreatReport (behaviours, IOCs)
   │
   ▼
 plan.py        Nemotron reasoning tier, thinking on                 → DetectionPlan (candidates, skipped)
   │
   ▼  for every candidate, in parallel
 author.py      Nemotron main tier, SigmaHQ few-shot                 → RuleDraft (Sigma YAML + test events)
   │
   ▼
 validate/      pySigma parse → field check → ATT&CK check →
                SQLite execution against the tests and the
                benign corpus                                         → ValidationReport
   │
   ├─ failed?   refine.py  (main tier, sees the exact misses)         → RuleDraft, loop ≤ N times
   │
   ├─ passed?   redteam.py (reasoning tier) adds evasion variants,
   │            then validate again and refine once more if needed
   │
   ▼
 convert.py     pySigma backends: Splunk, Elastic, KQL, SQLite       → queries per rule
   │
   ▼
 package.py     Navigator layer, report.md, zip                      → RunResult on disk
```

`pipeline.py` owns this sequence. Everything else is a stage with one public
function that takes typed inputs and returns typed outputs, so a stage can be
unit-tested on its own with the scripted fake model.

## Modules

| Path | Role |
|---|---|
| `rulesmith/config.py` | `Settings` (read from the environment), the three model tiers, model preference lists, list prices used for cost estimates. |
| `rulesmith/llm.py` | The Token Factory client. `complete_structured()` asks for JSON matching a pydantic schema, falls back from `json_schema` to JSON mode, repairs malformed output once, records tokens, cost and latency per call. `FakeLLM` answers from fixtures for tests. |
| `rulesmith/models.py` | Every pydantic model. These double as the JSON schemas handed to the model and as the on-disk format of a run. `ThreatReport` cleans its IOC list on construction. |
| `rulesmith/prompts.py` | The system prompts for each stage and the Sigma cheat-sheet they share. |
| `rulesmith/ingest.py` | Report acquisition: Tavily extract for URLs, Tavily search for queries, a plain fetch when Tavily is not configured, bundled example reports. |
| `rulesmith/extract.py`, `plan.py`, `author.py`, `refine.py`, `redteam.py` | The five model-driven stages. Each is a thin wrapper around one structured call plus the post-processing that keeps the model honest (normalising YAML, pruning test events that contradict the rule, retiring unreachable red-team variants). |
| `rulesmith/sigmahq.py` | Picks a few real SigmaHQ rules for the same logsource and technique to show the author as examples. |
| `rulesmith/validate/` | `sigma_check.py` (pySigma parse, structure and modifier checks), `fields.py` (field dictionary per logsource), `attack.py` (technique ids), `runner.py` (compiles to SQLite and executes against events), `corpus.py` (the benign baseline), `__init__.py` (combines them into a `ValidationReport` with per-selection miss diagnostics). |
| `rulesmith/convert.py` | pySigma backend conversions. A backend that cannot map a logsource reports an error for that target only. |
| `rulesmith/package.py` | ATT&CK Navigator layer, Markdown report, zip pack. |
| `rulesmith/pipeline.py` | `Pipeline.run()`, the event stream, metrics, the refine and red-team loop, saving runs, loading recorded runs. |
| `rulesmith/cli.py` | `rulesmith run | replay | examples | models | serve`. |
| `rulesmith/server/app.py` | FastAPI: health, examples, live runs with a Server-Sent Events stream, recorded replays, downloads, public-demo guards (budget, rate limits, lock). |
| `rulesmith/server/static/` | The UI: one HTML file, one stylesheet, one script, no build step. The same files run as a static Hugging Face Space in replay-only mode. |
| `data/` | Generated inputs: the benign corpus, field dictionary, ATT&CK index, slimmed SigmaHQ rules. Regenerate with the scripts in `scripts/`. |
| `examples/` | Five synthetic reports and the recorded runs that back replay mode and the eval. |
| `eval/` | The benchmark harness and its last results. |

## The event stream

The pipeline emits plain dict events through a callback. The CLI prints them,
the server buffers them per run and streams them over SSE, and the UI renders
them. Each event has `type`, `stage`, `message`, `ts` and type-specific extras:

| `type` | `stage` | Extras |
|---|---|---|
| `stage` | `ingest`, `extract`, `plan`, `rules` | `status` (`running` / `done`); `report` on extract done, `plan` on plan done |
| `rule` | the candidate id (`D1`, `D2` …) | `status` (`authoring`, `refining`, `validated`, `needs_review`, `failed`), `title`; the finished `rule` on the last event |
| `done` | `done` | `stats`, `run_id` |
| `error` | `done` | the failure message |
| `end` | – | sent by the server only, closes the SSE stream |

Replay mode synthesises the same events from a saved `RunResult`, which is why
a recorded run animates exactly like a live one.

## Rule status

- **validated**: parses, compiles, catches every attack test event (including the
  red-team variants), stays silent on every benign look-alike, and zero hits on
  the benign baseline.
- **needs_review**: parses and compiles but misses at least one test after the
  refine budget is spent. The pack keeps the failing tests and the validator's
  per-selection explanation of each miss, so the fix is usually small.
- **failed**: never parsed or compiled.

A refinement that scores worse than an earlier draft is rolled back; the run
keeps the best draft seen.

## Model routing

Three tiers, resolved at start-up from the Token Factory model list:

| Tier | Used for | Thinking |
|---|---|---|
| fast | extraction | off |
| main | authoring, refinement | off |
| reasoning | planning, red-team | on |

`RULESMITH_MODEL_<TIER>` pins a tier to a model id; otherwise the first match
from the preference list in `config.py` wins. Every call records prompt and
completion tokens, estimated cost from the list prices in `config.py`, and
latency; `RunResult.metrics` sums them and the UI shows the routing table.

## Public-demo guards

All in `server/app.py`, all configured by environment variables documented in
`.env.example`:

- `RULESMITH_DEMO_BUDGET_USD`: in-process spend cap. Runs are refused once it is
  spent; replays keep working. Resets when the process restarts.
- `RULESMITH_DEMO_RUNS_PER_HOUR` and `RULESMITH_DEMO_RUNS_PER_IP_PER_HOUR`:
  rolling-hour rate limits for the whole service and per client address
  (`X-Forwarded-For` aware), returning HTTP 429.
- `RULESMITH_DEMO_MAX_RULES`: caps rules per run while a budget is set.
- `RULESMITH_DEMO_LOCKED`: bundled examples and replays only.

## Extension points

- **A new input source**: add a branch to `ingest.py` that returns an
  `IngestResult`, and a `mode` value in `RunInput`.
- **A new logsource**: add its fields to `data/field_schemas.json` (key
  `<product>/<category>` or `<product>/service:<service>`), add benign events
  for it to `scripts/gen_benign_corpus.py` and regenerate the corpus, and check
  the pySigma pipelines in `convert.py` can map it.
- **A new SIEM target**: add a backend to `TARGETS` in `convert.py`; the pack
  and UI pick it up from the conversions dict.
- **A new check**: add it to `validate/` and fold its issues into
  `ValidationReport` in `validate/__init__.py`; the refine prompt receives
  every issue message verbatim.
- **A different model provider**: implement the `BaseLLM` interface in
  `llm.py`. The stages only call `complete_structured()`.
