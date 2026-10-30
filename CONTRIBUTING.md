# Contributing

Thanks for looking at RuleSmith. This page covers the development setup, the
checks to run before a pull request, and how the generated files are rebuilt.
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains how the code is organised.

## Set up

Python 3.11 or newer.

```bash
git clone https://github.com/Arekkusul/nebius-nvidia-hackathon.git
cd nebius-nvidia-hackathon
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env                                  # optional: add keys for live runs
```

Nothing below needs an API key except the live smoke tests and a real run.
Replays, the test-suite, the UI smoke test and the eval in replay mode all work
offline.

## Run it

```bash
rulesmith examples                                   # bundled reports and recorded runs
rulesmith replay macro_loader_campaign --out ./pack  # re-package a recorded run, no key needed
rulesmith serve --open                               # web UI + API on http://localhost:7860
rulesmith run --example macro_loader_campaign        # a live run (needs NEBIUS_API_KEY)
```

## Check before you push

```bash
ruff check rulesmith tests scripts eval deploy       # lint (line length 110)
pytest -q                                            # offline suite, under 10 seconds
pytest tests/test_live.py -s                         # live smoke tests, only with keys set
```

The UI has its own headless smoke test. It needs Node 22+ and a Chromium
binary (Playwright's works) and takes about 20 seconds:

```bash
python scripts/fake_server.py --port 7862 &          # live runs answered by the scripted fake model
rulesmith serve --port 7861 &                        # replays
node scripts/ui_smoke.js /path/to/chrome http://127.0.0.1:7862 http://127.0.0.1:7861
```

It drives a live run, a replay with a deep link, the filters, the theme toggle
and a phone-width layout, and fails on any console error.

## Where things live

```
rulesmith/            the package (see docs/ARCHITECTURE.md for a module map)
rulesmith/server/     FastAPI app and the static UI (index.html, style.css, app.js; no build step)
tests/                pytest suite; tests/fixtures.py holds the scripted fake-model answers
data/                 generated inputs (benign corpus, field dictionary, ATT&CK index, SigmaHQ examples)
examples/reports/     synthetic reports for offline demos and the eval
examples/runs/        recorded runs that back replay mode
eval/                 benchmark harness and its last results
scripts/              generators for data/, the UI smoke test, demo GIF and video recorders
deploy/huggingface/   static Space builder, live Space files, push script
```

## Conventions

- **Stages are functions.** A stage takes typed inputs, makes at most one
  structured model call, and returns typed outputs. Keep orchestration in
  `pipeline.py`.
- **Schemas are the contract.** Anything the model returns is a pydantic model
  in `models.py`; validators there are the place to clean model output.
- **Tests run offline.** New behaviour gets a test that uses `FakeLLM` and the
  fixtures; live calls belong only in `tests/test_live.py`, which skips without
  keys.
- **Comment the why.** Docstrings on every public function; inline comments
  where a fallback, a limit or an edge case is not obvious from the code.
- **Never commit keys.** `NEBIUS_API_KEY` and `TAVILY_API_KEY` come from the
  environment or an untracked `.env`.
- **Prompts are code.** A prompt change is reviewed like a logic change: run
  `python eval/run_eval.py` with a key and compare `eval/results.md` before and
  after.

## Regenerating the generated files

| File | Command | Notes |
|---|---|---|
| `data/benign_corpus.jsonl` | `python scripts/gen_benign_corpus.py` | Seeded; the output is deterministic. |
| `data/attack_techniques.json` | `python scripts/build_attack_index.py [stix-path-or-url]` | Downloads the enterprise STIX bundle when no path is given. |
| `data/sigmahq_examples.json` | `python scripts/build_sigmahq_index.py /path/to/sigma` | Needs a SigmaHQ checkout; the file is DRL 1.1 licensed. |
| `examples/runs/*.json` | `python eval/run_eval.py --record` | Live; re-records every example (about $1 in total). |
| `eval/results.md` | `python eval/run_eval.py --replay` | Scores the recorded runs offline. |
| `docs/demo.gif`, `docs/screenshot.png` | `node scripts/record_demo.js` then `python scripts/make_gif.py` | Headless Chromium; see the script headers. |
| `deploy/huggingface/static_site/` | `python deploy/huggingface/build_static.py` | The replay-only site; upload it to a static Space. |

## Pull requests

Keep them focused. Say what changed and why, include the test you added, and
paste the `pytest -q` line. If a change touches a prompt or a validator,
mention how the eval numbers moved.
