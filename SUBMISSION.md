# Devpost submission kit

Track: **Best Apps and Agents** · Bonus: **Best Use of Tavily** · Feedback section: see FEEDBACK.md

## Project name
RuleSmith

## Tagline
Threat intel in, tested detections out. An autonomous detection-engineering agent on NVIDIA Nemotron via Nebius Token Factory.

## Try it out
Hosted demo (recorded runs, no key needed; auto-plays one on arrival): https://huggingface.co/spaces/Arekkusul/rulesmith
Source: https://github.com/Arekkusul/nebius-nvidia-hackathon (clone it, add a Token Factory key, `rulesmith serve --open` to run it live on your own reports)

## Built with
Nebius Token Factory · NVIDIA Nemotron 3 Ultra · NVIDIA Nemotron 3 Super · NVIDIA Nemotron 3.5 Lightning · Tavily Search & Extract · Python · FastAPI · pySigma (SQLite, Splunk, Elasticsearch, Kusto backends) · SQLite · MITRE ATT&CK · Docker · Hugging Face Spaces

## Inspiration
Every SOC turns vendor threat reports into SIEM detections by hand. It takes hours per report and the result is rarely tested. Microsoft shipped a benchmark for this exact task in March 2026 (CTI-REALM) and the best frontier models score ~0.64; the academic systems all stop at "an LLM judge says it looks fine". We wanted an agent whose rules are *proven*, not reviewed.

## What it does
Give RuleSmith a report URL, pasted text, or a query like "latest Qilin ransomware TTPs". It:
1. fetches the intel with Tavily,
2. extracts behaviours with evidence quotes (Nemotron 3.5 Lightning),
3. plans which behaviours deserve rules and how to keep them specific (Nemotron 3 Ultra, thinking on),
4. writes Sigma rules plus positive and negative test events (Nemotron 3 Super),
5. validates with no LLM: pySigma parse, field dictionary, ATT&CK index, compiles to SQLite and executes against the tests and a 2,390-event benign baseline that includes SCCM running encoded PowerShell and installers writing Run keys,
6. feeds failures back to Super with the exact events it got wrong,
7. red-teams the rule with Ultra-generated evasions and hardens it again,
8. ships Sigma + Splunk + Elastic + KQL + tests + an ATT&CK Navigator layer + an evidence-linked report.

The UI streams every step live and shows which Nemotron tier did what, with tokens and cost. Every rule card opens with a verdict, pass/fail counts, ATT&CK links, copy and download buttons for the Sigma YAML and each SIEM query, the tests with a caught/blocked result per event, the refine history, the evidence quotes, and, for anything short of validated, a "What to check before deploying" box naming the exact failing tests and the per-field reason. The evasions the red-team judged beyond the logsource's reach are listed too, so the blind spots are on the page, not hidden.

## How we built it
Python 3.12, FastAPI with Server-Sent Events, a no-framework front end. All inference through Token Factory's OpenAI-compatible endpoint with strict JSON schema outputs and `enable_thinking` toggled per stage. Validation is deterministic: pySigma's SQLite backend (the engine behind Zircolite) turns a rule into SQL that we run against an in-memory table of events. 82 tests run without network using a scripted fake model, including a too-broad rule that must be refined using benign-corpus evidence, and a headless-browser smoke test drives the UI through a live run and a replay with zero console errors. The author and refine prompts are grounded on SigmaHQ rules retrieved per logsource and ATT&CK technique.

## Challenges
- Model ids differ in casing across Nebius pages, so we resolve them at runtime against `/v1/models`.
- The structured-output docs had broken examples, so the client degrades from `json_schema` to `json_object` to prompt-only and repairs invalid JSON with one extra call.
- Making the benign corpus adversarial enough to matter: a naive "-enc" rule must fail because SCCM and Intune legitimately run encoded PowerShell.

## Accomplishments
Across the five recorded reports: 25 rules, 15 validated under the strict definition (parses, compiles, every attack event caught, every benign look-alike blocked, every red-team variant caught, zero baseline hits), 187 red-team variants, zero false positives on the 2,390-event benign baseline, $0.73 and seven minutes for the whole set. A real CISA advisory (AA24-241A) fetched through Tavily came out at 3 of 5 validated with zero baseline hits for $0.13. Every rule converts to four SIEM dialects with the evidence sentence from the report attached.

## What we learned
Tiered routing is a product feature: Ultra for judgement, Super for the loop, Lightning for extraction cuts cost without cutting quality, and showing the split builds trust. And execution-based validation catches what LLM judges miss.

## What's next
Pull-request mode against a SigmaHQ-style repo, CTI-REALM scoring, distillation of Super-written rules into a Lightning fine-tune once Nemotron bases are fine-tunable on Token Factory, and Token Factory Sandboxes for running the validator in isolation.

---

## Demo video

`docs/demo.webm` (75 s, 1280x720, captions burned in, no audio) is a recording of a genuine live run of the agent on the
CISA AA24-241A advisory in the web UI, captured headless by `scripts/record_video.js` and assembled by `scripts/make_video.py`
(re-run both to refresh it). Devpost needs a video link, so upload the file to YouTube (unlisted is fine) and paste the link
into the submission form and into the README. Suggested title and description:

> **RuleSmith: threat intel in, tested detections out (Nebius x NVIDIA hackathon demo)**
>
> An autonomous detection-engineering agent on NVIDIA Nemotron via Nebius Token Factory, with Tavily for the web. This is a
> real run on CISA advisory AA24-241A: Tavily extracts the report, Nemotron 3.5 Lightning pulls behaviours with evidence
> quotes, Nemotron 3 Ultra plans the detections, Nemotron 3 Super writes each Sigma rule and its tests, the validator executes
> them against the tests and a 2,390-event benign baseline, failures go back with the exact event, and Ultra red-teams the
> result. Waiting segments were shortened; the timestamps in the UI are real. Source: github.com/Arekkusul/nebius-nvidia-hackathon

## 3-minute video script (for a narrated re-recording, optional)

**0:00–0:20 · Problem (talking head or title cards)**
"This is a 2,000-word threat report. A detection engineer will spend the afternoon turning it into SIEM rules, and nobody will test them. RuleSmith does it in minutes, and proves every rule before you see it."

**0:20–0:35 · What it is built on (say it out loud, show the health pill and the routing table)**
"Every model call is NVIDIA Nemotron served by Nebius Token Factory: Lightning to extract, Super to write, Ultra to plan and red-team. Tavily fetches the intel."

**0:35–1:25 · Live run (screen capture, speed up waits, say so in the description)**
URL tab → click the CISA AA24-241A quick-fill → Run the agent. Tavily extract → behaviour chips appear (click one: the evidence quote) → Ultra's plan → the progress bar and the rule counter move as rules finish and their cards appear. Pause on one rule going *refining → validated* in the log: open its History tab and show the per-field reason the first draft missed and the change Super made.

**1:25–1:55 · Red-team**
Tests tab: the author's tests, then the red-team variants (reordered flags, SysWOW64 paths, quoting tricks) each marked caught; then the Out-of-scope evasions tab for what the logsource cannot see. On a needs-review rule, show the "What to check before deploying" box: the exact failing test and why.

**1:55–2:25 · The pack**
The verdict banner, then Copy on the KQL pane and paste it into a SIEM query window; Download pack: Sigma, Splunk, Elastic, KQL, tests.jsonl, Navigator layer, report. Open the Navigator layer in attack.mitre.org/navigator. Show the routing table: "this whole run cost about fifteen cents on Token Factory."

**2:25–2:50 · Numbers**
Eval table: five reports, 25 rules, 15 validated under the strict definition, zero false positives on 2,390 benign baseline events, 187 red-team variants, about $0.73 and seven minutes for the whole run.

**2:50–3:00 · Close**
"RuleSmith: threat intel in, tested detections out. Open source, MIT, built on Nemotron and Nebius Token Factory."

Video description must state: "Waiting segments were shortened; the timestamps in the UI are real."
