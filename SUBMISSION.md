# Devpost submission kit

Track: **Best Apps and Agents** · Bonus: **Best Use of Tavily** · Feedback section: see FEEDBACK.md

## Project name
RuleSmith

## Tagline
Threat intel in, tested detections out. An autonomous detection-engineering agent on NVIDIA Nemotron via Nebius Token Factory.

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

The UI streams every step live and shows which Nemotron tier did what, with tokens and cost.

## How we built it
Python 3.12, FastAPI with Server-Sent Events, a no-framework front end. All inference through Token Factory's OpenAI-compatible endpoint with strict JSON schema outputs and `enable_thinking` toggled per stage. Validation is deterministic: pySigma's SQLite backend (the engine behind Zircolite) turns a rule into SQL that we run against an in-memory table of events. 47 tests run without network using a scripted fake model, including a too-broad rule that must be refined using benign-corpus evidence.

## Challenges
- Model ids differ in casing across Nebius pages, so we resolve them at runtime against `/v1/models`.
- The structured-output docs had broken examples, so the client degrades from `json_schema` to `json_object` to prompt-only and repairs invalid JSON with one extra call.
- Making the benign corpus adversarial enough to matter: a naive "-enc" rule must fail because SCCM and Intune legitimately run encoded PowerShell.

## Accomplishments
Rules that fire on the attack, stay silent on 2,390 benign events, survive evasion variants, and convert to four SIEM dialects, with the evidence sentence from the report attached to each one.

## What we learned
Tiered routing is a product feature: Ultra for judgement, Super for the loop, Lightning for extraction cuts cost without cutting quality, and showing the split builds trust. And execution-based validation catches what LLM judges miss.

## What's next
Pull-request mode against a SigmaHQ-style repo, CTI-REALM scoring, distillation of Super-written rules into a Lightning fine-tune once Nemotron bases are fine-tunable on Token Factory, and Token Factory Sandboxes for running the validator in isolation.

---

## 3-minute video script

**0:00–0:20 · Problem (talking head or title cards)**
"This is a 2,000-word threat report. A detection engineer will spend the afternoon turning it into SIEM rules, and nobody will test them. RuleSmith does it in minutes, and proves every rule before you see it."

**0:20–0:35 · What it is built on (say it out loud, show the health pill and the routing table)**
"Every model call is NVIDIA Nemotron served by Nebius Token Factory: Lightning to extract, Super to write, Ultra to plan and red-team. Tavily fetches the intel."

**0:35–1:25 · Live run (screen capture, speed up waits, say so in the description)**
Paste a report URL → Tavily extract → behaviours appear with evidence quotes → Ultra's plan → rules stream in. Pause on one rule going *refining → validated*: show the benign SCCM event it fired on and the fix Super made.

**1:25–1:55 · Red-team**
Open History: Ultra's evasion variants (`-ec`, reordered args, SysWOW64), the rule being hardened, final test table all green.

**1:55–2:25 · The pack**
Download zip: Sigma, Splunk, KQL, tests.jsonl, Navigator layer. Open the Navigator layer in attack.mitre.org/navigator. Show cost: "this whole run cost under a dollar on Token Factory."

**2:25–2:50 · Numbers**
Eval table: five reports, rules validated, zero baseline false positives, red-team variants caught.

**2:50–3:00 · Close**
"RuleSmith: threat intel in, tested detections out. Open source, MIT, built on Nemotron and Nebius Token Factory."

Video description must state: "Waiting segments were shortened; the timestamps in the UI are real."
