---
title: RuleSmith Live
emoji: 🛡️
colorFrom: green
colorTo: gray
sdk: gradio
sdk_version: 5.49.1
app_file: app.py
pinned: false
license: mit
short_description: Threat intel in, tested Sigma rules out. Live on Nemotron via Nebius.
---

# RuleSmith (live demo)

Note: Hugging Face hosts Gradio and Docker Spaces only for PRO accounts; the static Space is the free option.

Autonomous detection-engineering agent on NVIDIA Nemotron served by Nebius Token Factory, with Tavily for the web layer.
Paste a threat-report URL, text or a search query; get Sigma rules that were executed against their own tests and a
2,390-event benign baseline, red-teamed, and converted to Splunk, Elastic and KQL.

Source and documentation: https://github.com/Arekkusul/nebius-nvidia-hackathon

Space secrets: `NEBIUS_API_KEY` (required), `TAVILY_API_KEY` (optional), `RULESMITH_DEMO_BUDGET_USD` (caps live spend;
recorded replays always work).
