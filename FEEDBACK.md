# Feedback on Nebius Token Factory and NVIDIA Nemotron

Written while building RuleSmith for the Nebius x NVIDIA Global AI Hackathon (October 2026). Specific, so it is actionable. Items marked *(live)* will be refined after the final live runs.

## Nebius Token Factory

**What we used it for.** All inference: five pipeline stages across three Nemotron tiers through the OpenAI-compatible `chat/completions` endpoint with `response_format=json_schema`, `chat_template_kwargs.enable_thinking`, and `GET /v1/models` for runtime model resolution.

**What worked well.**
- Zero to hello world is genuinely fast: the OpenAI SDK with a changed `base_url` just works, and the `llms.txt` index of the docs is excellent for agents and humans alike.
- Having Lightning, Super and Ultra on one endpoint with one key made tiered routing trivial. Being able to say "Ultra for planning, Lightning for extraction, Super for the loop" and show the cost split per tier is a real product feature, not just a cost trick.
- The FAQ on the hackathon page and the hackathon Discord answered the "does my whole app need to run on Nebius" question clearly.

**What needs work.**
1. **Model ids are inconsistent across Nebius's own pages.** The Nemotron landing page shows `nvidia/Nemotron-3_5-Lightning` and `nvidia/Nemotron-3.5-Super-VL`, the cookbook shows `nvidia/nvidia-nemotron-3-nano-30b-a3b`, third-party integrations show `nvidia/nemotron-3-super-120b-a12b`. Mixed casing and separators (`3_5` vs `3.5`) mean copy-pasting from docs fails. We had to resolve ids case-insensitively against `/v1/models` at startup. One canonical id per model, printed everywhere, would remove a whole class of first-hour errors.
2. **The "Structured output & JSON" doc page has broken examples.** The Python `response_format` dict is missing commas, the cURL sample uses `"response format"` with a space, and the prose shows a `name/schema/strict` wrapper while the code passes a bare schema. We shipped a fallback chain (`json_schema` → `json_object` → prompt-only) because we could not tell from the docs which shape the server wants. A single correct example per SDK, plus a per-model "JSON mode" capability flag in `/v1/models?verbose=true`, would be ideal.
3. **No published per-model support matrix for tool calling / JSON mode / reasoning toggle.** The docs say "look for the tag on the model card". That should be in the API.
4. **Rate-limit docs give no numbers** for the Startup tier. The adaptive window mechanism is well explained, but a table of starting RPM/TPM per tier would let builders size parallelism. We defaulted to 3 parallel rule authors blind.
5. **Fine-tuning does not list any Nemotron base model.** Distilling our Super-written rules into a Lightning/Nano fine-tune is the obvious next step for cost, and it is not possible on the platform today.
6. **Sandboxes are gated behind an access request.** For a hackathon whose Coding track says "write, run and test code in Token Factory", open self-serve access during the event would have let us run pySigma validation inside Token Factory instead of in-process.

**Would we build with it again?** Yes. The economics of Lightning for extraction (effectively free at $0.06/M input) and Ultra only where judgement matters are hard to beat, and the OpenAI compatibility meant zero vendor-specific code outside `llm.py`.

## NVIDIA Nemotron

**What we used.** Nemotron 3.5 Lightning (extraction), Nemotron 3 Super (authoring and refinement), Nemotron 3 Ultra (planning and red-team).

**What worked well.**
- Reasoning on/off via `chat_template_kwargs.enable_thinking` is exactly the right control for an agent that mixes judgement stages with extraction stages. The model cards document it clearly, including the client-side budget pattern.
- Lightning's 1M context means we never chunk a report.
- The model cards give concrete sampling recommendations (temp 1.0/top_p 0.95; 0.6 for tool calling on Nano). We used them.

**What needs work.**
1. **Reasoning traces leaking into `content`.** Depending on the serving stack, a `<think>` block can arrive inline, be split into `reasoning_content`, or be truncated when `max_tokens` is hit. We strip `<think>` defensively. A guarantee that `content` never contains the trace when `enable_thinking` is on would simplify every structured-output client.
2. **The tool-call format is documented only by parser name** (`qwen3_coder`), not by the token-level format. Builders who cannot use vLLM's parser have to reverse-engineer it.
3. **Sigma/YAML specifics** *(live)*: observations on how often each tier produced invalid YAML, hallucinated fields, or wrong technique ids are recorded in `eval/results.md` after the final runs. The validator exists precisely because this is where general-purpose models slip; a Nemotron fine-tune on SigmaHQ-style rules would be a natural "Nemotron for security" release.

**Would we build with it again?** Yes. Being able to show judges three open-weight models from one family doing three different jobs, with the same prompt conventions, is a strong story for open infrastructure.

## Tavily

`extract` with `extract_depth="advanced"` and markdown output was the difference between usable report text and HTML soup; `search` with `time_range` made "find me the latest reporting on X" a one-liner. Documentation inconsistency spotted: the Python reference documents `map` while an example calls `mapping`, and `crawl`/`map` take `instructions` in the reference but `query` in the quickstart.
