/* RuleSmith front-end: no build step, no framework. */
(() => {
  "use strict";

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });

  // Static mode: the page is served from plain files (e.g. a free static
  // Hugging Face Space) with no API behind it. Recorded runs live under
  // replays/ as JSON and zip files; live runs are disabled.
  const STATIC = Boolean(window.RULESMITH_STATIC);
  const staticIndex = new Map(); // id -> {parts, zip} from replays/index.json (static mode only)

  // Fetch a recorded run. In static mode the JSON is split into part files
  // (replays/<id>.part0.json ...) which are concatenated here.
  async function fetchReplay(id) {
    if (!STATIC) return (await fetch(`/api/replays/${id}`)).json();
    const parts = (staticIndex.get(id) || {}).parts || 1;
    const texts = await Promise.all(Array.from({ length: parts }, (_, n) => fetch(`replays/${id}.part${n}.json`).then((r) => r.text())));
    return JSON.parse(texts.join(""));
  }

  const state = {
    mode: "example",
    runId: null,
    es: null,
    replaying: false,
    rules: new Map(),   // candidate_id -> {title, status, lines[]}
    result: null,
    health: null,
  };

  // ------------------------------------------------------------------ boot
  async function boot() {
    bindTabs();
    $("#run-btn").addEventListener("click", startRun);
    $("#replay-btn").addEventListener("click", () => replay($("#replay-select").value));
    await Promise.all([loadHealth(), loadExamples(), loadReplays()]);
    const params = new URLSearchParams(location.search);
    if (params.get("replay")) replay(params.get("replay"));
  }

  async function loadHealth() {
    if (STATIC) {
      const el = $("#health");
      el.textContent = "static demo · replay only";
      el.className = "pill pill-warn";
      el.title = "This hosted copy serves recorded runs. Clone the repo and add NEBIUS_API_KEY to run the agent live.";
      $("#run-btn").disabled = true;
      $$(".tab").forEach((t) => { if (t.dataset.mode !== "example") t.disabled = true; });
      $("#input-error").textContent = "Static demo: pick a recorded run below. Live runs need the server with a Token Factory key (see the GitHub README).";
      $("#input-error").classList.remove("hidden");
      return;
    }
    try {
      const h = await (await fetch("/api/health")).json();
      state.health = h;
      const el = $("#health");
      if (h.llm_configured) {
        const m = h.models || {};
        el.textContent = `Token Factory ✓ ${m.main ? "· " + shortModel(m.main) : ""}`;
        el.className = "pill pill-ok";
        el.title = Object.entries(m).map(([k, v]) => `${k}: ${v}`).join("\n");
      } else {
        el.textContent = "no API key on server · replay only";
        el.className = "pill pill-warn";
      }
      if (h.demo_locked) {
        $$(".tab").forEach((t) => { if (t.dataset.mode !== "example") t.disabled = true; });
        $("#input-error").textContent = "Hosted demo: live runs are limited to the bundled example reports. Clone the repo to analyse your own.";
        $("#input-error").classList.remove("hidden");
      }
      if (!h.tavily_configured) { const q = $('.tab[data-mode="query"]'); q.disabled = true; q.title = "Needs TAVILY_API_KEY"; }
    } catch (e) {
      $("#health").textContent = "server unreachable";
    }
  }

  async function loadExamples() {
    // In static mode the bundled-report picker mirrors the recorded runs.
    const list = await (await fetch(STATIC ? "replays/index.json" : "/api/examples")).json();
    const sel = $("#example-select");
    sel.innerHTML = list.map((e) => `<option value="${esc(e.id)}">${esc(e.title)}</option>`).join("") || `<option value="">(no examples bundled)</option>`;
  }

  async function loadReplays() {
    const list = await (await fetch(STATIC ? "replays/index.json" : "/api/replays")).json();
    if (STATIC) list.forEach((r) => staticIndex.set(r.id, r));
    const sel = $("#replay-select");
    sel.innerHTML = list.map((r) => `<option value="${esc(r.id)}">${esc(r.title)} · ${r.validated}/${r.rules} validated</option>`).join("") || `<option value="">(no recorded runs)</option>`;
    $("#replay-btn").disabled = !list.length;
  }

  function bindTabs() {
    $$("#mode-tabs .tab").forEach((btn) => btn.addEventListener("click", () => {
      state.mode = btn.dataset.mode;
      $$("#mode-tabs .tab").forEach((b) => b.classList.toggle("active", b === btn));
      $$(".mode-panel").forEach((p) => p.classList.toggle("hidden", p.dataset.panel !== state.mode));
    }));
  }

  const shortModel = (m) => m.replace(/^nvidia\//i, "");

  // ------------------------------------------------------------------ run
  async function startRun() {
    const body = { mode: state.mode, max_rules: +$("#opt-rules").value, max_refine_iterations: +$("#opt-iter").value, enable_redteam: $("#opt-redteam").checked };
    if (state.mode === "example") body.value = $("#example-select").value;
    if (state.mode === "url") body.urls = $("#url-input").value.split("\n").map((s) => s.trim()).filter(Boolean);
    if (state.mode === "text") body.value = $("#text-input").value;
    if (state.mode === "query") body.value = $("#query-input").value;
    showError("");
    resetRun(false);
    $("#run-btn").disabled = true;
    try {
      const r = await fetch("/api/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) {
        const err = await r.json().catch(() => ({ detail: r.statusText }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
      }
      state.runId = (await r.json()).run_id;
      connect(state.runId);
    } catch (e) {
      showError(e.message);
      $("#run-btn").disabled = false;
    }
  }

  function connect(runId) {
    if (state.es) state.es.close();
    const es = new EventSource(`/api/runs/${runId}/events`);
    state.es = es;
    es.onmessage = (m) => {
      const evt = JSON.parse(m.data);
      if (evt.type === "end") { es.close(); finish(runId, evt.error); return; }
      handleEvent(evt);
    };
    es.onerror = () => { /* browser auto-reconnects; buffered events are replayed by the server */ };
  }

  async function finish(runId, error) {
    $("#run-btn").disabled = false;
    if (error) { showError(error); setStage("done", "error"); return; }
    const r = await (await fetch(`/api/runs/${runId}`)).json();
    if (r.result) renderResult(r.result, { zip: `/api/runs/${runId}/download`, nav: `/api/runs/${runId}/navigator.json`, md: `/api/runs/${runId}/report.md` });
  }

  function showError(msg) {
    const el = $("#input-error");
    el.textContent = msg;
    el.classList.toggle("hidden", !msg);
  }

  function resetRun(replaying) {
    state.rules = new Map();
    state.result = null;
    state.replaying = replaying;
    $("#replay-badge").classList.toggle("hidden", !replaying);
    $("#log").innerHTML = "";
    $("#behaviours").innerHTML = "";
    $("#plan").innerHTML = "";
    $("#results").classList.add("hidden");
    $("#rules").innerHTML = "";
    $$("#stages li").forEach((li) => (li.className = ""));
  }

  // ------------------------------------------------------------- events
  function setStage(stage, status) {
    const li = $(`#stages li[data-stage="${stage}"]`);
    if (li) li.className = status;
  }

  function logLine(evt) {
    const li = document.createElement("li");
    const cls = evt.status ? ` s-${evt.status}` : evt.type === "error" ? " s-error" : "";
    li.innerHTML = `<span class="t">${fmtTime(evt.ts)}</span><span class="${cls}">${esc(evt.type === "rule" ? `[${evt.stage}] ` : "")}${esc(evt.message)}</span>`;
    const log = $("#log");
    log.appendChild(li);
    log.scrollTop = log.scrollHeight;
  }

  function handleEvent(evt) {
    logLine(evt);
    if (evt.type === "stage") {
      setStage(evt.stage, evt.status === "done" ? "done" : "running");
      if (evt.stage === "extract" && evt.report) renderBehaviours(evt.report);
      if (evt.stage === "plan" && evt.plan) renderPlan(evt.plan);
    } else if (evt.type === "rule") {
      const r = state.rules.get(evt.stage) || { title: evt.title || evt.stage, status: "authoring", lines: [] };
      r.title = evt.title || r.title;
      r.status = evt.status || r.status;
      r.lines.push(evt.message);
      state.rules.set(evt.stage, r);
      renderLiveRules();
    } else if (evt.type === "done") {
      setStage("done", "done");
    } else if (evt.type === "error") {
      setStage("done", "error");
    }
  }

  function renderBehaviours(report) {
    $("#behaviours").innerHTML = (report.behaviors || []).map((b) =>
      `<span class="chip${b.detectable ? "" : " dim"}" title="${esc(b.description)}\n\n“${esc(b.evidence)}”"><b>${esc(b.id)}</b> ${esc(b.attack_technique_id)} · ${esc(b.attack_tactic)} · ${Math.round(b.confidence * 100)}%</span>`
    ).join("") || `<span class="muted">No behaviours.</span>`;
  }

  function renderPlan(plan) {
    $("#plan").innerHTML = (plan.candidates || []).map((c) =>
      `<div class="cand"><b>${esc(c.id)} · ${esc(c.title)}</b><small>${esc(c.logsource.product)}/${esc(c.logsource.category || c.logsource.service)} · ${esc(c.attack_technique_ids.join(", "))} · ${esc(c.priority)} priority · keys on ${esc(c.key_fields.join(", "))}</small></div>`
    ).join("") + ((plan.skipped || []).length ? `<div class="skipped">Skipped: ${esc(plan.skipped.join(" · "))}</div>` : "");
  }

  function renderLiveRules() {
    if (state.result) return; // final render takes over
    $("#results").classList.remove("hidden");
    $("#metrics").innerHTML = "";
    $("#routing").innerHTML = "";
    $("#rules").innerHTML = Array.from(state.rules.entries()).map(([id, r]) => `
      <div class="rule"><div class="rule-head"><div><h4>${esc(r.title)}</h4><div class="meta">${esc(id)} · ${esc(r.lines[r.lines.length - 1])}</div></div><span class="status ${esc(r.status)}">${esc(r.status.replace("_", " "))}</span></div></div>`).join("");
  }

  // ------------------------------------------------------------ results
  function renderResult(result, links) {
    state.result = result;
    $("#results").classList.remove("hidden");
    $("#dl-zip").href = links.zip; $("#dl-nav").href = links.nav; $("#dl-md").href = links.md;
    const s = stats(result);
    const metric = (v, k) => `<div class="metric"><div class="v">${v}</div><div class="k">${k}</div></div>`;
    $("#metrics").innerHTML = [
      metric(`${s.validated}/${s.rules}`, "rules validated"),
      metric(pct(s.positive_recall), "attack events caught"),
      metric(pct(s.negative_precision), "benign look-alikes blocked"),
      metric(s.benign_hits, "baseline false positives"),
      metric(s.iterations, "validate → refine cycles"),
      metric(`$${s.cost_usd.toFixed(4)}`, "est. Token Factory cost"),
      metric(`${s.latency_s}s`, "model time"),
    ].join("");
    const tiers = byTier(result.metrics.calls);
    $("#routing").innerHTML = `<table><thead><tr><th>Tier</th><th>Nemotron model (Nebius Token Factory)</th><th>Used for</th><th>Calls</th><th>Tokens in / out</th><th>Est. cost</th></tr></thead><tbody>${
      ["fast", "main", "reasoning"].filter((t) => tiers[t]).map((t) => `<tr><td>${t}</td><td><code>${esc(result.models[t] || tiers[t].model)}</code></td><td>${{ fast: "extract behaviours (thinking off)", main: "author + refine rules", reasoning: "plan + red-team (thinking on)" }[t]}</td><td>${tiers[t].calls}</td><td>${tiers[t].prompt_tokens.toLocaleString()} / ${tiers[t].completion_tokens.toLocaleString()}</td><td>$${tiers[t].cost_usd.toFixed(4)}</td></tr>`).join("")
    }</tbody></table>`;
    const warn = (result.warnings || []).length ? `<div class="notice">${esc(result.warnings.join(" · "))}</div>` : "";
    $("#rules").innerHTML = warn + result.rules.map(renderRule).join("");
    $$("#rules .rule-head").forEach((h) => h.addEventListener("click", () => h.nextElementSibling.classList.toggle("hidden")));
    $$("#rules .rule-tabs button").forEach((b) => b.addEventListener("click", () => {
      const body = b.closest(".rule-body");
      $$(".rule-tabs button", body).forEach((x) => x.classList.toggle("active", x === b));
      $$(".pane", body).forEach((p) => p.classList.toggle("hidden", p.dataset.pane !== b.dataset.pane));
    }));
  }

  const pct = (v) => (v == null ? "n/a" : `${Math.round(v * 100)}%`);

  function stats(r) {
    const rules = r.rules || [];
    const sum = (f) => rules.reduce((a, x) => a + f(x), 0);
    const pt = sum((x) => x.validation.positives_total), pm = sum((x) => x.validation.positives_matched);
    const nt = sum((x) => x.validation.negatives_total), nm = sum((x) => x.validation.negatives_matched);
    const calls = r.metrics.calls || [];
    return {
      rules: rules.length,
      validated: rules.filter((x) => x.status === "validated").length,
      positive_recall: pt ? pm / pt : null,
      negative_precision: nt ? 1 - nm / nt : null,
      benign_hits: sum((x) => x.validation.benign_hits),
      iterations: sum((x) => x.history.length),
      cost_usd: calls.reduce((a, c) => a + c.cost_usd, 0),
      latency_s: Math.round(calls.reduce((a, c) => a + c.latency_s, 0) * 10) / 10,
    };
  }

  function byTier(calls) {
    const out = {};
    for (const c of calls) {
      const t = out[c.tier] || (out[c.tier] = { model: c.model, calls: 0, prompt_tokens: 0, completion_tokens: 0, cost_usd: 0 });
      t.calls++; t.prompt_tokens += c.prompt_tokens; t.completion_tokens += c.completion_tokens; t.cost_usd += c.cost_usd;
    }
    return out;
  }

  const LABELS = { splunk: "Splunk SPL", elasticsearch: "Elastic (Lucene)", kusto: "KQL (Defender XDR)", sqlite: "SQLite" };

  function renderRule(rule, i) {
    const v = rule.validation;
    const conv = Object.entries(rule.conversions || {});
    const convErr = Object.entries(rule.conversion_errors || {});
    const tests = rule.tests || [];
    const outcome = Object.fromEntries((v.test_outcomes || []).map((o) => [o.event_id, o]));
    const behaviours = (state.result.report.behaviors || []).filter((b) => (state.result.plan.candidates.find((c) => c.id === rule.candidate_id)?.behavior_ids || []).includes(b.id));
    return `
    <div class="rule">
      <div class="rule-head">
        <div><h4>${esc(rule.title)}</h4><div class="meta">${esc(rule.attack_technique_ids.join(", "))} · ${esc(v.summary ? v.summary : summarize(v))} · ${rule.history.length} cycle(s)</div></div>
        <span class="status ${esc(rule.status)}">${esc(rule.status.replace("_", " "))}</span>
      </div>
      <div class="rule-body ${i === 0 ? "" : "hidden"}">
        <div class="rule-tabs">
          <button class="tab active" data-pane="sigma">Sigma</button>
          ${conv.map(([k]) => `<button class="tab" data-pane="${k}">${LABELS[k] || k}</button>`).join("")}
          <button class="tab" data-pane="tests">Tests (${tests.length})</button>
          <button class="tab" data-pane="history">History</button>
          <button class="tab" data-pane="evidence">Evidence</button>
        </div>
        <div class="pane" data-pane="sigma"><pre>${esc(rule.sigma_yaml)}</pre>${rule.author_notes ? `<p class="muted">${esc(rule.author_notes)}</p>` : ""}</div>
        ${conv.map(([k, q]) => `<div class="pane hidden" data-pane="${k}"><pre>${esc(q)}</pre></div>`).join("")}
        <div class="pane hidden tests" data-pane="tests">
          ${convErr.length ? `<p class="muted">Conversion skipped: ${esc(convErr.map(([k, e]) => `${k}: ${e}`).join(" · "))}</p>` : ""}
          <table><thead><tr><th>Id</th><th>Label</th><th>Expectation</th><th>Result</th><th>Event</th></tr></thead><tbody>
          ${tests.map((t) => { const o = outcome[t.id]; const ok = o ? o.passed : null; return `<tr><td class="mono">${esc(t.id)}</td><td>${esc(t.label)}${t.id.startsWith("R") ? " (red-team)" : ""}</td><td>${esc(t.description)}</td><td class="${ok === null ? "" : ok ? "pass" : "fail"}">${ok === null ? "–" : ok ? "pass" : "FAIL"}${o ? ` (${o.matched ? "matched" : "no match"})` : ""}</td><td><pre>${esc(JSON.stringify(t.event, null, 1))}</pre></td></tr>`; }).join("")}
          </tbody></table>
          ${v.benign_examples && v.benign_examples.length ? `<h3>Benign baseline events still matching</h3><pre>${esc(JSON.stringify(v.benign_examples, null, 1))}</pre>` : `<p class="muted">Benign baseline: ${v.benign_hits} hits across ${v.benign_total} events.</p>`}
        </div>
        <div class="pane hidden history" data-pane="history">
          <ul>${rule.history.map((h) => `<li class="${h.passed ? "ok" : "ko"}">${esc(h.phase)} #${h.iteration}: ${esc(h.summary)}${h.change_summary ? ` — ${esc(h.change_summary)}` : ""}</li>`).join("")}</ul>
          ${rule.redteam_analysis ? `<h3>Red-team analysis (Nemotron Ultra)</h3><p>${esc(rule.redteam_analysis)}</p>` : ""}
          ${(rule.retired_tests || []).length ? `<h3>Red-team variants retired as unreachable</h3><ul>${rule.retired_tests.map((t) => `<li class="muted"><span class="mono">${esc(t.id)}</span> ${esc(t.description)}</li>`).join("")}</ul>` : ""}
          ${(v.issues || []).length ? `<h3>Open issues</h3><ul>${v.issues.map((x) => `<li class="${x.severity === "error" ? "ko" : "muted"}">${esc(x.severity)} · ${esc(x.code)} · ${esc(x.message)}</li>`).join("")}</ul>` : ""}
        </div>
        <div class="pane hidden evidence" data-pane="evidence">
          ${behaviours.length ? behaviours.map((b) => `<div><b>${esc(b.id)} · ${esc(b.attack_technique_id)}</b> ${esc(b.description)}<blockquote>“${esc(b.evidence)}”</blockquote></div>`).join("") : `<p class="muted">No behaviour mapping recorded.</p>`}
        </div>
      </div>
    </div>`;
  }

  function summarize(v) {
    if (!v.parse_ok) return "parse failed";
    return `positives ${v.positives_matched}/${v.positives_total}, negatives blocked ${v.negatives_total - v.negatives_matched}/${v.negatives_total}, benign hits ${v.benign_hits}/${v.benign_total}`;
  }

  // ------------------------------------------------------------- replay
  async function replay(id) {
    if (!id) return;
    resetRun(true);
    showError("");
    const result = await fetchReplay(id);
    // Synthesise the event stream from the saved run so the UI animates like a live run.
    const t0 = Date.parse(result.created_at) / 1000 || Date.now() / 1000;
    const events = [];
    let ts = t0;
    const push = (e) => events.push({ ts: (ts += 0.6), ...e });
    push({ type: "stage", stage: "ingest", status: "running", message: "Fetching the report" });
    push({ type: "stage", stage: "ingest", status: "done", message: `Got ${result.source.chars.toLocaleString()} characters${result.source.tavily_used ? " via Tavily" : ""}` });
    push({ type: "stage", stage: "extract", status: "running", message: `Extracting behaviours with ${result.models.fast || "fast tier"}` });
    push({ type: "stage", stage: "extract", status: "done", message: `${result.report.behaviors.length} behaviours, ${result.report.iocs.length} IOCs`, report: result.report });
    push({ type: "stage", stage: "plan", status: "running", message: `Planning detections with ${result.models.reasoning || "reasoning tier"} (thinking on)` });
    push({ type: "stage", stage: "plan", status: "done", message: `${result.plan.candidates.length} rule candidates, ${result.plan.skipped.length} behaviours skipped`, plan: result.plan });
    push({ type: "stage", stage: "rules", status: "running", message: `Authoring, testing and hardening ${result.rules.length} rules` });
    for (const r of result.rules) {
      push({ type: "rule", stage: r.candidate_id, status: "authoring", title: r.title, message: `Authoring '${r.title}'` });
      for (const h of r.history) push({ type: "rule", stage: r.candidate_id, status: h.passed ? "validated" : "refining", title: r.title, message: `${h.phase} #${h.iteration}: ${h.summary}${h.change_summary ? " — " + h.change_summary : ""}` });
      push({ type: "rule", stage: r.candidate_id, status: r.status, title: r.title, message: `${r.status}: ${summarize(r.validation)}` });
    }
    push({ type: "stage", stage: "rules", status: "done", message: `${result.rules.filter((r) => r.status === "validated").length}/${result.rules.length} rules validated` });
    push({ type: "done", stage: "done", message: `Recorded run ${result.run_id} (${result.created_at.slice(0, 10)})` });
    let i = 0;
    const tick = () => {
      if (i >= events.length) {
        const hasZip = !STATIC || Boolean((staticIndex.get(id) || {}).zip);
        renderResult(result, { zip: STATIC ? `replays/${id}.zip` : `/api/replays/${id}/download`, nav: "#", md: "#" });
        $("#dl-nav").classList.add("hidden"); $("#dl-md").classList.add("hidden");
        // The static demo may ship without packs; point people at the CLI instead.
        $("#dl-zip").classList.toggle("hidden", !hasZip);
        if (!hasZip) $("#input-error").textContent = `Static demo: build the pack locally with "rulesmith run --example ${id} --out pack" (see the GitHub README).`;
        return;
      }
      handleEvent(events[i++]);
      setTimeout(tick, i < 8 ? 450 : 250);
    };
    tick();
  }

  boot();
})();
