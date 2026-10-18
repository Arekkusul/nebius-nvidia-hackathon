/* RuleSmith front-end: no build step, no framework.

   Three cards: choose a report, watch the agent work, read the detection
   pack. The same file runs against the FastAPI server (live runs over SSE,
   replays from /api/replays) and as a static page on a free Hugging Face
   Space (replays from replays/*.partN.json, no live runs). */
(() => {
  "use strict";

  // ------------------------------------------------------------ helpers
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
  const pct = (v) => (v == null ? "n/a" : `${Math.round(v * 100)}%`);
  const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 80) || "rule";
  const shortModel = (m) => String(m).replace(/^nvidia\//i, "");
  // ATT&CK technique id -> page on attack.mitre.org (T1059.005 -> /techniques/T1059/005/).
  const attackUrl = (tid) => `https://attack.mitre.org/techniques/${String(tid).toUpperCase().replace(".", "/")}/`;

  // Static mode: the page is served from plain files (a free static Hugging
  // Face Space) with no API behind it. Recorded runs live under replays/ as
  // split JSON parts; live runs are not available.
  const STATIC = Boolean(window.RULESMITH_STATIC);

  const state = {
    mode: "example",
    health: null,
    examples: [],          // [{id, title}] bundled reports
    replays: new Map(),    // id -> {id, title, rules, validated, parts?, zip?}
    runId: null,           // live run id on the server
    replayId: null,        // recorded run being played back
    es: null,              // EventSource for the live run
    replaying: false,
    report: null,          // ThreatReport from the extract stage (live or replay)
    plan: null,            // DetectionPlan from the plan stage
    rules: new Map(),      // candidate id -> {title, status, lines[], final?}
    result: null,          // full RunResult once the run has finished
    t0: 0,                 // run start, for the elapsed timer
    timer: null,
    skip: false,           // replay: drain the remaining events at once
    filter: "all",
    code: new Map(),       // code pane id -> {text, filename} for copy/download buttons
    blobUrl: null,         // object URL for the client-side Navigator layer (static mode)
  };

  // ------------------------------------------------------------ boot
  async function boot() {
    bindInputs();
    await Promise.all([loadHealth(), loadExamples(), loadReplays()]);
    fillExampleSelect();
    updateButtons();
    const params = new URLSearchParams(location.search);
    const wanted = params.get("replay");
    if (wanted && state.replays.has(wanted)) {
      $("#example-select").value = wanted;
      replay(wanted, { instant: params.get("instant") === "1", openRule: params.get("rule") });
    } else if (replayOnly() && params.get("autoplay") !== "0" && state.replays.size) {
      // Nothing to type and nothing to run: show visitors a real result straight away.
      replay($("#example-select").value || state.replays.keys().next().value, {});
    }
  }

  // The page cannot start a live run: static demo, or a server without a key.
  const replayOnly = () => STATIC || !(state.health && state.health.llm_configured);

  async function loadHealth() {
    const el = $("#health");
    if (STATIC) {
      el.textContent = "hosted demo · recorded runs";
      el.className = "pill pill-warn";
      el.title = "This static copy serves recorded runs. Clone the repository and add a Token Factory key to run the agent live.";
      $("#api-link").classList.add("hidden");
      return;
    }
    try {
      const h = await (await fetch("/api/health")).json();
      state.health = h;
      if (h.llm_configured) {
        const m = h.models || {};
        el.textContent = `Token Factory ✓${m.main ? " · " + shortModel(m.main) : ""}`;
        el.className = "pill pill-ok";
        el.title = Object.entries(m).map(([k, v]) => `${k}: ${v}`).join("\n") || "Nemotron models resolved";
      } else {
        el.textContent = "no API key · recorded runs only";
        el.className = "pill pill-warn";
        el.title = "Set NEBIUS_API_KEY on the server to run the agent live.";
      }
      if (h.budget) {
        // Public demo with a spend cap: say what is left so a refused run is not a surprise.
        el.textContent += ` · $${h.budget.remaining_usd.toFixed(2)} budget left`;
        if (h.budget.remaining_usd < 0.3) { el.className = "pill pill-warn"; el.textContent += " (replays only)"; }
      }
      if (!h.tavily_configured) { const q = $('.tab[data-mode="query"]'); q.disabled = true; q.title = "Search needs TAVILY_API_KEY on the server"; }
    } catch (e) {
      el.textContent = "server unreachable";
      el.className = "pill pill-bad";
    }
  }

  async function loadExamples() {
    if (STATIC) return; // the recorded runs double as the example list
    try { state.examples = await (await fetch("/api/examples")).json(); } catch (e) { state.examples = []; }
  }

  async function loadReplays() {
    try {
      const list = await (await fetch(STATIC ? "replays/index.json" : "/api/replays")).json();
      list.forEach((r) => state.replays.set(r.id, r));
    } catch (e) { /* no recorded runs available */ }
  }

  // One picker for everything: bundled reports first (run live or watch the
  // recording), then recorded runs of real advisories that have no bundled
  // report text (watch only).
  function fillExampleSelect() {
    const sel = $("#example-select");
    const exampleIds = new Set(state.examples.map((e) => e.id));
    const opt = (id, title, note) => `<option value="${esc(id)}">${esc(title)}${note ? ` (${note})` : ""}</option>`;
    const bundled = state.examples.map((e) => {
      const r = state.replays.get(e.id);
      return opt(e.id, e.title, r ? `${r.validated}/${r.rules} validated` : "");
    });
    const recordedOnly = Array.from(state.replays.values()).filter((r) => !exampleIds.has(r.id)).map((r) => opt(r.id, r.title, `${r.validated}/${r.rules} validated`));
    let html = "";
    if (STATIC) html = recordedOnly.join("");
    else if (bundled.length && recordedOnly.length) html = `<optgroup label="Bundled reports">${bundled.join("")}</optgroup><optgroup label="Recorded runs of real reports">${recordedOnly.join("")}</optgroup>`;
    else html = bundled.join("") + recordedOnly.join("");
    sel.innerHTML = html || `<option value="">(no reports available)</option>`;
  }

  // ------------------------------------------------------------ inputs
  function bindInputs() {
    $$("#mode-tabs .tab").forEach((btn) => btn.addEventListener("click", () => {
      state.mode = btn.dataset.mode;
      $$("#mode-tabs .tab").forEach((b) => { b.classList.toggle("active", b === btn); b.setAttribute("aria-selected", String(b === btn)); });
      $$(".mode-panel").forEach((p) => p.classList.toggle("hidden", p.dataset.panel !== state.mode));
      updateButtons();
    }));
    $("#example-select").addEventListener("change", updateButtons);
    $("#run-btn").addEventListener("click", startRun);
    $("#replay-btn").addEventListener("click", () => replay($("#example-select").value, {}));
    $("#skip-btn").addEventListener("click", () => { state.skip = true; });
    $("#theme-btn").addEventListener("click", toggleTheme);
    $("#copy-link").addEventListener("click", copyLink);
    $("#expand-all").addEventListener("click", () => $$("#rules .rule-body").forEach((b) => setOpen(b, true)));
    $("#collapse-all").addEventListener("click", () => $$("#rules .rule-body").forEach((b) => setOpen(b, false)));
    $$("#rules-toolbar .filters .chip-btn").forEach((b) => b.addEventListener("click", () => {
      state.filter = b.dataset.filter;
      $$("#rules-toolbar .filters .chip-btn").forEach((x) => x.classList.toggle("active", x === b));
      applyFilter();
    }));
    $$("[data-fill-url]").forEach((b) => b.addEventListener("click", () => { $("#url-input").value = b.dataset.fillUrl; $("#url-input").focus(); }));
    $("#text-input").addEventListener("input", () => { $("#text-count").textContent = $("#text-input").value.length.toLocaleString(); });
    ["#opt-rules", "#opt-iter", "#opt-redteam"].forEach((id) => $(id).addEventListener("change", updateSettingsSummary));
    updateSettingsSummary();
    document.addEventListener("keydown", (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        const run = $("#run-btn"), rep = $("#replay-btn");
        if (!run.disabled && !run.classList.contains("hidden")) startRun();
        else if (!rep.disabled && !rep.classList.contains("hidden")) replay($("#example-select").value, {});
      }
    });
    // Event delegation for everything rendered later: rule headers, tabs, copy/download, behaviour chips.
    document.addEventListener("click", onDelegatedClick);
  }

  function updateSettingsSummary() {
    $("#settings-summary").textContent = `${$("#opt-rules").value} rules · ${$("#opt-iter").value} refine rounds · red-team ${$("#opt-redteam").checked ? "on" : "off"}`;
  }

  // Decide what the two action buttons do for the current mode and selection.
  function updateButtons() {
    const run = $("#run-btn"), rep = $("#replay-btn"), hint = $("#replay-hint");
    const selected = $("#example-select").value;
    const hasReplay = state.mode === "example" && state.replays.has(selected);
    const bundled = state.examples.some((e) => e.id === selected);
    const locked = state.health && state.health.demo_locked && state.mode !== "example";
    rep.classList.toggle("hidden", !hasReplay);
    run.classList.toggle("hidden", replayOnly());
    run.disabled = Boolean(locked) || (state.mode === "example" && !bundled);
    rep.classList.toggle("primary", replayOnly() || run.disabled);
    hint.textContent = "";
    if (state.mode === "example" && !bundled && hasReplay && !replayOnly()) hint.textContent = "This report was analysed from its URL, so it can only be watched here; paste the URL in the URL tab to re-run it.";
    showNotice(STATIC ? "Hosted demo: it plays recorded runs of the agent. To analyse your own reports, clone the repository and add a Token Factory key (see the README)."
      : state.health && !state.health.llm_configured ? "This server has no NEBIUS_API_KEY, so only recorded runs can be played. Add the key and restart to run the agent live."
      : locked ? "Hosted demo: live runs are limited to the bundled example reports. Clone the repository to analyse your own." : "");
  }

  function showNotice(msg) { const el = $("#notice"); el.textContent = msg; el.classList.toggle("hidden", !msg); }
  function showError(msg) { const el = $("#input-error"); el.textContent = msg; el.classList.toggle("hidden", !msg); }

  function toggleTheme() {
    const root = document.documentElement;
    const effective = root.dataset.theme || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    root.dataset.theme = effective === "dark" ? "light" : "dark";
    try { localStorage.setItem("rulesmith-theme", root.dataset.theme); } catch (e) { /* private mode */ }
  }

  let toastTimer = null;
  function toast(msg) {
    const el = $("#toast");
    el.textContent = msg;
    el.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add("hidden"), 1600);
  }

  async function copyText(text, what) {
    try { await navigator.clipboard.writeText(text); toast(`${what} copied`); }
    catch (e) { toast("Copy failed: select the text and copy it by hand"); }
  }

  function copyLink() {
    if (!state.replayId) return;
    copyText(`${location.origin}${location.pathname}?replay=${encodeURIComponent(state.replayId)}`, "Link");
  }

  function downloadText(filename, text, type = "text/plain") {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = Object.assign(document.createElement("a"), { href: url, download: filename });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ------------------------------------------------------------ live run
  async function startRun() {
    const body = { mode: state.mode, max_rules: +$("#opt-rules").value, max_refine_iterations: +$("#opt-iter").value, enable_redteam: $("#opt-redteam").checked };
    if (state.mode === "example") body.value = $("#example-select").value;
    if (state.mode === "url") body.urls = $("#url-input").value.split("\n").map((s) => s.trim()).filter(Boolean);
    if (state.mode === "text") body.value = $("#text-input").value;
    if (state.mode === "query") body.value = $("#query-input").value;
    if (state.mode === "url" && !body.urls.length) return showError("Enter at least one URL.");
    if (state.mode !== "url" && state.mode !== "example" && !String(body.value || "").trim()) return showError("Enter the report text or a search query first.");
    showError("");
    resetRun(false);
    const btn = $("#run-btn");
    btn.disabled = true; btn.classList.add("busy"); btn.textContent = "Running…";
    try {
      const r = await fetch("/api/runs", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
      if (!r.ok) {
        const err = await r.json().catch(() => ({ detail: r.statusText }));
        throw new Error(typeof err.detail === "string" ? err.detail : JSON.stringify(err.detail));
      }
      state.runId = (await r.json()).run_id;
      startTimer();
      connect(state.runId);
    } catch (e) {
      showError(e.message);
      runButtonIdle();
      stopTimer();
    }
  }

  function runButtonIdle() {
    const btn = $("#run-btn");
    btn.classList.remove("busy"); btn.textContent = "Run the agent";
    updateButtons();
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
    es.onerror = () => { /* the browser reconnects; the server replays buffered events */ };
  }

  async function finish(runId, error) {
    runButtonIdle();
    stopTimer();
    if (error) { showError(error); setStage("done", "error"); setProgress(100, true); return; }
    const r = await (await fetch(`/api/runs/${runId}`)).json();
    if (r.result) renderResult(r.result, { zip: `/api/runs/${runId}/download`, nav: `/api/runs/${runId}/navigator.json`, md: `/api/runs/${runId}/report.md` });
  }

  function resetRun(replaying) {
    state.rules = new Map();
    state.result = null;
    state.report = null;
    state.plan = null;
    state.replaying = replaying;
    state.skip = false;
    if (!replaying) state.replayId = null;
    state.code = new Map();
    $("#replay-badge").classList.toggle("hidden", !replaying);
    $("#skip-btn").classList.toggle("hidden", !replaying);
    $("#log").innerHTML = "";
    $("#behaviours").innerHTML = "";
    $("#behaviour-count").textContent = "";
    $("#plan").innerHTML = "";
    $("#results").classList.add("hidden");
    $("#rules").innerHTML = "";
    $("#verdict").innerHTML = "";
    $("#metrics").innerHTML = "";
    $("#routing").innerHTML = "";
    $("#rules-count").textContent = "";
    $$("#stages li").forEach((li) => (li.className = ""));
    setProgress(0, false);
  }

  // ------------------------------------------------------------ progress
  function startTimer() {
    state.t0 = Date.now();
    const el = $("#elapsed");
    el.classList.remove("hidden");
    const tick = () => { const s = Math.round((Date.now() - state.t0) / 1000); el.textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`; };
    tick();
    clearInterval(state.timer);
    state.timer = setInterval(tick, 1000);
  }
  function stopTimer() { clearInterval(state.timer); state.timer = null; }

  function setProgress(p, failed) {
    const fill = $("#progress-fill");
    fill.style.width = `${Math.max(0, Math.min(100, p))}%`;
    fill.classList.toggle("error", Boolean(failed));
  }

  function setStage(stage, status) {
    const li = $(`#stages li[data-stage="${stage}"]`);
    if (li) li.className = status;
  }

  // Progress bar position from the stage pills and the per-rule completion count.
  function updateProgress() {
    const done = (s) => $(`#stages li[data-stage="${s}"]`).classList.contains("done");
    const total = state.plan ? state.plan.candidates.length : state.rules.size;
    const finished = Array.from(state.rules.values()).filter((r) => r.final).length;
    let p = 3;
    if (done("ingest")) p = 15;
    if (done("extract")) p = 30;
    if (done("plan")) p = 45;
    if (done("plan") && total) p = 45 + 50 * (finished / total);
    if (done("rules")) p = 95;
    if (done("done")) p = 100;
    setProgress(p, false);
    $("#rules-count").textContent = total ? `${finished}/${total}` : "";
  }

  function logLine(evt) {
    const li = document.createElement("li");
    const cls = evt.status ? ` s-${evt.status}` : evt.type === "error" ? " s-error" : "";
    const tag = evt.type === "rule" ? `<span class="tag-rule">[${esc(evt.stage)}]</span>` : "";
    li.innerHTML = `<span class="t">${fmtTime(evt.ts)}</span>${tag}<span class="${cls}">${esc(evt.message)}</span>`;
    const log = $("#log");
    log.appendChild(li);
    if ($("#log-follow").checked) log.scrollTop = log.scrollHeight;
  }

  function handleEvent(evt) {
    logLine(evt);
    if (evt.type === "stage") {
      setStage(evt.stage, evt.status === "done" ? "done" : "running");
      if (evt.stage === "extract" && evt.report) { state.report = evt.report; renderBehaviours(evt.report); }
      if (evt.stage === "plan" && evt.plan) { state.plan = evt.plan; renderPlan(evt.plan); }
      if (evt.stage === "rules" && evt.status === "running") setStage("rules", "running");
    } else if (evt.type === "rule") {
      const r = state.rules.get(evt.stage) || { title: evt.title || evt.stage, status: "authoring", lines: [], final: null };
      r.title = evt.title || r.title;
      r.status = evt.status || r.status;
      r.lines.push(evt.message);
      if (evt.rule) r.final = evt.rule; // the finished rule arrives on its last event
      state.rules.set(evt.stage, r);
      renderLiveRules();
    } else if (evt.type === "done") {
      setStage("done", "done");
    } else if (evt.type === "error") {
      setStage("done", "error");
    }
    updateProgress();
  }

  function renderBehaviours(report) {
    const list = report.behaviors || [];
    $("#behaviour-count").textContent = list.length ? `(${list.length})` : "";
    $("#behaviours").innerHTML = list.map((b) =>
      `<button type="button" class="chip${b.detectable ? "" : " dim"}" data-behaviour="${esc(b.id)}" title="${b.detectable ? "Click for the evidence" : "Judged not detectable from endpoint telemetry"}"><b>${esc(b.id)}</b> ${esc(b.attack_technique_id)} · ${esc(b.attack_tactic)} · ${Math.round(b.confidence * 100)}%</button>`
    ).join("") || `<span class="muted">No behaviours.</span>`;
  }

  function toggleBehaviour(id) {
    const existing = $("#behaviours .evidence-pop");
    const wasOpen = existing && existing.dataset.for === id;
    if (existing) existing.remove();
    $$("#behaviours .chip").forEach((c) => c.classList.toggle("open", false));
    if (wasOpen) return;
    const b = (state.report && state.report.behaviors || []).find((x) => x.id === id);
    if (!b) return;
    const pop = document.createElement("div");
    pop.className = "evidence-pop";
    pop.dataset.for = id;
    pop.innerHTML = `<b>${esc(b.id)} · <a href="${attackUrl(b.attack_technique_id)}" target="_blank" rel="noopener">${esc(b.attack_technique_id)}</a></b> ${esc(b.description)}<blockquote>“${esc(b.evidence)}”</blockquote>`;
    const chip = $(`#behaviours .chip[data-behaviour="${CSS.escape(id)}"]`);
    chip.classList.add("open");
    $("#behaviours").appendChild(pop);
  }

  function renderPlan(plan) {
    const cands = (plan.candidates || []).map((c) =>
      `<div class="cand"><b>${esc(c.id)} · ${esc(c.title)}</b><small>${esc(c.logsource.product)}/${esc(c.logsource.category || c.logsource.service)} · ${esc(c.attack_technique_ids.join(", "))} · ${esc(c.priority)} priority · keys on ${esc(c.key_fields.join(", "))}</small></div>`
    ).join("");
    const skipped = (plan.skipped || []).length ? `<details class="skipped"><summary>${plan.skipped.length} behaviour(s) deliberately not turned into rules</summary><ul>${plan.skipped.map((s) => `<li>${esc(s)}</li>`).join("")}</ul></details>` : "";
    $("#plan").innerHTML = cands + skipped;
  }

  // While the run is in flight, every rule gets a card: finished rules render
  // in full straight away, the others show their latest step.
  function renderLiveRules() {
    if (state.result) return; // the final render takes over
    $("#results").classList.remove("hidden");
    $("#rules").innerHTML = Array.from(state.rules.entries()).map(([id, r], i) => r.final ? renderRule(r.final, i, false) : `
      <div class="rule working" data-cid="${esc(id)}" data-status="working">
        <div class="rule-head" style="cursor:default"><div><h4>${esc(r.title)}</h4><div class="meta"><span class="tagchip">${esc(id)}</span><span>${esc(r.lines[r.lines.length - 1])}</span></div></div>
        <span class="status ${esc(r.status)}">${esc(r.status.replace("_", " "))}</span></div>
      </div>`).join("");
    applyFilter();
  }

  // ------------------------------------------------------------ results
  function renderResult(result, links) {
    state.result = result;
    $("#results").classList.remove("hidden");
    const s = stats(result);

    // Downloads: zip/report need the server; the Navigator layer can be built here.
    const zip = $("#dl-zip"), nav = $("#dl-nav"), md = $("#dl-md");
    zip.classList.toggle("hidden", !links.zip); if (links.zip) zip.href = links.zip;
    md.classList.toggle("hidden", !links.md); if (links.md) md.href = links.md;
    if (links.nav) { nav.href = links.nav; nav.removeAttribute("download"); nav.target = "_blank"; }
    else { if (state.blobUrl) URL.revokeObjectURL(state.blobUrl); state.blobUrl = URL.createObjectURL(new Blob([JSON.stringify(navigatorLayer(result), null, 2)], { type: "application/json" })); nav.href = state.blobUrl; nav.setAttribute("download", "navigator_layer.json"); nav.removeAttribute("target"); }
    $("#copy-link").classList.toggle("hidden", !state.replayId);

    // Verdict banner: the one sentence an analyst needs before the details.
    const cls = s.validated === s.rules ? "ok" : s.validated ? "warn" : "bad";
    const review = s.rules - s.validated;
    const headline = s.validated === s.rules ? "Every rule is ready to deploy." : s.validated ? `${s.validated} rule${s.validated > 1 ? "s" : ""} ready to deploy, ${review} need${review > 1 ? "" : "s"} a human look.` : "No rule reached the validated bar yet.";
    const detail = `Validated means it parses, compiles, catches every attack event, stays silent on every benign look-alike and survived the red-team. ${review ? "A needs-review rule parses and compiles and ships with the exact tests it misses and why, so the fix is usually small." : ""}${s.benign_hits === 0 ? " Zero hits on the benign baseline." : ` ${s.benign_hits} hit(s) on the benign baseline.`}`;
    $("#verdict").innerHTML = `<div class="big ${cls}">${s.validated}/${s.rules}</div><div class="text"><b>${esc(headline)}</b>${esc(detail)}</div>`;

    const metric = (v, k, title) => `<div class="metric" title="${esc(title || "")}"><div class="v">${v}</div><div class="k">${k}</div></div>`;
    $("#metrics").innerHTML = [
      metric(pct(s.positive_recall), "attack events caught", "Positive test events (including red-team variants) the rules matched"),
      metric(pct(s.negative_precision), "benign look-alikes blocked", "Negative test events the rules correctly ignored"),
      metric(s.benign_hits, "baseline false positives", `Hits across the ${s.benign_total.toLocaleString()} benign baseline events checked`),
      metric(s.redteam, "red-team variants", "Evasion attempts the Ultra red-team added as tests"),
      metric(s.iterations, "validate → refine cycles", "Every rule is executed after each change; this counts the cycles"),
      metric(`$${s.cost_usd.toFixed(3)}`, "est. Token Factory cost", "Estimated from tokens and list prices"),
      metric(`${s.latency_s}s`, "model time", "Sum of model call latencies (rules are authored in parallel)"),
    ].join("");

    const tiers = byTier(result.metrics.calls || []);
    const purpose = { fast: "extract behaviours (thinking off)", main: "author + refine rules", reasoning: "plan + red-team (thinking on)" };
    const rows = ["fast", "main", "reasoning"].filter((t) => tiers[t]).map((t) => `<tr><td>${t}</td><td><code>${esc(result.models[t] || tiers[t].model)}</code></td><td>${purpose[t]}</td><td>${tiers[t].calls}</td><td>${tiers[t].prompt_tokens.toLocaleString()} / ${tiers[t].completion_tokens.toLocaleString()}</td><td>$${tiers[t].cost_usd.toFixed(4)}</td></tr>`);
    const all = Object.values(tiers).reduce((a, t) => ({ calls: a.calls + t.calls, p: a.p + t.prompt_tokens, c: a.c + t.completion_tokens, cost: a.cost + t.cost_usd }), { calls: 0, p: 0, c: 0, cost: 0 });
    $("#routing").innerHTML = `<table><thead><tr><th>Tier</th><th>Nemotron model</th><th>Used for</th><th>Calls</th><th>Tokens in / out</th><th>Est. cost</th></tr></thead><tbody>${rows.join("")}<tr><td colspan="3"><b>Total</b></td><td>${all.calls}</td><td>${all.p.toLocaleString()} / ${all.c.toLocaleString()}</td><td>$${all.cost.toFixed(4)}</td></tr></tbody></table>`;

    const warn = (result.warnings || []).length ? `<div class="notice">${esc(result.warnings.join(" · "))}</div>` : "";
    state.code = new Map();
    $("#rules").innerHTML = warn + result.rules.map((r, i) => renderRule(r, i, i === 0)).join("");
    applyFilter();
  }

  function stats(r) {
    const rules = r.rules || [];
    const sum = (f) => rules.reduce((a, x) => a + f(x), 0);
    const pt = sum((x) => x.validation.positives_total), pm = sum((x) => x.validation.positives_matched);
    const nt = sum((x) => x.validation.negatives_total), nm = sum((x) => x.validation.negatives_matched);
    const calls = (r.metrics && r.metrics.calls) || [];
    return {
      rules: rules.length,
      validated: rules.filter((x) => x.status === "validated").length,
      positive_recall: pt ? pm / pt : null,
      negative_precision: nt ? 1 - nm / nt : null,
      benign_hits: sum((x) => x.validation.benign_hits),
      benign_total: sum((x) => x.validation.benign_total),
      redteam: sum((x) => (x.tests || []).filter((t) => t.id.startsWith("R")).length),
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

  // Same shape as rulesmith.package.navigator_layer, so the static demo can offer the layer too.
  function navigatorLayer(result) {
    const COLORS = { validated: "#2e8b57", needs_review: "#e9a23b", failed: "#c0392b" };
    const techniques = {};
    for (const rule of result.rules) for (const tid of rule.attack_technique_ids || []) {
      const u = tid.toUpperCase();
      const e = techniques[u] || (techniques[u] = { techniqueID: u, score: 0, color: COLORS[rule.status], comment: "", enabled: true, showSubtechniques: true });
      e.score += 1;
      e.comment = (e.comment ? e.comment + "; " : "") + `${rule.title} [${rule.status}]`;
      if (rule.status === "validated") e.color = COLORS.validated;
    }
    return {
      name: `RuleSmith: ${result.report.title}`.slice(0, 100),
      versions: { attack: "18", navigator: "5.1.0", layer: "4.5" },
      domain: "enterprise-attack",
      description: `Detections generated by RuleSmith from '${result.report.title}' on ${String(result.created_at).slice(0, 10)}.`,
      techniques: Object.values(techniques),
      gradient: { colors: ["#ffffff", "#2e8b57"], minValue: 0, maxValue: 3 },
      legendItems: Object.entries(COLORS).map(([k, v]) => ({ label: k.replace("_", " "), color: v })),
      showTacticRowBackground: true,
      selectTechniquesAcrossTactics: true,
    };
  }

  // ------------------------------------------------------------ rule cards
  const LABELS = { splunk: "Splunk SPL", elasticsearch: "Elastic (Lucene)", kusto: "KQL (Defender XDR)", sqlite: "SQLite" };
  const EXT = { splunk: "spl", elasticsearch: "lucene", kusto: "kql", sqlite: "sql" };

  // Register a code pane's text so the copy/download buttons can find it.
  function codePane(id, text, filename, extraHtml = "") {
    state.code.set(id, { text, filename });
    return `<div class="code-wrap"><div class="code-tools"><button type="button" class="small" data-copy="${esc(id)}">Copy</button><button type="button" class="small" data-download="${esc(id)}">Download</button></div><pre>${esc(text)}</pre>${extraHtml}</div>`;
  }

  // The one field that tells an analyst what a test event is about, for the compact tests table.
  const PREVIEW_FIELDS = ["CommandLine", "Details", "TargetFilename", "PipeName", "ImageLoaded", "QueryName", "DestinationHostname", "eventName", "ServiceName", "Image", "TargetObject", "url", "message"];
  function eventPreview(event) {
    for (const k of PREVIEW_FIELDS) {
      const hit = Object.keys(event).find((x) => x.toLowerCase() === k.toLowerCase());
      if (hit && typeof event[hit] === "string" && event[hit]) return `${hit}: ${event[hit]}`;
    }
    const first = Object.entries(event).find(([, v]) => typeof v === "string" && v);
    return first ? `${first[0]}: ${first[1]}` : JSON.stringify(event);
  }

  // Turn a validator issue into a headline plus the per-selection detail.
  function issueParts(issue) {
    const m = String(issue.message);
    const at = m.indexOf(". Per selection: ");
    if (at < 0) return { head: m, why: "" };
    return { head: m.slice(0, at + 1), why: m.slice(at + 2) };
  }

  function renderRule(rule, i, open) {
    const v = rule.validation;
    const conv = Object.entries(rule.conversions || {}).filter(([k]) => k !== "sqlite");
    const convErr = Object.entries(rule.conversion_errors || {});
    const tests = rule.tests || [];
    const outcome = Object.fromEntries((v.test_outcomes || []).map((o) => [o.event_id, o]));
    const cand = state.plan ? (state.plan.candidates || []).find((c) => c.id === rule.candidate_id) : null;
    const behaviours = (state.report && state.report.behaviors || []).filter((b) => ((cand && cand.behavior_ids) || []).includes(b.id));
    const errors = (v.issues || []).filter((x) => x.severity === "error");
    const warnings = (v.issues || []).filter((x) => x.severity !== "error");
    const oos = rule.redteam_out_of_scope || [];
    const fname = slug(rule.title);
    const cid = rule.candidate_id;
    const negBlocked = v.negatives_total - v.negatives_matched;

    const testRow = (t) => {
      const o = outcome[t.id];
      const positive = t.label === "positive";
      const res = !o ? ["", "–"] : o.passed ? ["pass", positive ? "✓ caught" : "✓ blocked"] : ["fail", positive ? "✗ missed" : "✗ fired"];
      const kind = `<span class="kind ${positive ? "attack" : "benign"}${t.id.startsWith("R") ? " red" : ""}">${positive ? "attack" : "benign"}${t.id.startsWith("R") ? " · red-team" : ""}</span>`;
      return `<tr><td class="mono">${esc(t.id)}</td><td>${kind}</td><td class="${res[0]}">${res[1]}</td><td>${esc(t.description)}<div class="preview">${esc(eventPreview(t.event))}</div><details><summary>full event</summary><pre>${esc(JSON.stringify(t.event, null, 1))}</pre></details></td></tr>`;
    };
    const authored = tests.filter((t) => !t.id.startsWith("R")), redteam = tests.filter((t) => t.id.startsWith("R"));
    const table = (rows) => `<table><thead><tr><th>Id</th><th>Kind</th><th>Result</th><th>What it is</th></tr></thead><tbody>${rows.map(testRow).join("")}</tbody></table>`;

    const checkBox = rule.status === "validated" ? "" : `<div class="check-box"><h5>What to check before deploying</h5>
      ${errors.length ? `<ul>${errors.map((x) => { const p = issueParts(x); return `<li>${esc(p.head)}${p.why ? `<details><summary>why, per selection and field</summary><div class="why">${esc(p.why)}</div></details>` : ""}</li>`; }).join("")}</ul>` : `<p>${rule.status === "failed" ? "The rule did not parse or compile; see the history tab." : "No blocking issue recorded; see the history tab for what the last refine round changed."}</p>`}
      ${warnings.length ? `<p class="muted">Also: ${esc(warnings.map((x) => x.message).join(" · "))}</p>` : ""}
    </div>`;

    return `
    <div class="rule ${esc(rule.status)}" data-cid="${esc(cid)}" data-status="${esc(rule.status)}">
      <div class="rule-head" role="button" tabindex="0" aria-expanded="${open ? "true" : "false"}">
        <div>
          <h4>${esc(rule.title)}</h4>
          <div class="meta">
            <span class="tagchip">${esc(cid)}</span>
            ${(rule.attack_technique_ids || []).map((t) => `<a class="tagchip" href="${attackUrl(t)}" target="_blank" rel="noopener" title="Open on attack.mitre.org">${esc(t)}</a>`).join("")}
            ${cand ? `<span class="tagchip" title="Sigma logsource">${esc(cand.logsource.product)}/${esc(cand.logsource.category || cand.logsource.service)}</span>` : ""}
            <span class="counts" title="attack events caught · benign look-alikes blocked · benign baseline hits"><span class="${v.positives_matched === v.positives_total ? "ok" : "ko"}">${v.positives_matched}/${v.positives_total} attack</span> · <span class="${negBlocked === v.negatives_total ? "ok" : "ko"}">${negBlocked}/${v.negatives_total} benign</span> · <span class="${v.benign_hits ? "ko" : "ok"}">${v.benign_hits} baseline</span></span>
            <span>· ${rule.history.length} cycle${rule.history.length === 1 ? "" : "s"}</span>
          </div>
        </div>
        <div class="row"><span class="status ${esc(rule.status)}">${esc(rule.status.replace("_", " "))}</span><span class="caret">${open ? "▴" : "▾"}</span></div>
      </div>
      <div class="rule-body ${open ? "" : "hidden"}">
        ${checkBox}
        <div class="rule-tabs" role="tablist">
          <button type="button" class="tab active" data-pane="sigma">Sigma</button>
          ${conv.map(([k]) => `<button type="button" class="tab" data-pane="${esc(k)}">${LABELS[k] || k}</button>`).join("")}
          <button type="button" class="tab" data-pane="tests">Tests (${tests.length})</button>
          <button type="button" class="tab" data-pane="history">History (${rule.history.length})</button>
          <button type="button" class="tab" data-pane="evidence">Evidence</button>
          ${oos.length ? `<button type="button" class="tab" data-pane="oos">Out-of-scope evasions (${oos.length})</button>` : ""}
        </div>
        <div class="pane" data-pane="sigma">${codePane(`${cid}-sigma`, rule.sigma_yaml, `${fname}.yml`)}${rule.author_notes ? `<p class="muted">${esc(rule.author_notes)}</p>` : ""}</div>
        ${conv.map(([k, q]) => `<div class="pane hidden" data-pane="${esc(k)}">${codePane(`${cid}-${k}`, q, `${fname}.${EXT[k] || "txt"}`)}</div>`).join("")}
        <div class="pane hidden tests" data-pane="tests">
          ${convErr.length ? `<p class="muted">Conversion skipped: ${esc(convErr.map(([k, e]) => `${k}: ${e}`).join(" · "))}</p>` : ""}
          <h3>Author's tests (${authored.length})</h3>${table(authored)}
          ${redteam.length ? `<h3>Red-team variants (${redteam.length})</h3>${table(redteam)}` : ""}
          ${(rule.retired_tests || []).length ? `<h3>Red-team variants retired as unreachable</h3><ul class="retired">${rule.retired_tests.map((t) => `<li><span class="mono">${esc(t.id)}</span> ${esc(t.description)}</li>`).join("")}</ul>` : ""}
          ${(rule.replaced_tests || []).length ? `<h3>Test events corrected during refinement (original shown)</h3><ul class="retired">${rule.replaced_tests.map((t) => `<li><span class="mono">${esc(t.id)}</span> ${esc(t.description)}</li>`).join("")}</ul>` : ""}
          ${v.benign_examples && v.benign_examples.length ? `<h3>Benign baseline events still matching</h3><pre>${esc(JSON.stringify(v.benign_examples, null, 1))}</pre>` : `<p class="muted">Benign baseline: ${v.benign_hits} hit(s) across ${v.benign_total.toLocaleString()} events for this logsource.</p>`}
        </div>
        <div class="pane hidden history" data-pane="history">
          <ul class="timeline">${rule.history.map((h) => `<li class="${h.passed ? "ok" : "ko"}"><span class="phase">${esc(h.phase)} #${h.iteration}</span><span>${esc(h.summary)}${h.change_summary ? `<span class="change">${esc(h.change_summary)}</span>` : ""}</span></li>`).join("")}</ul>
          ${rule.redteam_analysis ? `<h3>Red-team analysis (Nemotron Ultra)</h3><p>${esc(rule.redteam_analysis)}</p>` : ""}
        </div>
        <div class="pane hidden evidence" data-pane="evidence">
          ${behaviours.length ? behaviours.map((b) => `<div><b>${esc(b.id)} · <a href="${attackUrl(b.attack_technique_id)}" target="_blank" rel="noopener">${esc(b.attack_technique_id)}</a></b> ${esc(b.description)}<blockquote>“${esc(b.evidence)}”</blockquote></div>`).join("") : `<p class="muted">No behaviour mapping recorded.</p>`}
        </div>
        ${oos.length ? `<div class="pane hidden" data-pane="oos"><p class="muted">Evasions the red-team judged beyond what this logsource and rule can see. They were not added as tests; they are here so you know the blind spots.</p><ul class="retired">${oos.map((t) => `<li><span class="mono">${esc(t.id)}</span> ${esc(t.description)}<div class="preview mono">${esc(eventPreview(t.event || {}))}</div></li>`).join("")}</ul></div>` : ""}
      </div>
    </div>`;
  }

  function setOpen(body, open) {
    body.classList.toggle("hidden", !open);
    const head = body.previousElementSibling;
    head.setAttribute("aria-expanded", String(open));
    const caret = $(".caret", head);
    if (caret) caret.textContent = open ? "▴" : "▾";
  }

  function applyFilter() {
    $$("#rules .rule").forEach((el) => el.classList.toggle("hidden", state.filter !== "all" && el.dataset.status !== state.filter && el.dataset.status !== "working"));
  }

  // Clicks inside rendered content: rule headers, pane tabs, copy/download, behaviour chips.
  function onDelegatedClick(e) {
    const chip = e.target.closest("[data-behaviour]");
    if (chip) return toggleBehaviour(chip.dataset.behaviour);
    const copy = e.target.closest("[data-copy]");
    if (copy) { const c = state.code.get(copy.dataset.copy); if (c) copyText(c.text, c.filename); return; }
    const dl = e.target.closest("[data-download]");
    if (dl) { const c = state.code.get(dl.dataset.download); if (c) downloadText(c.filename, c.text); return; }
    const tab = e.target.closest(".rule-tabs .tab");
    if (tab) {
      const body = tab.closest(".rule-body");
      $$(".rule-tabs .tab", body).forEach((x) => x.classList.toggle("active", x === tab));
      $$(".pane", body).forEach((p) => p.classList.toggle("hidden", p.dataset.pane !== tab.dataset.pane));
      return;
    }
    const head = e.target.closest(".rule-head[role=button]");
    if (head && !e.target.closest("a")) setOpen(head.nextElementSibling, head.nextElementSibling.classList.contains("hidden"));
  }
  document.addEventListener("keydown", (e) => {
    if ((e.key === "Enter" || e.key === " ") && e.target.matches && e.target.matches(".rule-head[role=button]")) { e.preventDefault(); e.target.click(); }
  });

  function summarize(v) {
    if (!v.parse_ok) return "parse failed";
    return `positives ${v.positives_matched}/${v.positives_total}, negatives blocked ${v.negatives_total - v.negatives_matched}/${v.negatives_total}, benign hits ${v.benign_hits}/${v.benign_total}`;
  }

  // ------------------------------------------------------------ replay
  // Fetch a recorded run. In static mode the JSON is split into part files
  // (replays/<id>.part0.json ...) which are concatenated here.
  async function fetchReplay(id) {
    if (!STATIC) return (await fetch(`/api/replays/${id}`)).json();
    const parts = (state.replays.get(id) || {}).parts || 1;
    const texts = await Promise.all(Array.from({ length: parts }, (_, n) => fetch(`replays/${id}.part${n}.json`).then((r) => r.text())));
    return JSON.parse(texts.join(""));
  }

  async function replay(id, { instant = false, openRule = null } = {}) {
    if (!id || !state.replays.has(id)) return;
    if (state.es) { state.es.close(); state.es = null; }
    resetRun(true);
    state.replayId = id;
    showError("");
    const rep = $("#replay-btn");
    rep.disabled = true; rep.classList.add("busy");
    let result;
    try { result = await fetchReplay(id); }
    catch (e) { showError(`Could not load the recorded run: ${e.message}`); rep.disabled = false; rep.classList.remove("busy"); return; }
    startTimer();

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
      push({ type: "rule", stage: r.candidate_id, status: r.status, title: r.title, message: `${r.status}: ${summarize(r.validation)}`, rule: r });
    }
    push({ type: "stage", stage: "rules", status: "done", message: `${result.rules.filter((r) => r.status === "validated").length}/${result.rules.length} rules validated` });
    push({ type: "done", stage: "done", message: `Recorded run ${result.run_id} (${String(result.created_at).slice(0, 10)})` });

    const finishReplay = () => {
      stopTimer();
      rep.disabled = false; rep.classList.remove("busy");
      $("#skip-btn").classList.add("hidden");
      const entry = state.replays.get(id) || {};
      const links = STATIC
        ? { zip: entry.zip ? `replays/${id}.zip` : null, nav: null, md: null }
        : { zip: `/api/replays/${id}/download`, nav: `/api/replays/${id}/navigator.json`, md: `/api/replays/${id}/report.md` };
      renderResult(result, links);
      if (STATIC && !entry.zip) showNotice(`Hosted demo: copy or download each rule from its card. The full zip pack comes from the CLI: rulesmith replay ${id} --out pack`);
      if (openRule) {
        const card = $(`#rules .rule[data-cid="${CSS.escape(openRule)}"]`);
        if (card) { $$("#rules .rule-body").forEach((b) => setOpen(b, b === $(".rule-body", card))); card.scrollIntoView({ behavior: "smooth", block: "start" }); }
      }
    };
    if (instant) state.skip = true;
    let i = 0;
    const tick = () => {
      if (state.skip) { while (i < events.length) handleEvent(events[i++]); }
      if (i >= events.length) return finishReplay();
      handleEvent(events[i++]);
      setTimeout(tick, i < 8 ? 450 : 250);
    };
    tick();
  }

  boot();
})();
