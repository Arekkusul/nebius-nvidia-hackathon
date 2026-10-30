// Record the material for the demo video: a genuine live run in the web UI,
// captured frame by frame over the DevTools Protocol, followed by a tour of
// the finished pack. Writes PNG frames plus a manifest (caption and how long
// each segment should play); scripts/make_video.py turns that into a WebM.
//
//   NEBIUS_API_KEY=... TAVILY_API_KEY=... rulesmith serve --port 7863 &
//   node scripts/record_video.js /path/to/chrome /tmp/video-frames [url-to-analyse]
//   python scripts/make_video.py /tmp/video-frames docs/demo.webm
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const [chromeBin, outDir, reportUrl = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-241a"] = process.argv.slice(2);
if (!chromeBin || !outDir) {
  console.error("usage: node scripts/record_video.js <chrome> <frames-dir> [report-url]");
  process.exit(2);
}
const BASE = process.env.RULESMITH_BASE || "http://127.0.0.1:7863";
const PORT = 9336;
const WIDTH = 1600, HEIGHT = 900;    // 16:9, the shape YouTube expects
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const chrome = spawn(chromeBin, ["--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars", `--remote-debugging-port=${PORT}`, `--window-size=${WIDTH},${HEIGHT}`, "about:blank"], { stdio: "ignore" });
  let targets = [];
  for (let i = 0; i < 60 && !targets.length; i++) {
    try { targets = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json(); } catch (e) { /* not up yet */ }
    if (!targets.length) await sleep(250);
  }
  const ws = new WebSocket(targets[0].webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  let nextId = 0; const pending = new Map();
  ws.onmessage = (m) => { const msg = JSON.parse(m.data); if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); } };
  const send = (method, params = {}) => new Promise((resolve) => { const id = ++nextId; pending.set(id, resolve); ws.send(JSON.stringify({ id, method, params })); });
  const evaluate = async (expression) => (await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true })).result.result?.value;
  await send("Page.enable");
  await send("Emulation.setDeviceMetricsOverride", { width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: false });

  fs.mkdirSync(outDir, { recursive: true });
  for (const f of fs.readdirSync(outDir)) fs.unlinkSync(path.join(outDir, f));
  const manifest = [];   // [{file, caption, ms}] in playback order
  let n = 0;
  // One frame shown for `ms` milliseconds of video time.
  const frame = async (caption, ms) => {
    const r = await send("Page.captureScreenshot", { format: "png" });
    const file = `f${String(n++).padStart(4, "0")}.png`;
    fs.writeFileSync(path.join(outDir, file), Buffer.from(r.result.data, "base64"));
    manifest.push({ file, caption, ms });
  };
  // Capture a sequence at `everyMs` real time, each frame shown `showMs` in the video (speeds waits up).
  const capture = async (caption, totalMs, everyMs, showMs) => { for (let t = 0; t < totalMs; t += everyMs) { await frame(caption, showMs); await sleep(everyMs); } };

  // 1. Arrival: the page as a visitor sees it with a key configured.
  await send("Page.navigate", { url: `${BASE}/?autoplay=0` });
  await sleep(1500);
  await capture("RuleSmith. Every model call is NVIDIA Nemotron on Nebius Token Factory; Tavily fetches the intel.", 2500, 500, 500);

  // 2. Pick the URL tab, quick-fill the CISA advisory, run.
  await evaluate(`document.querySelector('.tab[data-mode="url"]').click()`);
  await sleep(400);
  await capture("A real advisory: CISA AA24-241A, Iran-based actors enabling ransomware. One click fills the URL.", 1500, 500, 500);
  await evaluate(`document.querySelector('[data-fill-url]').click()`);
  await sleep(400);
  await capture("Run the agent. Everything from here is live; waits are shortened, the timestamps are real.", 2000, 500, 500);
  await evaluate(`document.querySelector("#run-btn").click()`);

  // 3. The live run: capture every 500 ms real time, play at 8x (each frame 62 ms) until the pack is complete.
  const started = Date.now();
  let caption = "Tavily extracts the report; Nemotron 3.5 Lightning pulls behaviours with evidence quotes.";
  while (Date.now() - started < 8 * 60 * 1000) {
    const planDone = await evaluate(`document.querySelector('#stages li[data-stage="plan"]').classList.contains("done")`);
    const extractDone = await evaluate(`document.querySelector('#stages li[data-stage="extract"]').classList.contains("done")`);
    if (extractDone && !planDone) caption = "Nemotron 3 Ultra plans which behaviours deserve a rule, thinking on.";
    if (planDone) caption = "Nemotron 3 Super writes each rule and its tests; the validator executes them, failures go back with the exact event, Ultra red-teams the result.";
    await frame(caption, 62);
    if (await evaluate(`!document.querySelector("#downloads").classList.contains("hidden")`)) break;
    const err = await evaluate(`document.querySelector("#input-error").textContent`);
    if (err) throw new Error("run failed: " + err);
    await sleep(500);
  }
  const elapsed = Math.round((Date.now() - started) / 1000);
  console.log(`live run finished in ${elapsed}s`);

  // 4. The finished progress card, behaviours with one evidence quote open.
  await evaluate(`document.querySelector('[data-main-tab="evidence"]').click(); document.querySelector('#behaviours .chip').click()`);
  await sleep(300);
  await capture(`Done in ${Math.floor(elapsed / 60)}m${String(elapsed % 60).padStart(2, "0")}s. Click a behaviour: the evidence sentence the model took from the report.`, 3500, 500, 500);

  // 5. The pack: verdict, metrics, routing and cost.
  await evaluate(`document.querySelector('[data-main-tab="overview"]').click(); document.querySelector("#results").scrollIntoView({ block: "start" })`);
  await sleep(400);
  await capture("The verdict. Validated means: parses, compiles, catches every attack event, blocks every benign look-alike, survives the red-team, zero baseline hits.", 4500, 500, 500);
  await evaluate(`document.querySelector(".routing-box").scrollIntoView({ block: "start" })`);
  await sleep(400);
  await capture("Which Nemotron did what, with tokens and the cost of this whole run.", 3500, 500, 500);

  // 6. A rule that needs review, if there is one: the what-to-check box.
  await evaluate(`document.querySelector('[data-main-tab="rules"]').click()`);
  const review = await evaluate(`(() => { const r = document.querySelector('#rules .rule[data-status="needs_review"]'); if (!r) return false; document.querySelectorAll("#rules .rule-body").forEach(b => b.classList.add("hidden")); r.querySelector(".rule-body").classList.remove("hidden"); r.scrollIntoView({ block: "start" }); return true; })()`);
  if (review) {
    await sleep(400);
    await capture("A rule short of validated ships with the exact tests it misses and the per-field reason, so the fix is a minute's work, not an afternoon's.", 5000, 500, 500);
  }
  // 7. First rule: Sigma, then the tests table, then the red-team evasions out of scope.
  await evaluate(`(() => { const r = document.querySelector("#rules .rule"); document.querySelectorAll("#rules .rule-body").forEach(b => b.classList.add("hidden")); r.querySelector(".rule-body").classList.remove("hidden"); r.scrollIntoView({ block: "start" }); })()`);
  await sleep(400);
  await capture("Each rule: the Sigma YAML with copy and download, and the same logic in Splunk, Elastic and KQL.", 3500, 500, 500);
  await evaluate(`document.querySelector('#rules .rule .rule-tabs .tab[data-pane="kusto"]')?.click()`);
  await sleep(400);
  await capture("KQL for Defender XDR, ready to paste.", 2500, 500, 500);
  await evaluate(`document.querySelector('#rules .rule .rule-tabs .tab[data-pane="tests"]').click()`);
  await sleep(400);
  await capture("The tests: the author's attack and benign events, then Ultra's evasion variants, each one caught or blocked by execution, not by opinion.", 5000, 500, 500);
  await evaluate(`document.querySelector('#rules .rule .pane[data-pane="tests"] h3:last-of-type')?.scrollIntoView({ block: "start" })`);
  await sleep(400);
  await capture("Red-team variants: reordered flags, SysWOW64 paths, quoting tricks.", 3000, 500, 500);
  const oos = await evaluate(`(() => { const t = document.querySelector('#rules .rule .rule-tabs .tab[data-pane="oos"]'); if (!t) return false; t.click(); document.querySelector("#rules .rule").scrollIntoView({ block: "start" }); return true; })()`);
  if (oos) { await sleep(400); await capture("And the evasions the logsource cannot see, listed as blind spots instead of hidden.", 3500, 500, 500); }
  // 8. Downloads row.
  await evaluate(`document.querySelector('[data-main-tab="overview"]').click(); window.scrollTo(0, 0)`);
  await sleep(400);
  await capture("Download the pack: Sigma, Splunk, Elastic, KQL, tests, an ATT&CK Navigator layer and the evidence-linked report.", 3500, 500, 500);

  fs.writeFileSync(path.join(outDir, "manifest.json"), JSON.stringify({ width: WIDTH, height: HEIGHT, elapsed_s: elapsed, frames: manifest }, null, 1));
  ws.close(); chrome.kill();
  console.log(`captured ${n} frames into ${outDir}`);
}

main().catch((e) => { console.error("recording failed:", e.message); process.exit(1); });
