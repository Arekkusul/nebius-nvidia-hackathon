// Headless smoke test for the RuleSmith web UI, driven over the Chrome
// DevTools Protocol with nothing but Node 22 (global WebSocket) and a
// Chromium binary. It collects every console error and uncaught exception
// while it exercises the page, and exits non-zero if any were seen.
//
//   python scripts/fake_server.py --port 7862 &              # live runs with the fake model
//   rulesmith serve --port 7861 &                            # replays (no key needed)
//   node scripts/ui_smoke.js /path/to/chrome http://127.0.0.1:7862 http://127.0.0.1:7861 [screenshot-dir]
//
// The first base URL must have a model configured (the fake server does);
// the second may be key-less, it only needs the recorded runs. Pass a
// directory as the fourth argument to keep full-page screenshots.
const { spawn } = require("child_process");
const fs = require("fs");

const [chromeBin, liveBase, replayBase, outDir] = process.argv.slice(2);
if (!chromeBin || !liveBase || !replayBase) {
  console.error("usage: node scripts/ui_smoke.js <chrome> <live-base-url> <replay-base-url> [screenshot-dir]");
  process.exit(2);
}
const PORT = 9333;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Launch Chromium with the DevTools endpoint open and return a tiny CDP client.
async function launch() {
  const chrome = spawn(chromeBin, ["--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars", `--remote-debugging-port=${PORT}`, "--window-size=1440,1400", "about:blank"], { stdio: "ignore" });
  let targets = [];
  for (let i = 0; i < 60 && !targets.length; i++) {
    try { targets = await (await fetch(`http://127.0.0.1:${PORT}/json`)).json(); } catch (e) { /* not listening yet */ }
    if (!targets.length) await sleep(250);
  }
  if (!targets.length) throw new Error("Chromium did not expose a DevTools target");
  const ws = new WebSocket(targets[0].webSocketDebuggerUrl);
  await new Promise((r) => (ws.onopen = r));
  let nextId = 0;
  const pending = new Map();
  const problems = [];
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
    if (msg.method === "Runtime.exceptionThrown") problems.push("exception: " + (msg.params.exceptionDetails.exception?.description || msg.params.exceptionDetails.text));
    if (msg.method === "Runtime.consoleAPICalled" && msg.params.type === "error") problems.push("console.error: " + msg.params.args.map((a) => a.value || a.description).join(" "));
    if (msg.method === "Log.entryAdded" && msg.params.entry.level === "error") problems.push(`log: ${msg.params.entry.text} ${msg.params.entry.url || ""}`);
  };
  const send = (method, params = {}) => new Promise((resolve) => { const id = ++nextId; pending.set(id, resolve); ws.send(JSON.stringify({ id, method, params })); });
  const evaluate = async (expression) => {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
    if (r.result.exceptionDetails) throw new Error("evaluate failed: " + (r.result.exceptionDetails.exception?.description || r.result.exceptionDetails.text));
    return r.result.result.value;
  };
  // Poll an expression until it is truthy; evaluation errors while a page is still loading are ignored.
  const waitFor = async (expression, timeout = 30000) => {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      try { if (await evaluate(expression)) return; } catch (e) { /* retry */ }
      await sleep(200);
    }
    throw new Error("timed out waiting for " + expression);
  };
  const goto = async (url) => { await send("Page.navigate", { url }); await sleep(300); };
  const screenshot = async (name) => {
    if (!outDir) return;
    const height = await evaluate("document.documentElement.scrollHeight");
    await send("Emulation.setDeviceMetricsOverride", { width: 1440, height: Math.min(height, 6000), deviceScaleFactor: 1, mobile: false });
    const r = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true });
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(`${outDir}/${name}.png`, Buffer.from(r.result.data, "base64"));
    await send("Emulation.clearDeviceMetricsOverride");
  };
  await send("Runtime.enable"); await send("Log.enable"); await send("Page.enable");
  return { chrome, ws, send, evaluate, waitFor, goto, screenshot, problems };
}

async function main() {
  const b = await launch();
  const checks = [];
  const check = (name, ok, detail = "") => { checks.push({ name, ok }); console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? " · " + detail : ""}`); };

  // 1. A live run on the server with a model: example mode, settings summary, verdict, downloads.
  await b.goto(`${liveBase}/`);
  await b.waitFor(`document.querySelector("#health").textContent.includes("Token Factory")`);
  check("run button usable when a key is configured", await b.evaluate(`!document.querySelector("#run-btn").classList.contains("hidden") && !document.querySelector("#run-btn").disabled`));
  await b.evaluate(`document.querySelector("#opt-rules").value = 2; document.querySelector("#opt-rules").dispatchEvent(new Event("change"))`);
  check("settings summary follows the inputs", (await b.evaluate(`document.querySelector("#settings-summary").textContent`)).startsWith("2 rules"));
  check("pack card hidden before any run", await b.evaluate(`document.querySelector("#results").classList.contains("hidden")`));
  await b.evaluate(`document.querySelector("#run-btn").click()`);
  await b.waitFor(`!document.querySelector("#downloads").classList.contains("hidden")`, 60000);
  check("live run reaches a verdict", true, await b.evaluate(`document.querySelector("#verdict .text b").textContent`));
  check("every stage pill is done", await b.evaluate(`Array.from(document.querySelectorAll("#stages li")).every(l => l.className === "done")`));
  check("download links point at the run", await b.evaluate(`document.querySelector("#dl-zip").getAttribute("href").includes("/api/runs/")`));
  await b.screenshot("live_run");
  await b.evaluate(`document.querySelector('#rules .rule-tabs .tab[data-pane="tests"]').click()`);
  check("tests tab renders rows", (await b.evaluate(`document.querySelectorAll('#rules .pane[data-pane="tests"] tbody tr').length`)) > 0);
  await b.evaluate(`document.querySelector('[data-filter="needs_review"]').click()`);
  await b.evaluate(`document.querySelector('[data-filter="all"]').click(); document.querySelector("#expand-all").click()`);
  check("expand all opens every card", await b.evaluate(`Array.from(document.querySelectorAll("#rules .rule-body")).every(b => !b.classList.contains("hidden"))`));
  await b.evaluate(`document.querySelector("#theme-btn").click()`);
  check("theme toggle sets data-theme", Boolean(await b.evaluate(`document.documentElement.dataset.theme`)));
  await b.evaluate(`document.querySelector("#theme-btn").click()`);
  await b.evaluate(`document.querySelector('.tab[data-mode="url"]').click(); document.querySelector("#run-btn").click()`);
  await sleep(300);
  check("empty URL is refused client-side", (await b.evaluate(`document.querySelector("#input-error").textContent`)).includes("URL"));

  // 2. A recorded run on the key-less server: deep link, skip, downloads, evidence, copy link.
  await b.goto(`${replayBase}/?replay=macro_loader_campaign&rule=D4`);
  await b.waitFor(`document.querySelector("#replay-badge") && !document.querySelector("#replay-badge").classList.contains("hidden")`);
  await sleep(1000);
  check("download buttons hidden while a run is in flight", await b.evaluate(`document.querySelector("#downloads").classList.contains("hidden")`));
  await b.evaluate(`document.querySelector("#skip-btn").click()`);
  await b.waitFor(`!document.querySelector("#downloads").classList.contains("hidden")`);
  check("replay reaches a verdict", true, await b.evaluate(`document.querySelector("#verdict .text b").textContent`));
  check("deep link opens the requested rule only", (await b.evaluate(`Array.from(document.querySelectorAll("#rules .rule")).filter(r => !r.querySelector(".rule-body").classList.contains("hidden")).map(r => r.dataset.cid).join(",")`)) === "D4");
  check("replay downloads use the replay endpoints", await b.evaluate(`document.querySelector("#dl-md").getAttribute("href").includes("/api/replays/")`));
  await b.evaluate(`document.querySelector('#behaviours .chip').click()`);
  check("behaviour chip shows its evidence", await b.evaluate(`Boolean(document.querySelector("#behaviours .evidence-pop"))`));
  check("copy link offered for a replay", await b.evaluate(`!document.querySelector("#copy-link").classList.contains("hidden")`));
  await b.screenshot("replay_rule_open");

  // 3. Unknown replay id, auto-play on a replay-only page, and a phone-width layout.
  await b.goto(`${replayBase}/?replay=does_not_exist`);
  await sleep(1200);
  check("unknown replay id reports an error", (await b.evaluate(`document.querySelector("#input-error").textContent`)).length > 0);
  await b.goto(`${replayBase}/`);
  await sleep(1500);
  check("replay-only page auto-plays a recorded run", await b.evaluate(`!document.querySelector("#replay-badge").classList.contains("hidden")`));
  await b.send("Emulation.setDeviceMetricsOverride", { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
  await sleep(500);
  check("no horizontal scroll at 390px", !(await b.evaluate(`document.documentElement.scrollWidth > document.documentElement.clientWidth`)));
  await b.send("Emulation.clearDeviceMetricsOverride");

  const failed = checks.filter((c) => !c.ok).length;
  console.log(`\n${checks.length - failed}/${checks.length} checks passed; browser problems: ${b.problems.length ? "\n  " + b.problems.join("\n  ") : "none"}`);
  b.ws.close(); b.chrome.kill();
  process.exit(failed || b.problems.length ? 1 : 0);
}

main().catch((e) => { console.error("smoke test crashed:", e.message); process.exit(1); });
