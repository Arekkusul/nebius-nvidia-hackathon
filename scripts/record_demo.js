// Capture frames of the UI replaying a recorded run, for the animated demo
// in the README and on the Devpost page. Frames are PNG screenshots taken
// over the DevTools Protocol while the run plays at normal speed, followed
// by a few of the finished pack; scripts/make_gif.py turns them into a GIF.
//
//   rulesmith serve --port 7861 &                       # replays only, no key needed
//   node scripts/record_demo.js /path/to/chrome /tmp/frames [replay-id]
//   python scripts/make_gif.py /tmp/frames docs/demo.gif
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const [chromeBin, framesDir, replayId = "ransomware_affiliate_intrusion"] = process.argv.slice(2);
if (!chromeBin || !framesDir) {
  console.error("usage: node scripts/record_demo.js <chrome> <frames-dir> [replay-id]");
  process.exit(2);
}
const BASE = process.env.RULESMITH_BASE || "http://127.0.0.1:7861";
const PORT = 9335;
const WIDTH = 1440, HEIGHT = 1000;   // capture size; make_gif.py scales the GIF down
const FRAME_MS = 400;                // one frame every 400 ms while the replay animates
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

  fs.mkdirSync(framesDir, { recursive: true });
  for (const f of fs.readdirSync(framesDir)) if (f.endsWith(".png")) fs.unlinkSync(path.join(framesDir, f));
  let n = 0;
  const frame = async () => {
    const r = await send("Page.captureScreenshot", { format: "png" });
    fs.writeFileSync(path.join(framesDir, `f${String(n++).padStart(4, "0")}.png`), Buffer.from(r.result.data, "base64"));
  };

  // The run plays at its normal pace; capture until the verdict is on screen.
  await send("Page.navigate", { url: `${BASE}/?replay=${encodeURIComponent(replayId)}` });
  await sleep(700);
  for (let i = 0; i < 150; i++) {
    await frame();
    if (await evaluate(`!document.querySelector("#downloads").classList.contains("hidden")`)) break;
    await sleep(FRAME_MS);
  }
  // Hold on the finished progress card, then scroll to the pack and hold again.
  for (let i = 0; i < 4; i++) { await frame(); await sleep(FRAME_MS); }
  await evaluate(`document.querySelector("#results").scrollIntoView({ block: "start" })`);
  await sleep(500);
  for (let i = 0; i < 8; i++) { await frame(); await sleep(FRAME_MS); }
  // Open the tests tab of the first rule and hold once more.
  await evaluate(`document.querySelector('[data-main-tab="rules"]').click(); document.querySelector('#rules .rule-tabs .tab[data-pane="tests"]').click(); document.querySelector("#rules .rule").scrollIntoView({ block: "start" })`);
  await sleep(500);
  for (let i = 0; i < 8; i++) { await frame(); await sleep(FRAME_MS); }
  ws.close(); chrome.kill();
  console.log(`captured ${n} frames in ${framesDir} (${FRAME_MS} ms apart)`);
}

main().catch((e) => { console.error("recording failed:", e.message); process.exit(1); });
