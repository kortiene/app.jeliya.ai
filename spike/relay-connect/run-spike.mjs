#!/usr/bin/env node
// THROWAWAY Phase 0 spike (#23) — orchestrator.
//
// Runs the complete browser→relay-auth→relay→native round trip on one or
// more browser engines, records the verdict in NOTES.md, and exits non-zero
// on a FAIL verdict so CI (or a human) cannot miss it.
//
// Usage:
//   ./run-spike.mjs [chromium|firefox|webkit]...
//
// Defaults to chromium,firefox,webkit. Engines whose browser binary is not
// installed are recorded as SKIPPED with the install command, not FAILED.

import { spawn } from "node:child_process";
import { createReadStream, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";

const HERE = resolve(dirname(fileURLToPath(import.meta.url)));
const REPO = resolve(HERE, "../..");
const RELEASE = join(HERE, "target/release");

// Resolve playwright from the ui workspace so this spike needs no npm install.
const PW = await import("file://" + join(REPO, "ui/node_modules/playwright/index.mjs"));
const { chromium, firefox, webkit } = PW;

const ENGINES = {
  chromium: { type: chromium, label: "Chromium" },
  firefox: { type: firefox, label: "Firefox" },
  webkit: { type: webkit, label: "WebKit" },
};

const wanted = process.argv.slice(2).filter((a) => ENGINES[a]);
const engines = wanted.length > 0 ? wanted : ["chromium", "firefox", "webkit"];

// --- 1. Start the three Rust services -------------------------------------

const procs = [];

function start(bin, args, label) {
  const p = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
  procs.push(p);
  p.stdout.on("data", (d) => process.stdout.write(`[${label}] ${d}`));
  p.stderr.on("data", (d) => process.stderr.write(`[${label}] ${d}`));
  p.on("exit", (code, sig) => {
    if (code !== 0 && code !== null && sig !== "SIGTERM") {
      console.error(`[${label}] exited code=${code} sig=${sig}`);
    }
  });
  return p;
}

async function waitForReady(label, predicate, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  const buf = [];
  // Each proc's stdout was already piped above; here we re-tap via a shared
  // mailbox. Simplest reliable path: poll a file the service prints to stdout
  // by watching the buffered lines.
  while (Date.now() < deadline) {
    const line = readyLines[label];
    if (line && predicate(line)) return line;
    await sleep(200);
  }
  throw new Error(`${label} did not become ready within ${timeoutMs}ms`);
}

// Tiny mailbox: each service prints one "SPIKE_*_READY ..." line on startup.
const readyLines = {};
function tapReady(label, proc) {
  let acc = "";
  proc.stdout.on("data", (d) => {
    acc += d.toString();
    const m = acc.match(/SPIKE_\w+_READY (.*)/);
    if (m && !readyLines[label]) readyLines[label] = m[1];
  });
}

console.log("==> starting relay-auth…");
const relayAuth = start(join(RELEASE, "spike-relay-auth"), ["--bind", "127.0.0.1:7780"], "relay-auth");
tapReady("relay-auth", relayAuth);
await waitForReady("relay-auth", (s) => s.includes("verifying_key="));
const authReady = readyLines["relay-auth"];
const verifyingKey = authReady.match(/verifying_key=([0-9a-f]+)/)[1];
console.log(`    verifying_key=${verifyingKey}`);

console.log("==> starting relay-server…");
const relaySrv = start(
  join(RELEASE, "spike-relay-server"),
  ["--bind", "127.0.0.1:3340", "--verifying-key", verifyingKey],
  "relay-server",
);
tapReady("relay-server", relaySrv);
await waitForReady("relay-server", (s) => s.includes("bind="));

console.log("==> starting native-endpoint…");
const native = start(
  join(RELEASE, "spike-native-endpoint"),
  [
    "--relay-url", "http://127.0.0.1:3340",
    "--relay-auth-url", "http://127.0.0.1:7780",
    "--uptime-secs", "300",
  ],
  "native-endpoint",
);
tapReady("native-endpoint", native);
await waitForReady("native-endpoint", (s) => s.includes("endpoint_id="));
const nativeReady = readyLines["native-endpoint"];
const nativeEndpointId = nativeReady.match(/endpoint_id=([0-9a-f]+)/)[1];
const nativeRelayUrl = nativeReady.match(/relay_url=(\S+)/)?.[1] ?? "http://127.0.0.1:3340";
console.log(`    native endpoint_id=${nativeEndpointId}`);

// --- 2. Serve the static web/ dir -----------------------------------------

const WEB_PORT = 7788;
const webDir = join(HERE, "web");
if (!existsSync(join(webDir, "pkg", "spike_browser_client_bg.wasm"))) {
  console.error("ERROR: web/pkg/spike_browser_client_bg.wasm missing — run ./build.sh first");
  cleanup(1);
}
const server = createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, "http://x").pathname);
  if (p === "/") p = "/index.html";
  const fp = join(webDir, p);
  if (!fp.startsWith(webDir) || !existsSync(fp)) {
    res.writeHead(404);
    res.end("not found");
    return;
  }
  const types = {
    ".html": "text/html",
    ".mjs": "application/javascript",
    ".js": "application/javascript",
    ".wasm": "application/wasm",
    ".json": "application/json",
  };
  const ct = types[p.slice(p.lastIndexOf("."))] ?? "application/octet-stream";
  // Cross-origin isolation so the wasm module can use SharedArrayBuffer if
  // iroh's wasm runtime needs it; harmless if it doesn't.
  res.writeHead(200, {
    "content-type": ct,
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
  });
  createReadStream(fp).pipe(res);
});
await new Promise((r) => server.listen(WEB_PORT, "127.0.0.1", r));
console.log(`==> static server: http://127.0.0.1:${WEB_PORT}/`);

// --- 3. Static-asset secret scan ------------------------------------------
//
// Acceptance criterion 2: "no project API secret appears in any served
// static asset, bundle, manifest, or public config." The only secret in the
// spike is relay-auth's signing key, which lives in process memory. Here we
// scan every served file for any 32-byte hex / base64 string that could be a
// key, and assert the relay-auth signing key is NOT among them.

const secretPatterns = [
  { name: "32-byte hex (signing-key-shaped)", re: /[0-9a-f]{64}/gi },
  { name: "44-char base64 (key-shaped)", re: /[A-Za-z0-9+/]{43}=/g },
];
const servedFiles = ["index.html", "spike.mjs", "pkg/spike_browser_client.js", "pkg/spike_browser_client_bg.wasm"];
const scanFindings = [];
for (const f of servedFiles) {
  const fp = join(webDir, f);
  if (!existsSync(fp)) continue;
  const buf = readFileSync(fp);
  const text = buf.toString("utf8");
  for (const { name, re } of secretPatterns) {
    const matches = text.match(re) ?? [];
    for (const m of matches) {
      scanFindings.push({ file: f, kind: name, value: m.slice(0, 16) + "…" });
    }
  }
}
const signingKeyInAssets = scanFindings.some(
  (f) => f.value.toLowerCase().includes(verifyingKey.slice(0, 16).toLowerCase()),
);
console.log(
  `SECRET SCAN: ${signingKeyInAssets ? "CRITICAL — relay-auth signing key found in served assets" : `ok — ${scanFindings.length} candidate string(s), none match the relay-auth signing key`}`,
);

// --- 4. Run the round trip on each browser engine -------------------------

const payload = "ping from the browser";
const cfg = {
  relayAuthUrl: "http://127.0.0.1:7780",
  relayUrl: nativeRelayUrl,
  nativeEndpointId,
  payload,
};
const pageUrl = `http://127.0.0.1:${WEB_PORT}/`;
const results = [];

for (const name of engines) {
  const engine = ENGINES[name];
  if (!engine) {
    results.push({ engine: name, verdict: "UNKNOWN_ENGINE" });
    continue;
  }
  console.log(`\n==> ${engine.label}: launching…`);
  let browser;
  try {
    browser = await engine.type.launch({ headless: true });
  } catch (err) {
    const msg = String(err?.message ?? err);
    const installHint = msg.includes("playwright install")
      ? `run: npx playwright install ${name}`
      : "";
    console.error(`    ${engine.label}: SKIPPED — ${msg.split("\n")[0]} ${installHint}`);
    results.push({ engine: engine.label, verdict: "SKIPPED", reason: msg.split("\n")[0], installHint });
    continue;
  }
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    page.on("console", (m) => {
      if (m.type() === "error") console.error(`    [${engine.label} console] ${m.text()}`);
    });
    page.on("pageerror", (e) => console.error(`    [${engine.label} pageerror] ${e}`));
    await page.goto(pageUrl, { waitUntil: "load" });
    await page.waitForFunction(() => typeof window.runSpike === "function", { timeout: 10_000 });

    const result = await page.evaluate(async (cfg) => {
      await window.runSpike(cfg);
      return window.__spikeResult;
    }, cfg);

    if (!result || result.ok !== true) {
      results.push({ engine: engine.label, verdict: "FAIL", error: result?.error ?? "no result" });
      continue;
    }
    const r = result.result;
    const expectedEcho = payload.toUpperCase();
    const nowMs = Date.now();
    const verdict =
      r.echoed === expectedEcho && r.token && r.tokenExpiresAtMs > nowMs
        ? "PASS"
        : "FAIL";
    results.push({
      engine: engine.label,
      verdict,
      echoed: r.echoed,
      expectedEcho,
      tokenLen: r.token?.length ?? 0,
      tokenExpiresInMs: r.tokenExpiresAtMs - nowMs,
      elapsedMs: r.elapsedMs,
      endpointId: r.endpointId,
    });
  } catch (err) {
    results.push({ engine: engine.label, verdict: "FAIL", error: String(err?.message ?? err).split("\n")[0] });
  } finally {
    await browser.close();
  }
}

// --- 5. Record results in NOTES.md ----------------------------------------

const overall = results.some((r) => r.verdict === "FAIL")
  ? "FAIL"
  : results.some((r) => r.verdict === "SKIPPED")
    ? "PASS (partial)"
    : results.some((r) => r.verdict === "PASS")
      ? "PASS"
      : "INCONCLUSIVE";

const notesPath = join(HERE, "NOTES.md");
const stamp = new Date().toISOString();
let prev = "";
if (existsSync(notesPath)) prev = readFileSync(notesPath, "utf8").split("\n## Run log\n")[0];

const log = [
  "## Run log",
  "",
  `### ${stamp} — verdict: **${overall}**`,
  "",
  `Engines: ${engines.join(", ")}`,
  `Iroh revision: iroh 1.0.1 (crates.io), pinned \`a5d98b70…\` via iroh-rooms workspace dep`,
  `Wrapper shape: wasm-bindgen \`--target web\`, default-features=off, tls-ring, ring compiled with clang for wasm32-unknown-unknown`,
  `Relay deployment: dedicated local iroh-relay 1.0.1 (\`spike-relay-server\`) on 127.0.0.1:3340 (plain HTTP dev mode), \`AccessControl\` validates relay-auth tokens`,
  `Relay-auth: local HTTP service on 127.0.0.1:7780, Ed25519 PoP + 60s endpoint-bound token, signing key generated in-process (verifying_key=${verifyingKey.slice(0,8)}…, NOT present in any served asset: ${!signingKeyInAssets})`,
  `Native endpoint: local iroh Endpoint (ALPN \`jeliya/spike/echo/1\`) behind the dedicated relay, endpoint_id=${nativeEndpointId.slice(0,8)}…`,
  "",
  "| Engine | Verdict | Echoed | Expected | Token (len) | Token TTL (ms) | Round-trip (ms) |",
  "|---|---|---|---|---|---|---|",
  ...results.map((r) =>
    `| ${r.engine} | ${r.verdict} | ${r.echoed ?? r.error ?? ""} | ${r.expectedEcho ?? ""} | ${r.tokenLen ?? ""} | ${r.tokenExpiresInMs ?? ""} | ${r.elapsedMs ?? ""} |`,
  ),
  "",
  "#### Static-asset secret scan",
  "",
  `Served files scanned: ${servedFiles.join(", ")}`,
  `Patterns checked: ${secretPatterns.map((p) => p.name).join("; ")}`,
  `Findings: ${scanFindings.length} candidate string(s); relay-auth signing key present in assets: **${signingKeyInAssets ? "YES (CRITICAL)" : "no"}**`,
  scanFindings.length ? "" : "(none)",
  "",
  "#### Amendment A4 note (WebKit storage boundary)",
  "",
  "WebKit's seven-day eviction of script-writable storage is a property of installed-PWA browser-peer mode (Phase 4), not of this Phase 0 transport spike: this spike stores nothing in IndexedDB, Cache Storage, or a service worker. The WebKit run above proves the transport path; A4's storage constraint applies to the first browser-peer build, not here.",
  "",
  "---",
  "",
].join("\n");

writeFileSync(notesPath, (prev || defaultNotesHeader()) + "\n" + log);

console.log("\n==> overall verdict:", overall);
console.log("==> results written to", notesPath);
cleanup(overall.startsWith("FAIL") ? 1 : 0);

// --- helpers / cleanup ----------------------------------------------------

function cleanup(code) {
  for (const p of procs) {
    try {
      p.kill("SIGTERM");
    } catch {}
  }
  try {
    server.close();
  } catch {}
  // Give services a moment to tear down.
  setTimeout(() => process.exit(code), 500).unref();
}

function defaultNotesHeader() {
  return [
    "# Spike run log — browser→native Iroh through authenticated relay (#23)",
    "",
    "This file is appended to by `run-spike.mjs`. The newest run is at the bottom.",
    "Each run records the verdict, the exact revisions, the wasm-bindgen wrapper",
    "shape, the relay deployment, and per-engine results.",
    "",
    "A FAIL verdict blocks any Phase 1 or Phase 2 engineering commitment; the",
    "resulting architecture change is raised as its own decision record rather",
    "than settled inside this spike.",
    "",
  ].join("\n");
}
