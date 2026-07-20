// THROWAWAY Phase 0 spike (#23) — browser bootstrap.
//
// Loads the wasm module built by `wasm-pack build --target web` from
// ../browser-client/pkg/, and exposes window.runSpike(config) so both the
// manual button on the page and the Playwright spec can drive a round trip.
//
// The page asserts NOTHING about the result here — Playwright does. This file
// only loads the module, wires up the DOM, and surfaces the result (or error)
// on window.__spikeResult so a test harness can read it after the run.

import init, { run_spike_roundtrip } from "./pkg/spike_browser_client.js";

const statusEl = document.getElementById("status");
const resultEl = document.getElementById("result");
const runBtn = document.getElementById("run");

// Expose for Playwright BEFORE awaiting init, so the harness can poll
// window.__spikeResult === "pending" → object even if init is slow.
window.__spikeResult = null;

let ready = init();
window.__spikeReady = ready;

async function runSpike(cfg) {
  window.__spikeResult = "pending";
  statusEl.textContent = "initializing wasm…";
  try {
    await ready;
    statusEl.textContent = "running round trip…";
    const result = await run_spike_roundtrip(cfg);
    window.__spikeResult = { ok: true, result };
    statusEl.textContent = "done";
    statusEl.className = "ok";
    resultEl.textContent = JSON.stringify(result, null, 2);
    return result;
  } catch (err) {
    const msg = String(err?.message ?? err);
    window.__spikeResult = { ok: false, error: msg };
    statusEl.textContent = "FAILED";
    statusEl.className = "fail";
    resultEl.textContent = msg;
    throw err;
  }
}

// Exposed for both the manual button and the Playwright harness.
window.runSpike = runSpike;
window.__spikeVersion = {
  // Recorded for the evidence doc. wasm-pack stamps these into the JS shim;
  // the orchestrator reads window.__spikeVersion after a run.
  iroh: "iroh 1.0.1 (default-features=off, tls-ring)",
  wrapper: "jeliya/spike/echo/1 over wasm-bindgen --target web",
};

runBtn.addEventListener("click", () => {
  const cfg = {
    relayAuthUrl: document.getElementById("relayAuthUrl").value,
    relayUrl: document.getElementById("relayUrl").value,
    nativeEndpointId: document.getElementById("nativeEndpointId").value.trim(),
    payload: document.getElementById("payload").value,
  };
  runSpike(cfg).catch(() => {});
});
