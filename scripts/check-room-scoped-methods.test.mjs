import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { checkRoomScopedMethods, enginePreflightMethods } from "./check-room-scoped-methods.mjs";
import { ROOM_SCOPED_METHODS, LEGACY_ROOM_SCOPED_METHOD_SETS } from "./room-scoped-methods.mjs";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/** A throwaway repo whose two inputs the caller controls. */
function fixture({ methods, legacy, engine }) {
  const root = mkdtempSync(join(tmpdir(), "jeliya-rsm-"));
  mkdirSync(join(root, "scripts"), { recursive: true });
  mkdirSync(join(root, "crates/jeliya-core/src"), { recursive: true });
  writeFileSync(
    join(root, "scripts/room-scoped-methods.json"),
    JSON.stringify({ methods, legacy_manifest_sets: legacy ?? [] }, null, 2),
  );
  writeFileSync(
    join(root, "crates/jeliya-core/src/engine.rs"),
    `fn requires_room_access_preflight(method: &str) -> bool {\n    matches!(\n        method,\n        ${engine
      .map((m) => `"${m}"`)
      .join("\n            | ")}\n    )\n}\n`,
  );
  return root;
}

test("the committed repository passes its own gate", () => {
  assert.deepEqual(checkRoomScopedMethods(repoRoot), []);
});

test("the engine allowlist is the oracle, and it is parsed correctly", () => {
  const source = readFileSync(join(repoRoot, "crates/jeliya-core/src/engine.rs"), "utf8");
  const parsed = enginePreflightMethods(source);
  assert.ok(parsed, "requires_room_access_preflight must be locatable");
  assert.deepEqual(parsed, [...ROOM_SCOPED_METHODS].sort());
  assert.equal(parsed.includes("room.join"), false, "room.join is the documented exemption");
});

test("a method the engine preflights but the list omits fails — the original drift", () => {
  // This is precisely the defect that shipped: the engine guarded room.health
  // and invite.cancel while three separate enumerations omitted them.
  const root = fixture({
    methods: ["message.send", "room.open"],
    engine: ["message.send", "room.open", "room.health", "invite.cancel"],
  });
  try {
    const failures = checkRoomScopedMethods(root);
    assert.equal(failures.length, 2);
    assert.match(failures.join("\n"), /room\.health: crosses the engine's room-access preflight/);
    assert.match(failures.join("\n"), /invite\.cancel: crosses the engine's room-access preflight/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a method the list names but the engine no longer preflights fails", () => {
  const root = fixture({
    methods: ["message.send", "room.open"],
    engine: ["message.send"],
  });
  try {
    assert.match(
      checkRoomScopedMethods(root).join("\n"),
      /room\.open: listed in scripts\/room-scoped-methods\.json but the engine does not preflight it/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("room.join acquiring a preflight fails loudly", () => {
  const root = fixture({
    methods: ["room.join", "room.open"],
    engine: ["room.join", "room.open"],
  });
  try {
    assert.match(
      checkRoomScopedMethods(root).join("\n"),
      /room\.join: must NOT require the accepted-room preflight/,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an unsorted or duplicated list fails, so diffs stay readable", () => {
  const root = fixture({ methods: ["room.open", "message.send"], engine: ["room.open", "message.send"] });
  try {
    assert.match(checkRoomScopedMethods(root).join("\n"), /must be sorted/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
  const dup = fixture({ methods: ["room.open", "room.open"], engine: ["room.open"] });
  try {
    assert.match(checkRoomScopedMethods(dup).join("\n"), /contains duplicates/);
  } finally {
    rmSync(dup, { recursive: true, force: true });
  }
});

test("a legacy set whose `unproven` field drifts from the real gap fails", () => {
  // That field is the record of what retained signatures do NOT prove. If it
  // silently goes stale, the gate stops telling the truth about signed history.
  const root = fixture({
    methods: ["message.send", "room.health", "room.open"],
    engine: ["message.send", "room.health", "room.open"],
    legacy: [{ id: "old", unproven: [], methods: ["message.send", "room.open"] }],
  });
  try {
    assert.match(
      checkRoomScopedMethods(root).join("\n"),
      /legacy manifest set "old".*actual gap against the current set is \[room\.health\]/s,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the recorded legacy gap matches what the retained manifests actually probe", () => {
  const legacy = LEGACY_ROOM_SCOPED_METHOD_SETS.find((s) => s.id === "pre-2026-07-26-seventeen");
  assert.ok(legacy, "the pre-drift manifest set must stay recorded");
  assert.deepEqual([...legacy.unproven].sort(), ["invite.cancel", "room.health"]);

  for (const file of [
    "docs/evidence/v0.6.0/direct.json",
    "docs/evidence/v0.6.0/relay.json",
    "docs/evidence/v0.5.0/direct.json",
    "docs/evidence/v0.5.0/relay.json",
  ]) {
    const manifest = JSON.parse(readFileSync(join(repoRoot, file), "utf8"));
    const denied = manifest.functional_evidence?.foreign_room_non_disclosure?.rpc_methods_denied;
    assert.deepEqual(
      denied,
      [...legacy.methods],
      `${file} must match the recorded legacy set exactly — its signature covers these bytes`,
    );
  }
});

test("a fail-closed gate: an unreadable engine is not a pass", () => {
  const root = mkdtempSync(join(tmpdir(), "jeliya-rsm-empty-"));
  mkdirSync(join(root, "scripts"), { recursive: true });
  writeFileSync(
    join(root, "scripts/room-scoped-methods.json"),
    JSON.stringify({ methods: ["room.open"] }),
  );
  try {
    assert.match(checkRoomScopedMethods(root).join("\n"), /could not read/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
