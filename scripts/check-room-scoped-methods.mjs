#!/usr/bin/env node
// Room-scoped method-list drift gate. No npm dependencies.
//
// "Which methods are room-scoped" is a security-relevant set: every method in
// it must cross the default-deny accepted-room preflight before touching
// room-derived state. It was written down in several places that drifted apart
// silently — the engine preflighted 19, while the release gate, that gate's own
// test, and the network-evidence harness each enumerated 17, all three omitting
// `room.health` and `invite.cancel`. Nothing failed, because nothing compared
// them. The signed release evidence therefore certified foreign-room
// non-disclosure for 17 of the 19 methods that claim it.
//
// This gate makes that class of drift impossible to reintroduce quietly:
// scripts/room-scoped-methods.json is the single source of truth, and the
// engine's own allowlist is the oracle it is checked against. Adding a
// room-scoped method to the engine without adding it here fails CI.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

/** The method names inside `requires_room_access_preflight` in engine.rs. */
export function enginePreflightMethods(source) {
  const fn = source.match(
    /fn\s+requires_room_access_preflight\s*\([^)]*\)\s*->\s*bool\s*\{([\s\S]*?)\n\}/,
  );
  if (!fn) return null;
  return [...fn[1].matchAll(/"([a-z][a-z_]*\.[a-z][a-z_]*)"/g)].map((m) => m[1]).sort();
}

export function checkRoomScopedMethods(root) {
  const failures = [];

  let declared;
  try {
    declared = JSON.parse(readFileSync(join(root, "scripts/room-scoped-methods.json"), "utf8"));
  } catch (err) {
    return [`scripts/room-scoped-methods.json: could not read or parse: ${err.message}`];
  }

  const listed = declared.methods;
  if (!Array.isArray(listed) || listed.length === 0) {
    return ["scripts/room-scoped-methods.json: `methods` must be a non-empty array"];
  }
  const sortedListed = [...listed].sort();
  if (JSON.stringify(listed) !== JSON.stringify(sortedListed)) {
    failures.push("scripts/room-scoped-methods.json: `methods` must be sorted, so diffs stay readable");
  }
  if (new Set(listed).size !== listed.length) {
    failures.push("scripts/room-scoped-methods.json: `methods` contains duplicates");
  }

  let engineSource;
  try {
    engineSource = readFileSync(join(root, "crates/jeliya-core/src/engine.rs"), "utf8");
  } catch (err) {
    // Fail closed: an unreadable oracle is not a pass.
    return [...failures, `crates/jeliya-core/src/engine.rs: could not read: ${err.message}`];
  }

  const engine = enginePreflightMethods(engineSource);
  if (engine === null) {
    return [
      ...failures,
      "crates/jeliya-core/src/engine.rs: could not find `fn requires_room_access_preflight` — "
        + "if it was renamed, update this gate rather than deleting it",
    ];
  }

  const missingHere = engine.filter((m) => !sortedListed.includes(m));
  const missingThere = sortedListed.filter((m) => !engine.includes(m));
  for (const method of missingHere) {
    failures.push(
      `${method}: crosses the engine's room-access preflight but is absent from `
        + "scripts/room-scoped-methods.json — every consumer of that file would under-verify it",
    );
  }
  for (const method of missingThere) {
    failures.push(
      `${method}: listed in scripts/room-scoped-methods.json but the engine does not preflight it — `
        + "either the engine lost a guard or the list names a method that no longer exists",
    );
  }

  // `room.join` must never acquire a preflight: its authorization object is the
  // key-bound ticket, and the caller is not a member until redemption succeeds.
  if (engine.includes("room.join")) {
    failures.push(
      "room.join: must NOT require the accepted-room preflight — it is the documented exemption, "
        + "and preflighting it would make joining a room require already being in it",
    );
  }

  for (const legacy of declared.legacy_manifest_sets ?? []) {
    const unproven = (legacy.unproven ?? []).slice().sort();
    const gap = sortedListed.filter((m) => !(legacy.methods ?? []).includes(m)).sort();
    if (JSON.stringify(unproven) !== JSON.stringify(gap)) {
      failures.push(
        `legacy manifest set "${legacy.id}": its \`unproven\` field says [${unproven.join(", ")}] `
          + `but the actual gap against the current set is [${gap.join(", ")}] — `
          + "that field is the record of what retained signatures do not prove and must stay exact",
      );
    }
  }

  return failures;
}

// Only when run as a command; importing this module must have no side effects.
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const failures = checkRoomScopedMethods(repoRoot);
  if (failures.length > 0) {
    console.error(`room-scoped-methods: ${failures.length} finding(s)\n`);
    for (const failure of failures) console.error(`  ${failure}`);
    process.exit(1);
  }
  console.log(
    "room-scoped-methods: OK — the committed set matches the engine's own preflight allowlist.",
  );
}
