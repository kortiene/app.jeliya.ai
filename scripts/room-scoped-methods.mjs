// The committed room-scoped method set, as a module, so every consumer reads
// the same bytes rather than keeping its own copy. The JSON file next to this
// one is the source of truth; scripts/check-room-scoped-methods.mjs gates it
// against `requires_room_access_preflight` in crates/jeliya-core/src/engine.rs.
//
// This module exists because the previous arrangement — each consumer with its
// own inline array — is exactly what drifted: the engine preflighted 19 methods
// while three separate enumerations each listed 17, and nothing compared them.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const declared = JSON.parse(readFileSync(join(here, "room-scoped-methods.json"), "utf8"));

/**
 * Every daemon-protocol method whose params carry a `room_id` and which must
 * therefore cross the accepted-room preflight. Sorted, frozen.
 *
 * `room.join` is deliberately NOT here: its authorization object is the
 * key-bound ticket, and the caller is not a member until redemption succeeds.
 */
export const ROOM_SCOPED_METHODS = Object.freeze([...declared.methods]);

/**
 * Method sets used by evidence manifests that predate the current set. These
 * exist only because retained manifests carry detached signatures over their
 * exact bytes: they cannot be regenerated, so a gate that only knows the
 * current set would reject signed history. Each entry records, in `unproven`,
 * precisely which methods those signatures do NOT cover.
 */
export const LEGACY_ROOM_SCOPED_METHOD_SETS = Object.freeze(
  (declared.legacy_manifest_sets ?? []).map((set) =>
    Object.freeze({
      id: set.id,
      unproven: Object.freeze([...(set.unproven ?? [])]),
      methods: Object.freeze([...(set.methods ?? [])]),
    }),
  ),
);
