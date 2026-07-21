---
type: "Runbook"
title: "Store-degraded runbook"
description: "Operator procedure for detecting and responding to a durable CRITICAL store_degraded trust decision (an accepted room event could not be persisted)."
tags: ["operations", "store", "store-degraded", "incident", "phase-1"]
timestamp: "2026-07-21T18:00:00Z"
status: "canonical"
implementation_status: "implemented"
verification_status: "partial"
release_status: "not-applicable"
audience: ["contributors", "maintainers", "operators"]
---

# Store-degraded runbook

This is the operator procedure for Phase 1 deliverable D7: detecting and
responding to a `store_degraded` trust decision. It discharges the D7 bullet of
the [Phase 1 implementation plan](phase-1-plan.md) and feeds the Phase 3
incident-runbook gate.

## What `store_degraded` means

`store_degraded` is a **durable, CRITICAL** trust decision the Iroh Rooms sync
engine records when an event that was *accepted* by the membership fold could
not be *persisted* to the local SQLite store after the bounded store-retry
budget exhausted (issue #119). It is raised by the pinned upstream revision
`a5d98b70...`, not by Jeliya.

- **Severity:** critical. The room's local state diverged from peers: an event
  was folded (and may have been pushed/broadcast) but is not durably stored, so
  a restart will not have it.
- **Durability:** the decision itself IS persisted (append-only, in
  `trust_decisions`), so it survives a daemon restart — that is the whole point.
- **Cause:** a store write failure — disk full, I/O error, store corruption, or
  the store held by another process. It is an operational durability failure,
  **not** a security breach or a signature/protocol fault.

## Detection

Query the room's health (Phase 1 D7):

```text
room.health  { room_id }
  → { decisions: [ { seq, code, severity, admin_seq, event_ids, created_at } ] }
```

A `code: "store_degraded"`, `severity: "critical"` row is the signal. The
`event_ids` list names the event(s) that could not be persisted. A healthy room
returns `decisions: []`. The decision is append-only: it never clears itself,
so a room that ever degraded stays flagged until the operator acts (below) and
re-creates the store.

The same surface also reports an admin-fork `equivocation` (critical) and an
`admin_view_suspect` (warning) — distinct causes, distinct responses, out of
scope for this runbook.

## Operator response

1. **Acknowledge and stop authoring.** Stop sending/inviting in the affected
   room. `store_degraded` means writes are not landing; further authoring
   widens the gap.
2. **Check disk and the store file.** Confirm `<data_dir>/rooms.db` and its
   WAL (`rooms.db-wal`, `rooms.db-shm`) are on a healthy, non-full volume:
   `df -h <data_dir>`; inspect `dmesg` / the filesystem for I/O errors.
3. **Free space / fix the volume, then restart.** Free disk space or remount
   the volume read-write, then restart `jeliyad`. On restart the engine
   re-syncs from peers: the missing event is fetched again from any peer (or
   an explicitly invited availability peer) that holds it. The durable
   `store_degraded` row remains until step 5.
4. **If the store is corrupt (not merely full)** — `rooms.db` fails to open or
   queries error — do NOT repair it in place:
   1. Stop the daemon and back up `<data_dir>/rooms.db*`.
   2. Back up the identity via `recovery.export` if you have not already
      (Phase 1 D1).
   3. Move the corrupt `rooms.db*` aside, then restart. The identity is
      unaffected (it lives in `identity.json` / `identity.secret`, not the
      store); the daemon re-creates an empty store and re-syncs room history
      from current peers as each room is reopened.
   4. Rejoin any room no current peer can serve from the invite ticket.
5. **Clear the flag** by confirming the room re-synced (a `room.timeline` read
   shows the previously-dropped event) and, once the operator is satisfied the
   store is healthy, starting from a clean store (step 4) so the append-only
   `store_degraded` row does not persist a stale alert.

## What the architecture cannot do

- It **cannot** recall an event no peer holds. If the dropped event was never
  replicated to another peer (or an availability peer), it is gone — the same
  boundary as any unreplicated local data (trust boundary TB4 in
  [Production deployment architecture](production-deployment.md#target-system-and-trust-boundaries)).
- It **cannot** make disk failure impossible. `store_degraded` fails loudly so
  the operator can act; it does not prevent the underlying outage.

## Citations

- [Phase 1 implementation plan](phase-1-plan.md) - deliverable D7 (surface `store_degraded` and define the operator response).
- [Production deployment architecture](production-deployment.md) - the `store_degraded` decision and the operator-response obligation.
- [Daemon protocol](PROTOCOL.md) - the `room.health` method.
