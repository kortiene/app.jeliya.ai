---
type: "Decision"
title: "Room-scoped device keys — decision record (issue #91)"
description: "Adopts deterministic per-room device keys derived from the profile device seed with a versioned BLAKE3 derive_key context, dispatched through the room's signed membership binding, plus a collision guard for legacy rooms bound to the global profile device. Fixes multi-room live-receive collision without persisting new secrets or changing the recovery bundle."
tags: ["identity", "rooms", "transport", "security", "decision", "issue-91"]
timestamp: "2026-07-22T00:00:00Z"
status: "canonical"
implementation_status: "complete"
verification_status: "tested"
release_status: "unreleased"
audience: ["contributors", "maintainers", "security-reviewers"]
---

# Room-scoped device keys — decision record (issue #91)

**Status: ADOPTED and implemented** in
[`identity.rs`](../crates/jeliya-core/src/identity.rs)
(`SecretKeys::room_device`) and
[`supervisor.rs`](../crates/jeliya-core/src/supervisor.rs)
(`room_bound_device`, `close_colliding_live_sessions`).

## Problem

`iroh-rooms` unifies transport, signing, and ACL identity: a room node's QUIC
`EndpointId` **is** its device key, inbound admission authorizes on
`Connection::remote_id()`, and peers dial each active member's device id.
`jeliyad` runs one `Node` per open room but historically spawned every one
from the single global profile device key. Two rooms open at once therefore
presented one `EndpointId`, remote traffic was routed to whichever node bound
last, and every earlier-opened room silently stopped receiving live events
(issue #91).

## Decision

1. **One device key per room, derived — not persisted.** The room-scoped
   device seed is
   `BLAKE3::derive_key(context_v1, device_seed || room_id_bytes)`, where
   `context_v1` is the immutable string
   `"jeliya.ai app.jeliya.ai 2026-07-22 room device seed v1"`, `device_seed`
   is the profile's 32-byte device seed, and `room_id_bytes` is the raw
   32-byte room-id digest. The derivation is **versioned by the context
   string**: any change requires a new v2 context plus legacy dispatch; a
   pinned test vector (`room_device_kdf_v1_vector_is_pinned`) trips if v1
   ever drifts.
2. **The signed membership log picks the key.** Every room-bound flow
   (node spawn, event authoring, invite-ticket discovery, file-provider
   lists, pipes, fetch self-filtering) resolves its signing/transport key via
   `room_bound_device`: read the device the room's membership fold binds for
   this identity, and use the derived key when it matches, the global profile
   device when the room predates this decision (legacy), and fail closed on
   anything else. No local marker file is consulted, so resolution survives a
   recovery restore into an empty data dir.
3. **Collision guard for legacy rooms.** Legacy rooms keep the global device
   and can still collide with each other. Before a room node binds its
   endpoint, `spawn_node` predicts the node's `EndpointId` from the resolved
   key and explicitly closes any other live session already presenting it
   (with a warning), so exactly one room owns a contended id and switching
   rooms re-binds deterministically. Non-colliding rooms are never touched.
   The guard runs pre-spawn, so no double-bind window exists at all.

## Why derived instead of persisted (the sibling `jeliya` daemon persists)

The sibling daemon stores a random per-room seed in `state.json`. This
repository deliberately diverges, because two Phase-1 guarantees would break:

- **`identity.secret` is the only secret-bearing file** and the only one the
  D1b at-rest password envelope seals. Random per-room seeds in `state.json`
  would create plaintext key material outside that envelope.
- **The D1 recovery bundle carries only the profile seeds.** Persisted room
  seeds would be unrecoverable after a restore (the member's bound device
  would be lost, making every room read-only), or would force a bundle format
  bump — and even then rooms joined after an export would be missing.
  Derived keys reproduce from the restored device seed for **every** room,
  including rooms joined after the export
  (`restored_identity_reproduces_room_device_keys`).

Trade-off accepted: two live installs restored from one bundle would derive
identical room devices and collide with each other — but running one identity
on two simultaneously live daemons is already outside the supported model,
and the same collision existed globally before this change.

## Compatibility

- **Wire/protocol:** none. `sender.device_id` in timeline events was always
  "the signing device"; it now varies per room instead of repeating the
  profile device. Invite tickets keep the same shape; their `discovery` entry
  now names the room-bound device (the id a joiner must actually dial).
- **Legacy rooms** (membership bound to the global device before this fix)
  stay fully usable — readable, authorable, joinable — but only one of them
  can be live at a time (the guard closes the older collider explicitly).
  Migrating one to a room-scoped key requires re-join/re-create, or a future
  upstream device-rotation event.
- **Re-join re-keys the device, and `file.shared` provider records are signed
  at share time** — a pre-rebind record names an endpoint id no live node
  presents after the migration. `file.fetch` and `file.list` therefore
  resolve providers against the CURRENT membership bindings
  (`current_provider_devices`): recorded devices that are still bound pass
  through; a stale one is replaced by the sharer's currently bound device
  (the blob lives in the sharer's daemon store, and its open session serves
  the room's blob dir regardless of which key authored the share).

## Regression coverage

`supervisor.rs`:
`two_open_rooms_receive_concurrently_on_distinct_endpoint_ids_loopback`
(two rooms, two daemons, four-way publish/receive with both rooms held open),
`legacy_rooms_sharing_the_global_device_cannot_both_stay_open`,
`legacy_and_new_format_rooms_stay_open_together`,
`open_room_fails_closed_when_the_bound_device_is_not_reproducible`,
`stale_file_provider_records_remap_to_the_sharers_current_device`;
`identity.rs`: `room_device_keys_are_room_scoped_and_deterministic`,
`room_device_kdf_v1_vector_is_pinned`;
`recovery.rs`: `restored_identity_reproduces_room_device_keys`.
