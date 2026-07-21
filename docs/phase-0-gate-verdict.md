---
type: "Decision"
title: "Phase 0 go/no-go gate verdict"
description: "Dated verdict against each of the six Phase 0 go/no-go gate conditions for the v0.6.0 candidate (922f620 + a5d98b70), each with linked evidence. Discharges issue #31."
tags: ["phase-0", "decision", "release", "verification", "governance"]
timestamp: "2026-07-21T14:10:00Z"
status: "canonical"
implementation_status: "not-applicable"
verification_status: "verified"
release_status: "not-applicable"
audience: ["contributors", "maintainers", "release-engineers", "security-reviewers"]
---

# Phase 0 go/no-go gate verdict

**Verdict: GO — 2026-07-21.** All six Phase 0 go/no-go gate conditions
([Production deployment architecture](production-deployment.md) Phase 0
go/no-go gate) pass for the current candidate Jeliya
`922f620b30ee95c82426a7d4404b1f73a70c0958` + Iroh Rooms
`a5d98b70d717f35d3ce60953a88e12e646f2e871`, each with recorded evidence.
Phase 1 may begin. The six amendments in the
[Production deployment decision](production-deployment-decision.md) are binding
on the later phase gates they name, not on Phase 0; they are listed at the foot
of this record so none is mistaken for a Phase 0 condition.

This record discharges
[issue #31](https://github.com/kortiene/app.jeliya.ai/issues/31). It records a
verdict at a point in time; it does not advance any implementation,
verification, or release status beyond what the linked evidence already carries.

## Candidate under verdict

| Field | Value |
|---|---|
| Jeliya source candidate | `922f620b30ee95c82426a7d4404b1f73a70c0958` |
| Iroh Rooms pin | `a5d98b70d717f35d3ce60953a88e12e646f2e871` |
| Verdict date (UTC) | 2026-07-21 |

## The six gate conditions

### 1. No contradictory release claim remains — PASS

The status and evidence documents were reconciled to one consistent claim set
(the current candidate `922f620…` + `a5d98b70…` is locally and network
qualified; the release-evidence gate is READY; the retained
`55024a4…` + `71fbb500…` runs are labelled historical/superseded). Documents
checked:

- [Verification evidence](verification-evidence.md) — `verification_status: "verified"`, `Release evidence gate | READY`.
- [Capability status](capability-status.md), [Platform matrix](platform-matrix.md), [Release versus main](release-vs-main.md), [Known gaps and roadmap](known-gaps-roadmap.md), [Real-network NAT runbook](realnet-runbook.md) — each cites the current pair as qualified.

No page asserts a contradictory "pending" or "does not transfer" claim about
the current candidate. The one remaining "current candidate pending" is
macOS-specific network certification, which the linux/arm64-qualified runs do
not claim to cover; it is not a contradiction of the candidate-level claim.

### 2. `Cargo.toml` and `Cargo.lock` both resolve Iroh Rooms `a5d98b70…` — PASS

- [`Cargo.toml`](../Cargo.toml) line 15: `iroh-rooms = { git = "https://github.com/kortiene/iroh-room", rev = "a5d98b70d717f35d3ce60953a88e12e646f2e871", features = ["experimental"] }`.
- [`Cargo.lock`](../Cargo.lock): the `iroh-rooms`, `iroh-rooms-core`, and `iroh-rooms-net` entries each record `source = "git+https://github.com/kortiene/iroh-room?rev=a5d98b70d717f35d3ce60953a88e12e646f2e871#a5d98b70d717f35d3ce60953a88e12e646f2e871"`.

### 3. Named upstream regressions and Jeliya's join/loopback suite pass at that revision — PASS

The provisional-peer fanout, connection-generation teardown, synchronization
isolation, and store retry/degradation regressions pass at `a5d98b70…`, with
Jeliya's 67-assertion join/loopback suite, recorded in
[Verification evidence](verification-evidence.md) (local exact-revision
qualification) and [Known gaps and roadmap](known-gaps-roadmap.md) (upstream
synchronization row). These upstream-internal regressions are exercised by the
detached local upstream suite, not by the network runs.

### 4. Complete CI passes twice on one immutable SHA — PASS

The daemon-only six-job CI matrix passed twice at
`922f620b30ee95c82426a7d4404b1f73a70c0958`, every job green on first attempt
with no rerun:

- push run `29713108134`;
- `workflow_dispatch` run `29713781499`.

Recorded in [Known gaps and roadmap](known-gaps-roadmap.md) (CI completeness
row). The earlier run `29699530741` at `105744b…` covered the then-current
matrix only and is not evidence for `922f620…`.

### 5. Direct and forced-relay evidence signed and bound to that SHA and `a5d98b70…` — PASS

- Direct: [signed schema 2 manifest `098c4979`](evidence/v0.6.0/direct.json) + [signature](evidence/v0.6.0/direct.json.sig); `source.commit = 922f620…`, `source.iroh_rooms.resolved_revision = a5d98b70…`, `certifiable: true`, 36/36 assertions across three peers, three distinct egresses, two ASNs.
- Forced relay: [signed schema 2 manifest `8bda01e6`](evidence/v0.6.0/relay.json) + [signature](evidence/v0.6.0/relay.json.sig); same binding; the relay-only source build self-attested on the operator host and both remotes, and A/B/C each remained relay for three consecutive observations.

Both detached Ed25519 signatures verify against
[`release/evidence-ed25519-public.pem`](../release/evidence-ed25519-public.pem),
and `validateEvidenceReadiness({ version: "0.6.0" })` returns `{ ready: true }`.

### 6. A browser reaches a native test endpoint through an authenticated relay — PASS

[Phase 0 relay-connect spike result](evidence/phase-0-relay-spike.md)
(issue [#23](https://github.com/kortiene/app.jeliya.ai/issues/23)): Chromium,
Firefox, and WebKit each obtained a short-lived (60 s), endpoint-bound
credential from a relay-auth service after Ed25519 proof of possession and
completed a bidirectional, end-to-end-encrypted round trip through a dedicated
authenticated relay. Verdict PASS.

## Mixed-version fleet boundary

The coordinated fleet-upgrade / mixed-version condition
([issue #26](https://github.com/kortiene/app.jeliya.ai/issues/26), closed) is
stated in the Phase 0 gate and in the published limitation docs: mixed
`v0.5.0`/candidate rooms cannot complete joins in either direction, so a room's
members — especially its admin — must move together. This is a stated launch
constraint, not a Phase 0 gate blocker.

## Phase 1

Phase 1 may begin: every gate condition above carries linked evidence. The
plan states no phase starts implementation work that depends on an unresolved
gate from the previous phase
([Production deployment architecture](production-deployment.md),
dependency-ordered roadmap); none of the six Phase 0 conditions remains open.

## Amendments are not Phase 0 conditions

The six amendments in the
[Production deployment decision](production-deployment-decision.md) are binding
on the phase gates they name, not on Phase 0. They are listed here (against the
plan's "What this record authorizes" and each amendment's "Blocks:" line) so
none is mistaken for a Phase 0 condition:

| Amendment | Blocks |
|---|---|
| A1 — bound the companion's authority to what the browser may name | Phase 1 gate |
| A3 — companion update path and measurable version skew | Phase 2 gate |
| A5 — accessibility and localization in scope for every new surface | Phase 2 gate |
| A2 — contain a hostile frontend, not merely replace it | Phase 3 gate |
| A6 — name trust-and-safety and legal owners before public launch | Phase 3 gate |
| A4 — state the WebKit storage boundary | Phase 4 gate |

## Out of scope

- Apple Developer enrollment and Windows Authenticode procurement
  ([issue #25](https://github.com/kortiene/app.jeliya.ai/issues/25)) are Phase 0
  *deliverables* (calendar lead time for Phase 2 signing), not Phase 0 *gate
  conditions*; their state is tracked on #25, not here. Phase 0 exit for #25
  requires enrollment SUBMITTED, which is not yet recorded.
- macOS-specific network certification at the current pin is not a Phase 0 gate
  condition; the current candidate is qualified via a linux/arm64 operator and
  `x86_64-unknown-linux-musl` remotes.
- Publication of `v0.6.0` is a later release-promotion action under explicit
  release authority, not a Phase 0 gate condition.

## Citations

- [Production deployment architecture](production-deployment.md) — Phase 0 deliverables and the six-condition go/no-go gate.
- [Production deployment decision](production-deployment-decision.md) — "What this record authorizes"; the six amendments and the gates they block.
- [Verification evidence](verification-evidence.md) — candidate identity table, certifying runs, and `Release evidence gate | READY`.
- [Signing and notarization](signing-notarization.md) — the Phase 0 procurement state tracked on #25.
