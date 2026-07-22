---
type: "Status Report"
title: "Capability status"
description: "Evidence-aware capability matrix for the v0.5.0 technical-preview candidate and the latest public release."
tags: ["capabilities", "release", "status", "verification"]
timestamp: "2026-07-20T13:55:00Z"
status: "canonical"
implementation_status: "partial"
verification_status: "partial"
release_status: "partial"
audience: ["contributors", "maintainers", "operators", "release-engineers"]
---

# Capability status

This page separates implementation, verification, and public availability.
`v0.5.0` shipped on 2026-07-14 as a daemon-only prerelease backed by signed,
certifying direct and forced-relay evidence. The post-release source candidate
on `main` pins `iroh-rooms` at the untagged upstream revision `a5d98b70...`
(the first merge carrying the provisional-peer and store-degradation fixes) and,
on top of that, carries the Phase 1 protocol primitives; the exact current
revision and which signed runs bind which pair are in the Snapshot boundary
table below (the table is the authoritative reference, since the prose would
otherwise go stale each merge). The candidate is not yet published. Network
qualification binds the pre-Phase-1 candidate `922f620…` + `a5d98b70…` (signed
direct `098c4979`, forced-relay `8bda01e6`) and does not transfer to the current
`main` HEAD, which needs fresh signed runs. Signed runs at the earlier
`55024a4...` + `71fbb500...` snapshot remain valid for that exact pair only.

## Snapshot boundary

| Field | Value |
|---|---|
| Released milestone | `v0.5.0 — Evidence-Backed Technical Preview`, published 2026-07-14 as a prerelease: five daemon+embedded-UI archives with `.sha256` sidecars |
| Current source candidate | `d610076c05f0f29cb8f87c7dbe805a5f603ecc89` (public `main`; pre-Phase-1 `922f620…` plus PR #78, remediation PRs #80–#85, and the delta-reviewed verdict-conditions PR #89; interleaved `main` commits are docs-only governance records) with Iroh Rooms `a5d98b70d717f35d3ce60953a88e12e646f2e871` |
| Last network-qualified `v0.6.0` snapshot | Jeliya `922f620b30ee95c82426a7d4404b1f73a70c0958` (the pre-Phase-1 candidate; signed direct `098c4979` + relay `8bda01e6` bind it — does not transfer to the current `d610076` candidate). Prior: `55024a46b3e112796ba2acf1dc408dab26dbba2e` with Iroh Rooms `71fbb5007bef4ce83631c94762ec68c2beef3d79` (tag `v0.1.0-rc.3`) |
| Retained certified evidence | signed schema 2 direct (`098c4979`) and forced-relay (`8bda01e6`) runs binding the pre-Phase-1 candidate `922f620…` + `a5d98b70…`; the earlier `1ca39cfa`/`cf28bc63` runs bound `55024a4…` + `71fbb500…` and are superseded. None transfer to the current `d610076` candidate |
| Candidate `iroh-rooms` pin | `a5d98b70d717f35d3ce60953a88e12e646f2e871` — deliberately untagged first merge carrying the `kortiene/iroh-room#121` and `kortiene/iroh-room#119` fixes plus `kortiene/iroh-room#126` follow-ups; later `main` changes only an unconsumed CLI crate |
| Candidate verification | exact-revision upstream fanout, isolation, and store-degradation tests pass; full Jeliya workspace and 67-assertion loopback suites pass at `922f620…`. At the current `d610076` candidate (`cdcae83` Phase 1 primitives plus remediation PRs #80–#85 and conditions PR #89), Phase 1 deliverables D1/D2/D3/D4/D5a/D7 are implemented and locally tested (127 Rust tests, clippy clean under `-D warnings`, UI + docs gates; PR #78 run `29868870066` — a `pull_request` run at branch head `e9f1ed5` — plus merge-SHA push runs `29922951249` at `df28f6a` and `29951799090` at `d610076`). Fresh signed direct and forced-relay evidence bound to `d610076` is still required; the Phase 1 gate is closed — row #7 APPROVE-WITH-CONDITIONS with [risk-owner GO recorded 2026-07-22](phase-1-gate-verdict.md#go-decision--risk-owner-countersignature-2026-07-22), approval [extended to `d610076`](phase-1-security-review.md#conditions-delta-review-2026-07-22) |
| Historical network verification | schema 1 runs at Jeliya `fe870c7…` with local upstream `3702e8c…`, and the schema 2 preview run at `0f6769a…` with pre-remediation pin `3cb9bfd…`; functional evidence only |
| Status captured | release and evidence snapshot 2026-07-19 23:30 UTC; branch-protection required-check state (#20) verified separately 2026-07-20 13:55 UTC |

See [Release versus main](release-vs-main.md) for the revision boundaries and
[Verification evidence](verification-evidence.md) for the complete ledger.
The released `v0.5.0` pins `d0ceb0b…`, which predates upstream's
join-after-conversation fix: an invite minted after any non-admin chat cannot
complete `room.join` on `v0.5.0` — the current repin carries that fix plus the
later provisional-peer and store-degradation fixes. Mixed `v0.5.0`/candidate
rooms cannot complete joins in either direction, so a room's members,
especially its admin, must move together.

## Capability matrix

| Capability | Implementation | Verification | Public release | Honest current claim |
|---|---|---|---|---|
| `jeliyad` with embedded React UI | implemented | certified for `v0.5.0` | released in `v0.5.0` (prerelease) | The complete five-target daemon+embedded-UI archive set with `.sha256` sidecars is published. Signed schema 2 direct and forced-relay runs certified the released revision pair. |
| Identity, room create/join/open, membership, and messages | implemented | certified direct and relay pass for `v0.5.0` and for the pre-Phase-1 `922f620…` + `a5d98b70…` candidate; current pin passes local integration | released in `v0.5.0` | Known `v0.5.0` limitation: an invite minted after non-admin chat cannot complete `room.join`. The pre-Phase-1 candidate fixed this and passes all 67 loopback assertions, and the `922f620…`-pin direct and relay network runs certify it. The current `d610076` candidate carries that fix forward but is not network-certified there. |
| Files and BLAKE3 fetch verification | implemented | certified direct and relay pass for `v0.5.0` | released in `v0.5.0` | Cross-network transfer, byte equality, and hash verification passed in both certifying runs. |
| Pipes | implemented | certified direct and relay pass for `v0.5.0` | released in `v0.5.0` | Authorized transfer, closure, and zero target bytes from the unauthorized third peer passed in both certifying runs. |
| Direct cross-network P2P | implemented | certified for `v0.5.0`, the prior `v0.6.0` snapshot, and the pre-Phase-1 candidate | released in `v0.5.0` | [Signed schema 2 direct run `098c4979`](evidence/v0.6.0/direct.json) certifies `922f620…` + `a5d98b70…` (operator linux arm64 over `AS11426`; remotes `demo1`/`demo2` over `AS24940`). The superseded run `1ca39cfa` certified only `55024a4…` + `71fbb500…`. Does not transfer to the current `d610076` candidate. |
| Deliberately forced relay | published seam pinned; verifier chain forwards through jeliya-core | certified for `v0.5.0`, the prior `v0.6.0` snapshot, and the pre-Phase-1 candidate | released in `v0.5.0` | [Signed schema 2 relay run `8bda01e6`](evidence/v0.6.0/relay.json) certifies `922f620…` + `a5d98b70…` (operator linux arm64; remotes `demo1`/`demo2`); the relay-only source build self-attested on all three hosts. The superseded run `cf28bc63` certified only `55024a4…` + `71fbb500…`. Does not transfer to the current `d610076` candidate. |
| Public room-scoped RPC isolation | implemented | verified locally and in both certifying runs | released in `v0.5.0` | A centralized guard covers the public room-scoped surface. Seventeen negative RPC checks, local-file denial, and aggregate filtering passed over the public network in the certifying runs. |
| Upstream synchronization and provisional-peer isolation | remediated at current pin `a5d98b70…` | targeted isolation, provisional-fanout, and store-degradation regressions pass; core/net all-targets suite passes 806 tests with two ignores | released baseline in `v0.5.0`; new fixes unreleased | Local exact-revision evidence covers the upstream internals. Fresh signed network evidence is still required for Jeliya integration at the new pin. |
| Agent runner and fleet | implemented | local pass | released as source through `v0.5.0` | Agent E2E passes; the earlier fleet stability run passed 5/5. Linux orphan/zombie process-group cleanup was verified on `demo1` under UID `65534`. |
| Dependency security | gates implemented | Cargo and npm report zero vulnerabilities | release gates passed for `v0.5.0` | Four unmaintained/yanked dependency warnings have documented owners, mitigations, and expiry; no reachable unresolved high/critical vulnerability is accepted. |
| CI matrix | implemented | the daemon-only six-job matrix passed twice at the frozen candidate `922f620…` — push run `29713108134` and `workflow_dispatch` run `29713781499`, every job green on first attempt; the earlier run `29688515781` at `a24f223…` covered the then-current matrix only | exercised for `v0.5.0` | Six jobs are defined: `docs-ui`, `ui-e2e`, `rust-runtime`, `msrv`, `windows-installer`, and `dependency-security`; since #20 all six are required status checks on `main`. Together they cover the documentation profile, release and installer contracts, TypeScript units and browser regressions, Rust format/clippy/tests, daemon smoke, sidecar, agent, fleet, and TypeScript protocol conformance against the real daemon, the MSRV floor, Windows installer integrity, and Cargo/npm advisories. |
| Unix installer integrity | implemented | behavioral checks pass | released in `v0.5.0` | Unix installers fetch and verify the matching sidecar before extraction; `v0.5.0` installs via the version-pinned installer path. |
| Windows installer integrity | implemented | hosted `windows-latest` job passes on `main` | released in `v0.5.0` | The Windows job executes checksum/tamper behavior, simulates reparse-point rejection, and runs native `jeliyad.exe --version`; a `v0.5.0` Windows zip and sidecar are published. |
| Complete asset-set visibility and version consistency | implemented | executed for `v0.5.0` | released in `v0.5.0` | The publication workflow validated, sealed, smoked, and receipt-verified the complete five-archive set; the evidence key is provisioned and the signed evidence passed the release gate before publication. |
| WCAG 2.1 AA | partial | automated gate on every pull request; manual checklist per release | partial | Enforced, not certified. CI rejects any critical or serious axe violation across every destination at 1440x900, 920x800, 390x844 and 320x568, and fails on clipped layout at the 320 CSS px / 400%-zoom reflow target (WCAG 1.4.10) in English and French; `docs/accessibility-checklist.md` covers the screen-reader and keyboard behaviours automation cannot decide. Since #20, `ui-e2e` — check context "UI browser regression (Playwright)" — is a required status check on `main`, so a critical or serious violation blocks the merge. Still not a conformance claim: OS-level text-scale coverage lapsed with the native client and has no browser equivalent, and the manual checklist remains hand-verified per release. |
| OKF-compatible documentation | implemented | locally checked; reconciled to the released `v0.5.0`, prior signed snapshot, and current untagged candidate | released posture documented | The profile separates lifecycle, implementation, verification, and release status. |
| Recovery bundle + at-rest encryption (Phase 1 D1) | implemented | local tests pass (round-trip, tamper/wrong-key rejection, fresh-install restore, encrypted-not-plaintext); CI green on PR #78 | unreleased | `recovery.export`/`restore`/`test_restore` seal identity seeds in a versioned AES-256-GCM bundle keyed by a random 256-bit recovery key (ADR #3); `identity.secret` is sealed with Argon2id-derived AEAD under `JELIYA_IDENTITY_PASSWORD` (auto-detected on load). NOT network-certified at `d610076`; OS keystore backends (D1c) deferred. |
| Message idempotency + timeline cursor (Phase 1 D2/D3) | implemented | local tests pass (10k-retry dedup; cursor resync matches full materialization incl. concurrent authoring); CI green on PR #78 | unreleased | `message.send` accepts a `client_msg_id` (daemon-local dedup, survives restart); `room.timeline` takes `after_event_id` + returns `next_cursor`. Daemon-local exactly-once; cross-peer awaits an upstream content field. |
| Invite default expiry + cancellation (Phase 1 D4) | implemented | local tests pass (expired/cancelled tickets fail; fold rejects a cancelled redeem); CI green on PR #78 | unreleased | Omitted `expiry` now defaults to 24h; `invite.cancel` authors `member.removed`, consuming the invite (a later redeem fails `ticket_expired`). Cancellation is eventual like all signed-log state. |
| Companion control-protocol core (Phase 1 D5a) | implemented | local tests pass (replay/wrong-SAS/expired-key/revoked-key fail closed); CI green on PR #78 | unreleased | New `crates/jeliya-control`: pairing transcript + ~32-bit SAS, non-extractable bounded-lifetime control key (A1), default-deny scopes, sliding replay window, revocation (ADR #2). Wire transport + browser side + daemon wiring are Phase 2 (D5b). |
| `store_degraded` surfacing (Phase 1 D7) | implemented | local test passes (seeded CRITICAL decision surfaced; durable across restart); CI green on PR #78 | unreleased | `room.health` returns the persisted trust decisions; the [store-degraded runbook](store-degraded-runbook.md) defines the operator response. |

## Preview publication rule

`v0.5.0` published only `jeliyad` with its embedded web UI, after all required
daemon target gates passed — the rule held. The project is daemon-only, and a
separately packaged agent runner remains out of scope until its own gates are
satisfied.

No row becomes `verified` because code exists, and no row becomes `released`
because it is on a branch. For the next release the same bar applies to the
current candidate: fresh signed network evidence at `a5d98b70...`, passing
hosted gates, a matching tag, a complete verified artifact set, and explicit
release authority. See
[Known gaps and roadmap](known-gaps-roadmap.md).
