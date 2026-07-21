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
certifying direct and forced-relay evidence. The current `v0.6.0` source
candidate repins `iroh-rooms` to untagged upstream revision `a5d98b70...`, the
first `main` merge carrying the provisional-peer and store-degradation fixes.
It is locally qualified and network-qualified at `922f620…` + `a5d98b70…`
(signed direct `098c4979` and forced-relay `8bda01e6` runs), but not yet
published. Signed runs at
the earlier `55024a4...` + `71fbb500...` snapshot remain valid for that exact
pair and do not transfer to the current dependency.

## Snapshot boundary

| Field | Value |
|---|---|
| Released milestone | `v0.5.0 — Evidence-Backed Technical Preview`, published 2026-07-14 as a prerelease: five daemon+embedded-UI archives with `.sha256` sidecars |
| Current source candidate | `922f620b30ee95c82426a7d4404b1f73a70c0958` with Iroh Rooms `a5d98b70d717f35d3ce60953a88e12e646f2e871` |
| Last network-qualified `v0.6.0` snapshot | Jeliya `55024a46b3e112796ba2acf1dc408dab26dbba2e` with Iroh Rooms `71fbb5007bef4ce83631c94762ec68c2beef3d79` (tag `v0.1.0-rc.3`) |
| Retained certified evidence | signed schema 2 direct (`1ca39cfa`) and forced-relay (`cf28bc63`) runs of 2026-07-16; valid for the last network-qualified snapshot only |
| Candidate `iroh-rooms` pin | `a5d98b70d717f35d3ce60953a88e12e646f2e871` — deliberately untagged first merge carrying the `kortiene/iroh-room#121` and `kortiene/iroh-room#119` fixes plus `kortiene/iroh-room#126` follow-ups; later `main` changes only an unconsumed CLI crate |
| Candidate verification | exact-revision upstream fanout, isolation, and store-degradation tests pass; full Jeliya workspace and 67-assertion loopback suites pass. Fresh signed direct and forced-relay evidence is required |
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
| Identity, room create/join/open, membership, and messages | implemented | certified direct and relay pass for `v0.5.0` and for the current `922f620…` + `a5d98b70…` candidate; current pin passes local integration | released in `v0.5.0` | Known `v0.5.0` limitation: an invite minted after non-admin chat cannot complete `room.join`. The current candidate fixes this and passes all 67 loopback assertions, and the current-pin direct and relay network runs certify it. |
| Files and BLAKE3 fetch verification | implemented | certified direct and relay pass for `v0.5.0` | released in `v0.5.0` | Cross-network transfer, byte equality, and hash verification passed in both certifying runs. |
| Pipes | implemented | certified direct and relay pass for `v0.5.0` | released in `v0.5.0` | Authorized transfer, closure, and zero target bytes from the unauthorized third peer passed in both certifying runs. |
| Direct cross-network P2P | implemented | certified for `v0.5.0`, the prior `v0.6.0` snapshot, and the current candidate | released in `v0.5.0` | [Signed schema 2 direct run `098c4979`](evidence/v0.6.0/direct.json) certifies `922f620…` + `a5d98b70…` (operator linux arm64 over `AS11426`; remotes `demo1`/`demo2` over `AS24940`). The superseded run `1ca39cfa` certified only `55024a4…` + `71fbb500…`. |
| Deliberately forced relay | published seam pinned; verifier chain forwards through jeliya-core | certified for `v0.5.0`, the prior `v0.6.0` snapshot, and the current candidate | released in `v0.5.0` | [Signed schema 2 relay run `8bda01e6`](evidence/v0.6.0/relay.json) certifies `922f620…` + `a5d98b70…` (operator linux arm64; remotes `demo1`/`demo2`); the relay-only source build self-attested on all three hosts. The superseded run `cf28bc63` certified only `55024a4…` + `71fbb500…`. |
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
