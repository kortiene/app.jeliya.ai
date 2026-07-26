---
type: "Decision"
title: "Desktop-operator-first scope — decision record"
description: "Defers the hosted browser plane: Phases 2 through 5 of the production deployment architecture are cut from the plan behind a named re-entry trigger, distribution stays the installed daemon, the companion control plane and its three crates are removed, and the desktop release gate becomes the project's only launch gate; states the preconditions any hosted re-entry must satisfy first and re-anchors the code-signing trigger that Phase 5 was carrying."
tags: ["decision", "scope", "roadmap", "deployment", "architecture", "distribution"]
timestamp: "2026-07-24T21:30:00Z"
status: "canonical"
implementation_status: "planned"
verification_status: "unverified"
release_status: "unreleased"
audience: ["maintainers", "contributors", "operators", "product"]
---

# Desktop-operator-first scope — decision record

**Status: DECIDED 2026-07-24 —** Jeliya is desktop-operator-first. Phases 2
through 5 of the [production deployment architecture](production-deployment.md)
— the companion-backed browser slice, production web and relay operations, the
browser Wasm peer with multi-device identity, and the signed component system
with optional server peers — are **deferred, not abandoned**, behind the
re-entry trigger stated below. Distribution stays "install `jeliyad`". The
companion control plane and its three crates are removed from the tree. This
record supersedes the adopted deployment architecture and its six amendments
for scope purposes only; it changes **nothing** about the daemon, the loopback
UI, the peer-to-peer core, the agent and fleet plane, the recovery bundle, or
the release-evidence pipeline. It does not discharge an issue: it closes four
epics and re-scopes six.

**How this record lands.** The sections below are stated in the present tense
because they state what is *decided*, which is settled the moment this record
is adopted. They are not a report of the tree's current state. The consequences
land in their own reviewable change sets, in this order, each verifiable
against the checklist at the end:

| Change set | Discharges |
|---|---|
| this record | the decision itself, and its index entry |
| the code removal | [Consequences — code](#consequences--code), in one commit, plus the mandatory link repairs and the ADR #2 re-pin |
| the document pass | [Consequences — documents](#consequences--documents) and [Carried forward](#carried-forward-before-anything-is-deleted) |
| the housekeeping pass | [issues, gates, and the signing trigger](#consequences--issues-gates-and-the-signing-trigger) |

Until the last of those merges, this record describes a decision in force whose
consequences are partly outstanding. That is the normal state of a decision
record between adoption and discharge, and the checklist is what closes it.

## Decision

1. **The product's front door is the installed daemon.** A user obtains Jeliya
   by installing `jeliyad`, which serves its own UI on loopback. There is no
   hosted application origin, no CDN-delivered shell, no service worker, and no
   browser-resident peer.
2. **Phases 2 through 5 are cut from the plan.** Every gate condition, ADR
   obligation and amendment that exists only to serve them goes dormant. The
   phase structure itself ends: Phase 1 was the last phase.
3. **The companion control plane is removed.** The crates `jeliya-protocol`,
   `jeliya-control` and `jeliya-companion`, the daemon module `companion.rs`,
   the five `--companion-*` flags, the `control_keys.json` on-disk format, and
   the browser-side control library under `ui/src/lib/control/` are deleted.
   The companion control wire protocol ceases to exist as a live contract.
4. **The desktop release gate is the only launch gate.** The eight exit
   criteria in [Known gaps and roadmap](known-gaps-roadmap.md) are promoted
   from "the next release" to the project's launch gate. The first-launch gate
   that governed the hosted origin is closed unfired.
5. **Deferral is recorded, not erased.** Every superseded record stays in the
   wiki marked `deprecated`, because a deferral's whole value is that the
   analysis survives for whoever re-enters. Nothing in this cut is deleted for
   tidiness.

## Why

The users this project is built for already have a complete product.
[`PRODUCT.md`](../PRODUCT.md) states them plainly: "technical operators — they
run daemons, invite peers, watch agent fleets, open pipes to local ports."
Those users install a binary today, and the released `v0.5.0` preview is
certified for real peer-to-peer operation by signed direct and forced-relay
evidence. Every remaining phase existed to remove one step — the install — for
a user the product does not currently claim.

The price of removing that step was never the engineering alone. It was:

- a staffing assumption the project does not meet. The adopted plan sizes
  Phases 2 through 5 against "two core/full-stack engineers, one
  web/operations engineer at least part-time, and an independent security
  review". Jeliya has one maintainer.
- standing spend before the first user, and a hard operating ceiling to
  administer, per the [relay load and cost ceilings
  record](relay-load-and-cost-ceilings-decision.md).
- a permanent operator role in which one individual holds the legal entity,
  the abuse contact, triage duty with stated response times, launch approval
  and the retention-owner seat, per the [trust, safety, and legal ownership
  record](trust-safety-and-legal-decision.md).
- a security-reviewed fork of the peer-to-peer engine, re-audited on every
  rebase, per the [portable traits record](iroh-rooms-portable-traits-decision.md).
- a second qualification pipeline. The signed cross-machine evidence harness is
  the heaviest standing operational item in the repository and it is what makes
  the honesty rules non-vacuous. One such pipeline is affordable for a solo
  maintainer. A second one, for a browser runtime, is not — and this is the
  strongest single argument for the cut.

Two facts about the current tree support the timing. The companion control
plane has never shipped, and the claim is checkable rather than asserted: the
three crates are **absent from the `v0.6.0` tagged tree**, which contains only
`jeliya-core`, `jeliya-ffi` and `jeliyad` — `jeliya-control` first appears in
`cdcae83` (PR #78) and `jeliya-companion` in `f51ae85` (PR #101). No published
release contains them either: `v0.5.0` is the last release actually built and
published, and per the [verification evidence](verification-evidence.md) the
public `v0.6.0` tag does not exist. The whole plane is reachable only behind
opt-in flags. And it does not currently work — issue #115 records that
`jeliyad --companion-control` never starts, because the bind path awaits an
endpoint readiness signal that does not arrive. The cut therefore removes
unreleased, non-functioning code and its two-language wire protocol, not a
capability any user has.

## What this decision does not change

Stated explicitly, because a scope cut invites over-reading:

- The peer-to-peer core, the signed event log, and the fold. Every view remains
  a replay over a tamper-evident log.
- The daemon protocol in [`PROTOCOL.md`](PROTOCOL.md), unchanged in every
  method, push and view-model.
- Identity, the room-scoped device keys, and the [recovery
  bundle](recovery-bundle-decision.md).
- The agent runner, the fleet read model, and their contracts.
- The release-evidence pipeline: the six required CI jobs, the dual conformance
  oracles for the daemon protocol, the manual promotion workflow, the sealed
  receipt, the cross-machine signed evidence, and the Ed25519 evidence key.
- **The compact and responsive UI shell.** It is retained on accessibility
  grounds, not phone grounds: it serves the WCAG 1.4.10 reflow target at
  320 CSS px / 400% zoom, which is a required check on the default branch and
  is independent of whether a phone can ever reach the daemon.
- The vulnerability-disclosure posture and the private reporting channel, which
  govern this repository and its released binaries.

## Re-entry trigger

The hosted plane is deferred, which means this record must say what would bring
it back. Any **one** of the following re-opens the question. Each is written to
be checkable by someone who was not in this decision:

1. **Capacity.** A second maintainer with web or operations capability joins and
   commits to the operator role — abuse triage, incident response, and the
   named deputy seat — for at least two release cycles.
2. **Evidenced demand.** The install step is named as the blocker by at least
   ten distinct would-be users in the issue tracker or the disclosure channel,
   recorded as such rather than inferred from silence.
3. **Funding.** Committed funding covers the standing infrastructure floor
   stated in the cost-ceilings record **and the cost of** the qualified legal
   review of the lawful-basis position.

   To be explicit, because these two are easy to conflate: what re-opens the
   question is funding that *covers* the review. What gates a hosted *launch*
   is the review being *completed*. Re-entry does not require the review to
   have happened first — it requires the means to obtain it — and the completed
   review re-enters as a pre-launch condition along with the plane, exactly as
   [recorded below](#consequences--issues-gates-and-the-signing-trigger).

Re-entry does not restore the old plan wholesale. It re-opens
[`production-deployment.md`](production-deployment.md) as the starting analysis,
subject to the preconditions in the next section.

## Preconditions on any hosted re-entry

These are the results the deferred work paid for. They are not plan; they are
constraints that a future hosted plane must satisfy before it is built, and
they are recorded here so re-entry starts from them rather than rediscovering
them.

- **The `room.join` confused-deputy invariant.** A browser controller must
  never be able to cause the device to author a signed membership event into a
  room the human did not name. In the deleted design this was enforced by
  absence: `room.join` had no method identifier on the control wire at all, so
  an attacker could not request what the wire could not represent. Any
  replacement must preserve enforcement by absence or something equally
  structural, plus human confirmation of the room at redemption.
- **Bounded authority for any second controller.** A non-extractable control
  key; a lifetime clamped to a stated finite range with no path to an unbounded
  key; default-deny scopes; and per-room binding. Authority granted to a
  browser is a grant, never an identity.
- **Fail-closed authorization in a fixed order.** The gateway chain is identity,
  then revocation, then expiry, then scope, then per-room binding, then replay —
  with **rate limiting charged separately and earlier**, on every request from
  an admitted key, before method lookup and parameter validation. The order is
  the invariant, not an implementation detail. Note for the record: the summary
  line in [`control-wire-protocol.md`](control-wire-protocol.md) states this
  order incorrectly and contradicts its own normative section further down; the
  normative section and the code are correct, and the summary was wrong.
- **A public-key identity is free to mint, so no limit keyed on it can bind.**
  Any admission control for a shared resource must anchor on something scarce.
  This result stands independently of the relay design that produced it.
- **A signature proves provenance, not harmlessness.** It applies to component
  packages, to update metadata, and to any signed artifact a future plane
  introduces.
- **Anti-rollback, key rollover, and fail-open are one design, not three.** A
  monotonic floor with a payload-hash comparison and idempotent equal-sequence
  handling; a rollover that does not trust only the outgoing key; and an
  unreachable-document path that fails open so an offline client is not
  bricked.

## Consequences — code

All of the following land together, because the workspace must compile and
`clippy -D warnings` must pass in one commit:

| Removed | Notes |
|---|---|
| `crates/jeliya-protocol`, `crates/jeliya-control`, `crates/jeliya-companion` | Workspace members drop from five to two. |
| `crates/jeliyad/src/companion.rs` and its `mod` declaration | Plus the four call sites in `main.rs`. |
| The five `--companion-*` flags and their argument-parsing tests | `--companion-control`, `--companion-pair`, `--companion-reset-pairings`, `--companion-list-pairings`, `--companion-revoke`. |
| `crates/jeliyad/Cargo.toml` companion dependencies | The three path dependencies, **and `blake3`, `zeroize` and `atomicwrites`** — each is used only inside `companion.rs` and becomes dead with it. |
| `ui/src/lib/control/` in full, with its committed Noise vector and golden wire corpus | No file outside that directory imports it. |
| The `control_keys.json` on-disk format | It has never existed on any user's disk, because the plane has never shipped. |

Third-party dependencies do **not** shrink. `aes-gcm`, `curve25519-dalek`,
`sha2` and `subtle` all reach the daemon through `jeliya-core` and the
peer-to-peer engine regardless. What is removed is the hand-written Noise state
machine, the SAS ceremony, the ordered gateway, and the pairing and persistence
code — and one wire protocol maintained byte-identically in two languages.

## Consequences — documents

Superseded records are marked `deprecated` and **retained**. The profile
defines that status as "retained for history or link continuity; readers must
follow its replacement", which is exactly the intent here. No superseded record
is deleted.

| Document | Disposition |
|---|---|
| [Production deployment architecture](production-deployment.md) | Deprecated, retained whole. It is the re-entry artifact, and its Phase 3 and Phase 4 bodies carry navigation links that other retained records depend on. |
| [Production deployment decision](production-deployment-decision.md) | Deprecated. Amendments A1 through A6 go dormant; A1's invariant is carried forward above. |
| [Production deployment architecture review](production-deployment-review.md) | Deprecated, retained as the verified finding set behind the amendments. |
| [Relay load and cost ceilings](relay-load-and-cost-ceilings-decision.md) | Deprecated. |
| [Relay-auth admission rule](relay-auth-admission-rule-decision.md) | Deprecated. Its admission result is carried forward above. |
| [Hostile-frontend containment](hostile-frontend-containment-decision.md) | Deprecated. Its anti-rollback and fail-open design is carried forward above. |
| [Trusted Types policy allowlist](trusted-types-policy-decision.md) | Deprecated. |
| [Portable Iroh Rooms traits](iroh-rooms-portable-traits-decision.md) | Deprecated. Its short-lived-audited-patch rule is retained as dependency policy in [Dependency fork policy](verification-evidence.md#dependency-fork-policy). |
| [Companion control protocol decision](companion-control-protocol-decision.md) | Deprecated. See the review-pin note below — this file cannot be left untouched. |
| [Companion control wire protocol](control-wire-protocol.md) | Deprecated, **retained**. It is the remediation artifact that closed a blocker finding in the Phase 1 security review, and the only specification of the wire being removed. |
| [Provider selection](provider-selection-decision.md) | Reduced in place: the DNS, CDN, edge-token, relay and object-store rows go dormant; the native-signing row survives. |
| [Production ownership](production-ownership.md) | Reduced in place: the zone, CDN, relay and edge-token custody rows go dormant; the repository and signing rows survive. |
| [Supported platform matrix decision](platform-matrix-decision.md) | Reduced in place to its desktop-OS axis, which remains live. |
| [Platform matrix](platform-matrix.md) | Reduced in place: browser and mobile columns go dormant. |
| [Security and threat model](security-threat-model.md) | Reduced in place, and **gains** the carried-forward invariants and architectural limits from this record. |
| [Trust, safety, and legal ownership](trust-safety-and-legal-decision.md) | Reduced in place. The takedown-limit statement and both named human dependencies survive; origin-publication mechanics go dormant. |
| [Hosted-origin vulnerability disclosure](vulnerability-disclosure-decision.md) | Reduced in place. The disclosure path, advisory commitment and enabled private reporting all survive; the `security.txt` serving requirement and the two named hosted trust boundaries go dormant. |
| [Code-signing deferral](signing-deferral-decision.md) | Reduced in place with a **new trigger** — see below. |
| [Capability status](capability-status.md) | The companion control-protocol row is restated as historical, not deleted: implemented under Phase 1 D5a, removed by this decision, with the removal commit. |
| [Known gaps and roadmap](known-gaps-roadmap.md) | Updated: the exit criteria are promoted to the launch gate, and it receives the carried-forward gaps listed below. |
| [`SECURITY.md`](../SECURITY.md) | Reduced in place: the affected-component list drops the companion ALPN and the relay-auth worker; everything else stands. |
| [`docs/index.md`](index.md) | Gains an archived-plane section and an entry for this record. Existing entries for the deprecated records stay — several documents elsewhere in the wiki reach the index only through those lines. |

## Carried forward before anything is deleted

Each of these is a durable engineering result whose only current home is a
document being deprecated. Each must land in its new home **in the same change
set**, or it survives only in Git history:

- **Owner removal via a signed `member.removed` event.** The only written design
  for it lives in the agent-marketplace proposal, and it is an independently
  tracked protocol gap, not a marketplace feature. **Landed:**
  [Carried-forward gaps](known-gaps-roadmap.md#carried-forward-gaps).
- **The architectural limits.** Signatures prevent forgery but not copying;
  revocation cannot recall material a peer already received; a recovery bundle
  restores identity authority and not unreplicated blobs. They are the
  product's differentiator and must survive every future cut. **Landed:**
  [Architectural limits](security-threat-model.md#architectural-limits), a
  standing section in the threat model.
- **The invite residual-disclosure list**, including the channels that fire with
  no user action. **Landed:** [Invite-ticket residual
  disclosure](security-threat-model.md#invite-ticket-residual-disclosure).
  Re-anchored on arrival: the two no-user-action channels were conditional on a
  join **URL**, which desktop-first does not have — invites are ticket strings
  copied to the clipboard — so they are restated as a standing constraint on any
  future URL-borne delivery rather than a present exposure. The four
  clipboard-and-screenshot channels are live today.
- **Why the loopback daemon must not be public** — the complete constructional
  argument, which is now the boundary statement for the only surface that
  exists. **Landed:** [Why the loopback daemon must not be
  public](security-threat-model.md#why-the-loopback-daemon-must-not-be-public).
  The "two honest limits" paragraph, which was stranded inside the now-dormant
  hosted-boundaries section and is sharper than the carried text, moved up with
  it.
- **Recovery finding F7:** re-export does not rotate, so every prior recovery
  key stays valid indefinitely. A named limitation of a shipped feature.
  **Landed:** [Carried-forward gaps](known-gaps-roadmap.md#carried-forward-gaps).
- **The `room.timeline` limit clamp.** The upper bound was defined only in a
  crate being deleted; the daemon's own path has no cap. **Landed:**
  [Carried-forward gaps](known-gaps-roadmap.md#carried-forward-gaps), with the
  fix specified to land in `jeliya-core`.
- **The cross-implementation conformance method** — one committed golden corpus
  exercised by both implementations — as the project's standard for any future
  second implementation. **Landed:** [Conformance
  method](verification-evidence.md#conformance-method). Recorded there rather
  than in `PROTOCOL.md`, which is the more natural home but sits in the Phase 1
  review's reopen set; adding a documentation section is not worth reopening a
  closed security review.
- **The short-lived-audited-patch rule** for any dependency fork: short-lived by
  rule, not by hope. **Landed:** [Dependency fork
  policy](verification-evidence.md#dependency-fork-policy).
- **The open operator action** to point the distribution repository's security
  file at the centralized intake. **Landed:** [Carried-forward
  gaps](known-gaps-roadmap.md#carried-forward-gaps), recorded as an open
  operator action rather than an engineering task.

## Consequences — issues, gates, and the signing trigger

**Closed as won't-do:** the four phase epics (#43, #50, #51, #55), the WebKit
storage-boundary amendment (#53), and the companion bind defect (#115), whose
subject ceases to exist.

**Moot:** the four blocked ADR decisions — multi-device authorization and
revocation semantics (#52), the browser signing strategy (#54), whether server
peers may read content (#56), and component metadata and trust roots (#57).

**Re-scoped:** signing procurement (#25), the review-gate assessors (#36), the
Phase 1 epic's companion deliverables (#38), the non-visual pairing and wordlist
work (#40), version-skew measurement (#41), and the frontend literal-scan
widening (#42). **The build-pipeline trust boundary (#39) becomes more important,
not less** — with distribution as the only channel, the build and release
pipeline is the trust boundary that matters most.

**The code-signing trigger is re-anchored.** The deferral currently fires "after
Phase 5", a condition that can now never be met, which would defer signing
permanently by accident. Its replacement: **the signing gate fires before the
first release published without the technical-preview label.** Until then,
archives ship with SHA-256 sidecars that detect corruption but do not
authenticate against a trusted root, and the installers' verified-checksum
behaviour remains the enforced contract.

**Both named human dependencies survive the cut.** A qualified legal review of
the lawful-basis position and a named deputy were pre-launch conditions for the
hosted origin. The legal review is no longer a launch blocker, because the
project processes no user data on infrastructure it operates; it re-enters with
the plane. The deputy remains an open single-point-of-failure on the repository
and release keys, and should be tracked as such rather than closed with the
phase.

## Carve-outs — residue that only looks like the hosted plane

Recorded because a later cleanup pass will otherwise get these wrong:

- **`app.jeliya.ai` is baked into a key-derivation context.** It occurs exactly
  once in the Rust tree, inside `ROOM_DEVICE_KDF_CONTEXT_V1` in
  `crates/jeliya-core/src/identity.rs` — the versioned BLAKE3 `derive_key`
  context for room-scoped device keys — and it is mirrored in the [room device
  key decision](room-device-key-decision.md). It is a **domain-separation
  constant, not an origin reference**, and the `v1` in its name is the migration
  seam: changing the string is a key-version change, never a rename. **Do not
  find-and-replace it.** Changing it re-derives every room-scoped device key,
  which changes each room's `EndpointId` and its invite-discovery semantics.

  Stated precisely, because the blast radius is smaller than it looks and the
  overclaim would be caught: room-scoped device keys are **not yet released**
  (the [room device key decision](room-device-key-decision.md) carries
  `release_status: "unreleased"`; the feature landed in PR #94, `4206984`, after
  the `v0.6.0` tag was cut). So today the damage is confined to trees built from
  `main`, not to any published install. That is an argument for fixing the
  constant's status *now* rather than for treating it as harmless — it becomes
  genuinely irreversible on the first published release that contains it. The
  repository slug is likewise a repository name, not an origin.
- **The relay-connect spike under `spike/` is retained**, alongside its recorded
  [Phase 0 result](evidence/phase-0-relay-spike.md), as re-entry evidence. It is
  not dead hosted code to be swept.
- **The daemon does emit one Content-Security-Policy header**, on the
  peer-supplied file download path. It is a live daemon control and must not be
  removed with the hosted header set.
- **The compact UI shell, the mobile tab bar, and the 320 px e2e specs stay.**
  See "What this decision does not change".

## The review pin, and why one edit is unavoidable

The companion control protocol decision is content-pinned by hash in the [Phase
1 security review scope](phase-1-security-review-scope.md), where any edit is
declared a post-adoption change that reopens review. That pin cannot be honoured
here: several retained audit documents link to a source file inside a crate
being deleted, and the documentation gate fails on a link to a path that no
longer exists. The link repairs are therefore mandatory, and the pinned file is
among them.

The resolution is to make the edit deliberate rather than incidental: repair the
links mechanically — convert each to an inline code span, leaving the surrounding
sentences byte-identical — mark the record `deprecated` in the same edit, and
**re-pin the hash in the same change**, with an explicit note that the change
carries no semantic content. A reviewer must be able to confirm that by diff.

## Verification

This decision is complete when:

- [ ] `node scripts/check-docs.mjs` passes. It must pass in **every** change
      set, not only at the end, because it is a required gate on the default
      branch. The one change set that breaks it is the code removal, which
      deletes the crate that eight audit-chain links point into: one in the
      companion control protocol decision, two Phase 1 gate-verdict references,
      and five in the Phase 1 security review — plus a sixth link in that last
      file which the gate masks today under its four-space indented-code rule
      and which is repaired with the others. Those repairs therefore land in the
      code-removal change set, not here.
- [ ] `cargo clippy --locked --workspace --all-targets -- -D warnings` and
      `cargo test --locked --workspace` pass with the three crates, the daemon
      module, the five flags and the argument-parsing tests removed together.
- [ ] The UI build and its browser regression suite pass with
      `ui/src/lib/control/` removed, and the 320 px reflow checks still pass.
- [ ] Every item under "Carried forward before anything is deleted" has landed
      in its new home, verifiable by link from this record.
- [ ] The security-review scope hash is re-pinned, with the no-semantic-content
      note.
- [ ] `docs/index.md` reaches this record, and no document is orphaned.
- [ ] **Fresh signed network evidence is generated against the final source
      commit.** Removing three crates changes the candidate, and certified
      evidence binds one exact revision pair — it never transfers across
      commits. The retained direct and forced-relay manifests therefore stop
      certifying the tree the moment this decision lands, and a signed direct
      run plus a signed forced-relay run bound to the post-deletion source
      commit are required before the next release. This is the longest-lead item
      in the change set: it needs the operator workstation and the remote hosts,
      not CI.

      Note the ordering this implies, so it is not read as a contradiction: the
      manifests are written under `docs/evidence/` **after** the runs complete,
      so the commit that carries the evidence is necessarily a later commit than
      the source commit the evidence certifies. That is the normal flow, not a
      defect. What must match is the revision pair recorded *inside* each
      manifest and the source commit being qualified — not the commit the
      manifest file happens to land in.
