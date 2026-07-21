---
type: "Decision"
title: "Production deployment architecture — decision record"
description: "Adopts the capability-aware hybrid architecture and the companion-backed first slice for app.jeliya.ai, subject to six binding amendments drawn from the adversarial review."
tags: ["architecture", "deployment", "decision", "security", "roadmap", "governance"]
timestamp: "2026-07-20T13:20:00Z"
status: "canonical"
implementation_status: "planned"
verification_status: "partial"
release_status: "unreleased"
audience: ["contributors", "maintainers", "product", "release-engineers", "security-reviewers"]
---

# Production deployment architecture — decision record

**Status: DECIDED 2026-07-19 — Jeliya adopts the capability-aware hybrid
architecture described in [Production deployment
architecture](production-deployment.md), with the companion-backed shell as the
first production slice at `https://app.jeliya.ai`. The adoption is subject to
the six amendments in this record, which are binding on the phase gates they
name.**

This record discharges the Phase 0 item "accept or reject the hybrid
architecture through an ADR". It does not authorize a production deployment,
and it does not advance any implementation, verification, or release status.

## Decision

1. `app.jeliya.ai` serves an immutable static PWA. `jeliyad` is never exposed
   through a public listener or reverse proxy, and no public-listen flag,
   proxied `/ws`, or remotely reused daemon token is acceptable.
2. The first production release pairs that PWA with a signed local companion
   over a new mutually authenticated, end-to-end-encrypted Iroh control
   protocol.
3. A browser-resident Wasm room peer follows only after browser storage,
   signing, synchronization, and Iroh Rooms adapters pass independent gates.
4. Dedicated relays route encrypted traffic and never join rooms.
5. Optional server peers use distinct identities and are explicitly invited.
   Under the current protocol a server peer can read the room content it
   receives; a content-blind server requires a new application-encryption
   layer and is out of scope for the first slice.

The alternatives are rejected for the reasons recorded in the proposal's
deployment-model comparison: a hosted gateway would replace Jeliya's privacy
and local-first boundaries with server trust, and a browser-only peer cannot be
built today because the repository contains neither its storage nor its network
runtime.

### The companion is not the deleted native client

The companion is a headless, signed local process, not a graphical
application. Removing the Flutter client (`app/`), the Dart client
(`dart/jeliya_protocol`), and the mobile FFI shim (`crates/jeliya-ffi`) does
not remove any component this decision depends on. `jeliyad` already has the
companion's shape, and `.github/workflows/release.yml` already produces the
five archives it needs. The remaining companion work is the control protocol,
pairing, and signing — not a client rewrite.

## Evidence this decision rests on

- The proposal, assessed against the tree and recorded in [Production
  deployment architecture](production-deployment.md).
- The adversarial review in [Production deployment architecture
  review](production-deployment-review.md): 138 claims checked and found
  accurate, 78 findings surviving verification, 47 refuted and dropped, and a
  verdict recommending adoption subject to six amendments.
- The current dependency pin and its local requalification, recorded in
  [Known gaps and roadmap](known-gaps-roadmap.md) and [Capability
  status](capability-status.md).

Signed direct and forced-relay network qualification at the current revision
pair is **pending** and remains a Phase 0 gate. This record does not treat the
older signed manifests as transferring to it.

## Amendments

These six amendments are binding. Each names the gate it blocks. Work inside a
phase may proceed before its amendment is closed, but the phase's go/no-go gate
does not pass until it is.

### A1. Bound the companion's authority to what the browser may name

**Blocks: the Phase 1 gate.** This is a design change, not a documentation
change, and it must land in the scope model before the pairing protocol is
specified.

Two paths in the proposal grant the browser more authority than the scope list
admits:

- **`room.join` is a confused deputy.** It appears in neither the default-scope
  list nor the separate-approval list, yet joining is explicitly inside the
  first slice. `requires_room_access_preflight` in
  [`engine.rs`](../crates/jeliya-core/src/engine.rs) deliberately exempts
  `room.join` — "its authorization object is the key-bound ticket, and the
  caller is not a room member until redemption succeeds" — so there is no
  existing guard to inherit. A compromised origin can mint an identity-bound
  ticket into a room it controls and have the paired companion redeem it with
  the root identity's authority, producing a signed `member.joined` from the
  victim's device key and disclosing the victim's endpoint to attacker peers.
  Identity binding does not close this: it prevents ticket theft, not
  attacker-chosen rooms.
- **The browser control key's extractability is unspecified.** The proposal
  mandates non-extractability for the browser *identity* key, which does not
  exist in the first slice, and says nothing about the *control* key, which is
  what actually authorizes the companion to act. An extractable control key
  makes a single origin compromise permanent and off-origin: it survives the
  frontend rollback, the CSP, and the service-worker update.

The decision requires: an explicit redemption scope with human confirmation of
the room being joined; a non-extractable browser control key; and a bounded
maximum control-key lifetime, expressed as a duration rather than "expire".

### A2. Contain a hostile frontend, not merely replace it

**Blocks: the Phase 3 gate.**

The 15-minute rollback objective bounds when clean bytes become *available*,
not when hostile code stops *running*. A malicious service worker keeps serving
its own cached shell until the browser fetches a byte-different worker script,
and an installed PWA that is not navigated may not re-check for up to 24 hours.
`Clear-Site-Data: "storage"` — the one header that unregisters service workers
on the origin — is absent from the proposal's header set, and the signed kill
switch is scoped to component metadata only, with none for the web shell.

The decision requires: `Clear-Site-Data` in the production header set, a kill
switch covering the web shell, and a rollback objective stated in terms of
hostile-code termination rather than pointer flip.

### A3. Specify the companion update path and measure version skew

**Blocks: the Phase 2 gate.**

The web origin auto-updates; the companion does not. The proposal's entire
treatment is a one-line minimum-safe version enforcement, with no upgrade
prompt, no grace window, and no way to measure how many users a hard fail would
strand — companion version is not in the allowed telemetry. The repository
already records the real-world shape of this failure: mixed pre- and
post-repin fleets cannot complete joins, so joiners and admins must upgrade
together.

The decision requires: a stated auto-update channel or an explicit decision
that there is none; an in-browser upgrade prompt; a grace window before
minimum-safe enforcement hard-fails; and a companion-version bucket in the
allowed metrics so the stranded fraction is measurable *before* enforcement is
enabled.

### A4. State the WebKit storage boundary before promising browser-peer mode

**Blocks: the Phase 4 gate.**

On WebKit — all Safari, and every browser on iOS — script-writable storage
(IndexedDB, Cache Storage, service-worker registrations) is deleted after seven
days of browser use without user interaction with the origin. That is every
storage tier browser-peer mode depends on. Home-screen-installed web
applications run on their own use counter and are exempt.

The decision requires: browser-peer mode on iOS is supported only for
home-screen-installed PWAs; a non-installed Safari tab is treated as companion
mode; and this is stated in the product copy, not only in the risk register.

### A5. Accessibility and localization are in scope for every new surface

**Blocks: the Phase 2 gate.**

The proposal adds pairing, invite, recovery, storage, and quota interfaces and
never mentions accessibility or internationalization. The repository enforces
both. The concrete hole is mechanical: `LITERAL_SCAN_ROOTS` in
[`check-ui-i18n.mjs`](../scripts/check-ui-i18n.mjs) covers only
`ui/src/App.tsx` and `ui/src/components`, while the proposal places new
user-facing copy in `ui/src/pairing/`, `ui/src/invites/`, and `ui/src/storage/`
— outside the scan. Copy written there would ship untranslated with green CI.

The decision requires: widening `LITERAL_SCAN_ROOTS` to cover every new
frontend area in the same change that creates it; EN/FR catalog entries for all
new copy, budgeted as real translation work; and an accessibility gate in the
new pull-request gate set alongside the security gates.

### A6. Name the trust-and-safety and legal owners before public launch

**Blocks: the Phase 3 gate, which is the first production launch gate.**

The proposal plans a public messaging product with an EU relay and 72-hour log
retention, and contains no regulatory framing and no user-safety model beyond a
single "block/report tools" bullet with no recipient, triage owner, or duty.
Its own architecture states the constraint that makes this urgent: signatures
prevent forgery but not copying, and a revocation "cannot recall material
already received."

The decision requires: a named abuse contact and triage owner; a stated
retention and lawful-basis position for the relay and log data; and an explicit
statement of what the architecture can and cannot do about content already
distributed.

## Findings discharged since the review

Three of the review's twelve high-severity findings no longer apply to the
current tree. They are recorded here so the ledger is not re-litigated:

| Finding | Status | Evidence |
|---|---|---|
| F1, F12 — upstream fanout and store-integrity defects treated as unresolved | Discharged | The workspace pins `a5d98b70…`, the first upstream merge carrying both fixes. The remaining obligation is fresh signed network evidence, already a Phase 0 gate. |
| F8 — `file.fetch` writes to an unconfined caller-supplied `save_dir` | Discharged | `resolve_fetch_dir` in [`supervisor.rs`](../crates/jeliya-core/src/supervisor.rs) confines the destination to `<data-dir>/downloads`, rejects `..` before touching the filesystem, canonicalizes the deepest existing ancestor against planted symlinks, and validates the default path too. |

The nine remaining high-severity findings are carried by the amendments above
or remain open in the review ledger.

## What this record authorizes

Phase 0 work only: reconciling status and threat documentation, requalifying
the current revision pair, confirming DNS, CDN, relay, and signing ownership,
and proving browser-to-native Iroh connectivity through an authenticated relay.

It does not authorize Phase 1 implementation. Phase 1 begins when the Phase 0
gate passes, including the signed direct and forced-relay evidence bound to the
final candidate commit and `a5d98b70…`, and a clean run of the six-job CI
matrix twice on one immutable SHA.

## Consequences

- The estimate of 11 to 17 engineering weeks to the first production slice
  predates this record and does not include the work A3, A5, and A6 add. It
  should be re-baselined at the Phase 0 gate rather than carried forward.
- Signing has calendar lead time that is not engineering time. The Phase 2 gate
  requires signed macOS and Windows packages, so issuance must complete before
  that gate. Enrollment **submission** is an early-Phase-1 deliverable (start
  the clock during Phase 1; it is no longer a Phase 0 exit requirement so the
  first slice can ship an unsigned companion downloaded from the GitHub release
  without waiting on procurement). See [Signing and notarization](signing-notarization.md).
  (Reclassified 2026-07-21 from "start during Phase 0" to an early-Phase-1
  deliverable; issuance-completed remains the Phase 2 entry precondition.)
- Browser-to-native Iroh connectivity through an authenticated relay is both a
  Phase 0 gate item and the top two entries in the proposal's highest-risk
  unknowns. Every later phase assumes it works. It should be spiked before
  engineers are committed to Phase 1 or Phase 2.
- `app.jeliya.ai` had no resolvable A, AAAA, or CNAME record at the time of
  this record.

## Decisions deferred to their own records

This record adopts the architecture. It does not settle the eight decisions the
proposal defers, which each require their own record: provider
selection; the companion control protocol and pairing transcript;
recovery-bundle format and custody; multi-device and revocation semantics;
whether optional server peers may read content; the browser signing strategy;
component package metadata and trust-root custody; and the supported browser,
desktop, and mobile matrix. Decision 8 is now recorded in the
[supported platform matrix decision](platform-matrix-decision.md); the other
seven remain open.

One decision the proposal did not defer is registered here alongside them so
the plan's highest-risk unknown #1 has a named owner: the upstream-or-fork
path for the portable Iroh Rooms store, blob, transport, clock, and
task-scheduling traits is recorded in the
[portable Iroh Rooms traits decision](iroh-rooms-portable-traits-decision.md),
owned by the upstream and core maintainer.

## Citations

- [MDN: Storage quotas and eviction criteria](https://developer.mozilla.org/en-US/docs/Web/API/Storage_API/Storage_quotas_and_eviction_criteria) - Safari's seven-day eviction of script-writable storage for origins without user interaction.
- [WebKit: Full third-party cookie blocking and more](https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/) - The affected storage tiers and the home-screen web application exemption.
- [MDN: Clear-Site-Data](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Clear-Site-Data) - `"storage"` unregisters each service-worker registration on the origin.
- [Chrome: Fresher service workers by default](https://developer.chrome.com/blog/fresher-sw) - Update-check cache bypass and the 24-hour registration staleness cap.
- [Iroh: WebAssembly and browsers](https://docs.iroh.computer/languages/wasm-browser) - Relay-only browser connections and the required wrapper.
- [Iroh: Use your own relay](https://docs.iroh.computer/add-a-relay) - Relay authentication and two-region guidance.
