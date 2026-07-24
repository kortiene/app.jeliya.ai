---
type: "Decision"
title: "Hostile-frontend containment — decision record"
description: "Discharges amendment A2 for the first public launch: separates the 15-minute CDN-pointer rollback objective (when clean bytes become available) from a hostile-code-termination objective (when hostile code stops running), and specifies the two mechanisms that actually evict a hostile web shell. Adds Clear-Site-Data as an incident header served from the rolled-back origin on the service-worker script path and index.html; a signed web-shell kill-switch document — signed by the existing release/provenance chain with a monotonic anti-rollback version floor — that the service worker checks on activate and on navigation and self-terminates on; a fail-open-on-unreachable posture so the offline shell survives a network blip; and the runbook, smoke-test, and gate edits that wire them in. Issue #44."
tags: ["decision", "deployment", "security", "hostile-frontend", "service-worker", "phase-3"]
timestamp: "2026-07-24T21:00:00Z"
status: "canonical"
implementation_status: "planned"
verification_status: "unverified"
release_status: "unreleased"
audience: ["maintainers", "operators", "security-reviewers", "frontend", "release-engineers"]
---

# Hostile-frontend containment — decision record

**Status: DECIDED 2026-07-24 —** This record makes the amendment **A2**
([production deployment decision](production-deployment-decision.md) §A2) decisions for
issue [#44](https://github.com/kortiene/app.jeliya.ai/issues/44), discharging review
finding **F11** ([production deployment architecture review](production-deployment-review.md)
§F11, CONFIRMED high). It separates *availability of clean bytes* from *termination of
hostile code* and specifies the mechanisms that evict a hostile web shell. The header,
runbook, kill-switch, objective, smoke-test, and gate **edits land now** in
[production deployment architecture](production-deployment.md) (§9); the service-worker
kill-switch check, the served `Clear-Site-Data`, the signed kill-switch document, and
the eviction smoke test are **Phase-3 build** carried as gate items (§8). The
acceptance-criteria mapping (§10) marks each item.

## 1. Two distinct threats — each mechanism covers only one

F11's core point: the 15-minute rollback objective bounds when clean bytes are
*available*, not when hostile code stops *running*, and one mechanism does not cover
both failure modes. This record keeps them distinct:

- **Hostile content, legitimate service worker** — a compromised origin/CDN serves a
  hostile shell, but the browser's registered service worker is still the project's own
  code. Containment: the **legitimate SW checks the signed kill-switch document (§3)**
  and stops serving its cached shell when the shell is marked killed. This is the case
  the in-SW check exists for.
- **Hostile service worker** — the registered SW code is itself malicious (registered
  during the compromise window). No document the hostile SW chooses to read helps; it
  controls its own `fetch` handler and can answer navigations from cache without ever
  seeing the origin. Containment: the **browser eventually refetches a byte-different
  SW script** — bounded by the normative service-worker staleness cap (the browser
  bypasses the HTTP cache for the top-level worker script once a registration is >24h
  stale, and on navigation) — and **`Clear-Site-Data` (§2)** on that refetched response
  unregisters it. This is why the termination objective (§5) is bounded by the SW
  update check, worst case ~24h plus a navigation, not by the 15-minute pointer flip.

Neither mechanism alone is sufficient; both are required, and stating which threat each
covers is the honest form of the containment claim.

## 2. `Clear-Site-Data` as an incident header

The production header configuration gains **`Clear-Site-Data: "cache", "storage",
"executionContexts"`**, served **from the rolled-back origin on the service-worker
script path and `index.html`** during a frontend-compromise incident. `"storage"` is
the operative directive: per the spec it clears origin storage **including Cache
Storage** and **unregisters every `ServiceWorkerRegistration` on the origin**; `"cache"`
clears the HTTP cache; `"executionContexts"` reloads live browsing contexts.

**This is an incident header, not a standing one.** Emitting `Clear-Site-Data` on every
response would wipe the app's own storage on every load and defeat the offline shell;
it is served on the SW-script and `index.html` responses **when the kill switch is
active** (the rolled-back deployment carries it), then withdrawn once clients are
evicted. Two caveats are recorded honestly:

- **Browser support.** `"executionContexts"` is currently unimplemented across the whole
  supported matrix — Chrome/Edge never shipped it, Firefox removed it after v67, Safari
  after v18.2 — so the app relies on it nowhere; it stays in the emitted header (unknown
  directive values are ignored), but the **eviction rests on `"storage"`**, which
  performs the SW unregistration on every engine in the
  [supported matrix](platform-matrix-decision.md).
- **Delivery to a hostile SW is not guaranteed.** A hostile SW controls its own `fetch`
  handler and may answer navigations from cache without requesting the origin, so it
  need not see the header until the browser's own update check refetches the worker
  script out-of-band. `Clear-Site-Data` is therefore **necessary but not sufficient on
  its own**; the ~24h SW-update-check bound (§5) is the backstop, and the two together
  are the containment.

## 3. The signed web-shell kill-switch document

The [Rollback](production-deployment.md) controls gain a **signed kill switch covering
the web shell**, independent of the existing component-metadata kill switch:

- **A signed version / kill-switch document**, hosted at the origin with
  `Cache-Control: no-cache`, carrying a **monotonically increasing sequence number** and
  a `killed` state for the shell.
- **Signed by the operator-held, out-of-band Ed25519 release-evidence key** — the same
  offline signing authority that signs the qualification-evidence manifests
  ([production ownership record](production-ownership.md) §4 "Ed25519 evidence signing
  key"; [verification evidence](verification-evidence.md), detached `.sig`). No new
  signing key is introduced, and this key is **available at launch**: the
  [code-signing deferral](signing-deferral-decision.md) defers only OS installer
  code-signing (Apple/Windows notarization) and explicitly keeps the Ed25519
  release-evidence key alive as "unrelated to OS code-signing", so the deferral does
  **not** gate this Phase-3 web-shell kill switch. The service worker pins that key and
  verifies the detached signature before honoring the document. Reusing the operator's
  one existing offline key avoids adding to the solo-operator signing-custody gap
  recorded in [production ownership record](production-ownership.md) §4.
- **Anti-rollback.** The SW persists the highest sequence number it has verified and
  **refuses any document with a lower or equal sequence**, so an attacker with pointer
  control cannot replay an old "all-clear" to un-kill a killed shell (closing the
  rollback-as-downgrade path the [threat model](security-threat-model.md) records). A
  validly-signed *higher-sequence* document supersedes a prior kill, so genuine recovery
  is possible.
- **The SW checks it on `activate` and on navigation** (and may re-check on a bounded
  timer while running), then **stops serving its cached shell when the document marks
  the shell killed** — it unregisters itself, clears its Cache Storage, and serves a
  minimal safe page directing the user to reload. Checking on navigation, not only on
  `activate`, means a long-running legitimate SW that has not received an update still
  notices a kill promptly.

## 4. Failure posture: fail-open on unreachable

When the SW **cannot fetch or verify** the kill-switch document — the client is offline,
or the origin/CDN is down — it **keeps serving the last-known-good cached shell**
(fail-open). Only a **validly-signed document marking the shell killed** stops it; an
unreachable or unverifiable document never does.

This is deliberate. The kill switch is for a **confirmed compromise**, not a network
blip. Failing closed — refusing to serve unless freshness is confirmed — would break the
offline PWA entirely, self-DoS the app on any origin/CDN outage, and contradict both the
"offline shell and cached view open during origin outage" gate item and the 99.95%
static-shell availability objective. The residual risk this accepts: a client that is
offline throughout an incident is not evicted until it reconnects and the browser's
update check runs — which is the same ~24h-plus-navigation bound as §5, made explicit
rather than hidden.

## 5. Two service objectives, not one

The [service-objective table](production-deployment.md) states **two** numbers where it
stated one:

- **Frontend rollback (CDN pointer): at most 15 minutes** — when clean bytes become
  *available* at the origin (unchanged).
- **Hostile-code termination: bounded by the service-worker update check, worst case
  ~24 hours plus a navigation** — when hostile code stops *running* in an installed
  client. For a **running** legitimate shell the in-SW kill-switch check (§3) makes this
  near-immediate (next navigation); the ~24h worst case applies to a **dormant** installed
  PWA that is not navigated — its SW is not re-checked until the next navigation, at which
  point, if the registration is more than 24h stale, the update fetch bypasses the HTTP
  cache and refetches the worker script.

The two are reported separately so a runbook cannot claim containment on the 15-minute
number while installed clients still execute the attacker's shell.

## 6. Runbook, smoke test, and gate

- **Runbook (AC 2).** The "malicious frontend or CDN credential compromise" runbook
  invokes **`Clear-Site-Data` as the shell-eviction step and publishes the signed
  kill-switch document**, not only the CDN-pointer flip.
- **Smoke test (AC 6).** The production smoke tests gain a **hostile-shell eviction
  case** — a killed shell stops serving and the client re-fetches clean bytes — in
  addition to the existing service-worker N/N-1 update test.
- **Gate (AC 7).** The Phase-3 "external TLS/header/CSP assessment passes" gate item is
  run against the header set **including `Clear-Site-Data`**, and the
  "N-to-N-1 rollback completes within 15 minutes" gate item **stays stated separately**
  from the hostile-code-termination objective (§5).

## 7. What this does and does not contain

It contains a hostile shell to a **bounded, stated** window and gives the incident
runbook a mechanism that actually evicts it. It does **not** make eviction instantaneous
for a dormant installed PWA, and it does **not** recover data a hostile shell already
exfiltrated or actions it already drove within a granted companion scope — those are the
[amendment A6](trust-safety-and-legal-decision.md) takedown-limit and the
[hosted-origin disclosure](vulnerability-disclosure-decision.md) advisory/notification
paths. A2 bounds *how long hostile code runs*, not *what it did while running*.

## 8. Phase 3 gate items (added by this record)

The first production launch gate ([production deployment
architecture](production-deployment.md) "Go/no-go gate") gains:

- the header assessment covers **`Clear-Site-Data`** on the SW-script and `index.html`
  incident responses (§2, §6);
- a **hostile-shell eviction smoke test** passes (§6);
- the **signed web-shell kill switch** and the **SW kill-switch check** exist and are
  exercised (§3), with the hostile-code-termination objective (§5) stated and measured
  separately from the 15-minute rollback.

## 9. Edits applied with this record

- [production deployment architecture](production-deployment.md) header configuration —
  adds the **`Clear-Site-Data`** incident header with its served-on-rollback scoping
  (AC 1).
- [production deployment architecture](production-deployment.md) Rollback list — adds the
  **signed web-shell kill switch** independent of the component-metadata one, and the
  **SW-checks-and-self-terminates** behavior (AC 3, AC 4).
- [production deployment architecture](production-deployment.md) incident runbooks — the
  malicious-frontend runbook **invokes `Clear-Site-Data` and the kill-switch document**
  as the eviction step (AC 2).
- [production deployment architecture](production-deployment.md) service-objective
  table — **two numbers**: CDN-pointer rollback and hostile-code termination (AC 5).
- [production deployment architecture](production-deployment.md) production smoke
  tests — a **hostile-shell eviction** case (AC 6).
- [production deployment architecture](production-deployment.md) Phase-3 go/no-go gate —
  header assessment **includes `Clear-Site-Data`**; rollback-15-minutes stays **separate**
  from the termination objective (AC 7).
- [docs index](index.md) — registers this record.

## 10. Acceptance-criteria mapping (issue #44)

Each criterion is marked **met** (decided/applied here) or **publication-deferred**
(decided; served/exercised as a Phase-3 build item).

- *`Clear-Site-Data: "cache", "storage", "executionContexts"` added to the header set,
  served from the rolled-back origin on the SW-script path and `index.html`* — **met
  (named) / publication-deferred (served)**: §2, edit §9; the live header is served in
  Phase 3.
- *The malicious-frontend runbook invokes that header as the shell-eviction step, not
  only the CDN pointer flip* — **met**: §6, edit §9.
- *The Rollback list carries a signed kill switch covering the web shell, independent of
  the component-metadata kill switch* — **met**: §3, edit §9.
- *The service worker checks a signed version/kill-switch document on activate and stops
  serving its cached shell when it is marked killed* — **met (specified) /
  publication-deferred (built)**: §3–§4 specify the check, the signing chain, the
  anti-rollback floor, and the fail-open posture; the SW code is Phase-3 build (§8).
- *The service-objective table states two numbers — the 15-minute CDN rollback and a
  separate hostile-code-termination objective (~24h plus a navigation)* — **met**: §5,
  edit §9.
- *The smoke-test list gains a hostile-shell eviction case in addition to the N/N-1
  update test* — **met (named) / publication-deferred (exercised)**: §6, edit §9.
- *The "external TLS/header/CSP assessment" gate runs against the header set including
  `Clear-Site-Data`, and "N-to-N-1 rollback within 15 minutes" stays separate from the
  termination objective* — **met**: §6, §8, edit §9.

## 11. Reopen-set position

This record and its edits touch **documentation only** — a new decision record and
documentation-only edits to `docs/production-deployment.md` and the [docs index](index.md).
None is in the Phase-1 reopen set
([phase-1 security review scope](phase-1-security-review-scope.md)). No re-pin or delta
review is owed. When `ui/src/sw.ts`, the served `Clear-Site-Data`, and the signed
kill-switch document are implemented (Phase 3), that code change is reviewed on its own
terms.

## 12. Citations

- [production deployment decision](production-deployment-decision.md) §A2 — the amendment
  this record discharges.
- [production deployment architecture](production-deployment.md) — the header
  configuration, the Rollback list and its component-metadata kill switch, the incident
  runbooks, the service-objective table, the production smoke tests, and the Phase-3
  go/no-go gate.
- [production deployment architecture review](production-deployment-review.md) §F11 — the
  confirmed high finding (CDN rollback bounds byte availability, not hostile-code
  termination; `Clear-Site-Data: "storage"` unregisters service workers; no web-shell
  kill switch) that this record discharges.
- [security threat model](security-threat-model.md) — the hostile-service-worker and
  rollback-as-downgrade residual risks.
- [production ownership record](production-ownership.md) §4 and [verification
  evidence](verification-evidence.md) — the operator-held out-of-band Ed25519
  release-evidence key reused to sign the kill-switch document, and the solo-operator
  signing-custody gap; [code-signing deferral](signing-deferral-decision.md) preserves
  that key as unrelated to the deferred OS installer code-signing.
- Issue [#44](https://github.com/kortiene/app.jeliya.ai/issues/44); amendment A2.
