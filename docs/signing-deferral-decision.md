---
type: "Decision"
title: "Code-signing deferral — decision record"
description: "Defers code-signing (the signing gate and #25 procurement) until the first release published without the technical-preview label, so signing never blocks development. Until then the daemon archives ship unsigned with SHA-256 sidecars, and the installers' verified-checksum behaviour is the enforced contract."
tags: ["decision", "deployment", "signing", "release", "distribution"]
timestamp: "2026-07-26T00:00:00Z"
status: "canonical"
implementation_status: "planned"
verification_status: "unverified"
release_status: "unreleased"
audience: ["contributors", "maintainers", "release-engineers", "security-reviewers"]
---

# Code-signing deferral — decision record

**Status: DECIDED 2026-07-21. Trigger re-anchored 2026-07-26 by the
[desktop-operator-first scope decision](desktop-first-scope-decision.md) —**
Code-signing must not sit on the development critical path. The signing gate
("supported installers verify signatures and reject tampering") and the
procurement work
([#25](https://github.com/kortiene/app.jeliya.ai/issues/25): Apple Developer
ID / notarization and Windows Authenticode) are deferred until **the first
release published without the technical-preview label**. Until that release the
daemon ships **unsigned** — a native archive from the GitHub release with its
SHA-256 checksum sidecar — and signing is added as a final hardening step
before the label comes off.

**Why the trigger moved, recorded so the re-anchor is auditable rather than a
silent rewrite.** The original trigger was "after the full system is deployed
and tested end-to-end", which meant after Phase 5. Phases 2 through 5 are now
deferred behind a re-entry trigger, so that condition **can never be met**, and
leaving it in place would have deferred signing permanently by accident — the
one outcome nobody decided. The replacement is stated in decision 1 below.

This record supersedes the prior "start signing procurement during Phase 0 /
Phase 1" framing in
[Production deployment decision](production-deployment-decision.md) and
[Signing and notarization](signing-notarization.md). It is a deliberate, dated
re-sequencing of a release-gate, not a change to the architecture.

## Decision

1. The signing gate item ("supported installers verify signatures and reject
   tampering") and the "signed macOS and Windows packages" deliverable are
   **removed from every technical-preview release** and moved to a **signing
   gate** (formerly the *post-deploy signing gate*) that **fires before the
   first release published without the technical-preview label**.

   The label is a real artifact, not a judgement call: the release title is
   written by `scripts/finalize-release.sh` as
   `Jeliya <tag> — Evidence-Backed Technical Preview`. Dropping that suffix is
   the observable event this gate keys on, which is what makes the trigger
   checkable by someone who was not in this decision — the property the old
   trigger lost the moment the phases went away.
2. [#25](https://github.com/kortiene/app.jeliya.ai/issues/25) is moved to the
   **Release hardening (signing)** milestone; enrollment and issuance proceed
   only as that gate nears. The scope decision **re-scopes** #25; it does not
   close it.
3. Every technical-preview release builds, ships, and is tested with
   **unsigned** daemon archives. No gate short of the signing gate requires
   signed packages — including the desktop release gate in
   [Known gaps and roadmap](known-gaps-roadmap.md), now the project's only
   launch gate, whose exit criteria require signed *evidence manifests* and
   verified checksums but no OS code-signing.

## Rationale

- The goal is to keep development unblocked. Signing procurement is calendar
  lead time (Apple organizational/identity verification, CA vetting), not
  engineering time; putting it on the critical path of a preview release would
  stall that release on lead time without changing what the preview promises.
- Until the signing gate fires, the SHA-256 checksum sidecar on the GitHub
  release detects accidental corruption or an archive/sidecar mismatch; it does
  **not** authenticate the artifact against a trusted root (a replaced release
  can replace both), so the unsigned-install risk recorded in the
  [Security threat model](security-threat-model.md) stands for every
  technical-preview release. Full OS-trust signing is added before the label
  comes off, as a final hardening step.
- **The installers' verified-checksum behaviour is the enforced contract in the
  meantime, and it is not deferred.** `packaging/install.sh` and
  `packaging/install.ps1` download the sidecar, require exactly one line of 64
  hex digits naming the selected archive, and refuse to extract on a missing,
  malformed, or mismatched sidecar. That fail-closed behaviour is a release-gate
  condition today; this deferral does not weaken it.

## Consequence accepted

Every technical-preview release ships **unsigned** daemon archives. This
deliberately accepts the [Security threat model](security-threat-model.md)'s
unsigned-install risk, and the acceptance is live rather than prospective:
`v0.5.0` is already published unsigned. The trade is an unblocked critical path
for a release that is labelled a preview and claims no OS-trust guarantee. The
signing gate is the trust boundary at which signed, notarized installers become
mandatory, and it fires before the label is removed — so **no release that stops
calling itself a technical preview ships unsigned**.

## What this does not change

- The architecture of the daemon, its distribution shape ("install `jeliyad`"),
  or the release-evidence pipeline.
- The two named human dependencies. Amendment A6 (trust-and-safety and legal
  owners before public launch) goes dormant with the hosted plane, but both
  human dependencies survive it, and neither concerns code-signing: the
  qualified legal review re-enters with the plane, and the **named deputy
  remains an open single point of failure on the repository and release keys** —
  including the signing credentials this record defers procuring (see
  [Signing and notarization](signing-notarization.md), "Custody, rotation, and
  incident response"). A preview release with unsigned artifacts stays an
  explicit, recorded posture until the signing gate closes.
- The out-of-band Ed25519 release-evidence key (used for evidence manifests),
  which is unrelated to OS code-signing. The scope decision's deferral of the
  hosted plane preserves it explicitly.

## Citations

- [Desktop-operator-first scope decision](desktop-first-scope-decision.md) — re-anchors this record's trigger; the authority for the trigger stated above.
- [Production deployment architecture](production-deployment.md) — deprecated; the phase gates that carried the original trigger.
- [Production deployment decision](production-deployment-decision.md) — deprecated; the prior signing-lead-time consequence, superseded here.
- [Signing and notarization](signing-notarization.md) — the procurement procedure, now deferred to the re-anchored signing gate.
- [Security threat model](security-threat-model.md) — the unsigned-install risk this decision accepts for every technical-preview release.
- [Known gaps and roadmap](known-gaps-roadmap.md) — the desktop release gate, now the project's only launch gate; none of its exit criteria require OS code-signing.
