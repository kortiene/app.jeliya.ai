---
type: "Decision"
title: "Code-signing deferral — decision record"
description: "Defers code-signing (the signing gate and #25 procurement) until after the full system is deployed and tested end-to-end, so signing never blocks development. Unsigned companion artifacts are accepted through build, deploy, and test."
tags: ["decision", "deployment", "signing", "release", "phase-0"]
timestamp: "2026-07-21T15:00:00Z"
status: "canonical"
implementation_status: "planned"
verification_status: "unverified"
release_status: "unreleased"
audience: ["contributors", "maintainers", "release-engineers", "security-reviewers"]
---

# Code-signing deferral — decision record

**Status: DECIDED 2026-07-21 —** Code-signing must not sit on the development
critical path. The signing gate ("supported installers verify signatures and
reject tampering") and the procurement work
([#25](https://github.com/kortiene/app.jeliya.ai/issues/25): Apple Developer
ID / notarization and Windows Authenticode) are deferred until **after the full
system is deployed and tested end-to-end**. Through build, deploy, and test the
companion ships **unsigned** — a native archive from the GitHub release with its
SHA-256 checksum sidecar — and signing is added as a final hardening step once
the system is proven.

This record supersedes the prior "start signing procurement during Phase 0 /
Phase 1" framing in
[Production deployment decision](production-deployment-decision.md) and
[Signing and notarization](signing-notarization.md). It is a deliberate, dated
re-sequencing of a release-gate, not a change to the architecture.

## Decision

1. The Phase 2 signing gate item ("supported installers verify signatures and
   reject tampering") and the Phase 2 "signed macOS and Windows packages"
   deliverable are **removed from Phase 2** and moved to a **post-deploy signing
   gate** that runs after Phase 5, once the system is deployed and tested
   end-to-end (see [Production deployment architecture](production-deployment.md)).
2. [#25](https://github.com/kortiene/app.jeliya.ai/issues/25) is moved to the
   **Release hardening (signing)** milestone; enrollment and issuance proceed
   only as that gate nears.
3. Phases 1 through 5 build, deploy, and test with **unsigned** companion
   artifacts. No phase gate in Phases 1–5 requires signed packages.

## Rationale

- The goal is to keep development unblocked. Signing procurement is calendar
  lead time (Apple organizational/identity verification, CA vetting), not
  engineering time; leaving it on the Phase 2 critical path would stall later
  phases on that lead time.
- During build, deploy, and test, release integrity is provided by the SHA-256
  checksum sidecars on the GitHub release; full OS-trust signing is added once
  the system is proven, as a final hardening step.

## Consequence accepted

Through build, deploy, and test the companion is **unsigned**. This deliberately
accepts the [Security threat model](security-threat-model.md)'s
unsigned-companion-install risk for the development/deploy/test period. If
"deployed and tested" includes a public deployment, that public artifact is
unsigned until the post-deploy signing gate closes — a deliberate trade for an
unblocked critical path. The post-deploy signing gate is the trust boundary at
which signed, notarized installers become mandatory.

## What this does not change

- The architecture, the companion's shape, or the production deployment model.
- Amendment A6 (Phase 3, trust-and-safety and legal owners before public launch)
  — A6 concerns ownership, not code-signing; a public launch with unsigned
  artifacts is now an explicit, recorded posture until the signing gate closes.
- The out-of-band Ed25519 release-evidence key (used for evidence manifests),
  which is unrelated to OS code-signing.

## Citations

- [Production deployment architecture](production-deployment.md) — the phase gates; the Phase 2 signing gate is moved to a post-Phase-5 signing gate.
- [Production deployment decision](production-deployment-decision.md) — the prior signing-lead-time consequence, superseded here.
- [Signing and notarization](signing-notarization.md) — the procurement procedure, now deferred to the post-deploy gate.
- [Security threat model](security-threat-model.md) — the unsigned-install risk this decision accepts during build, deploy, and test.
