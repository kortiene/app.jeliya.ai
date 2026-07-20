---
type: "Decision"
title: "Portable Iroh Rooms traits — decision record"
description: "Decides how the portable event-store, blob-store, sync-transport, clock, and task-scheduling traits reach the browser peer: an audited short-lived patch series with the upstream proposal as its exit path, a named audit owner, and a stated recurring cost."
tags: ["browser", "decision", "dependencies", "iroh", "security", "upstream"]
timestamp: "2026-07-20T13:20:00Z"
status: "canonical"
implementation_status: "planned"
verification_status: "unverified"
release_status: "unreleased"
audience: ["contributors", "maintainers", "release-engineers", "security-reviewers"]
---

# Portable Iroh Rooms traits — decision record

**Status: DECIDED 2026-07-20.** The browser peer depends on portable traits
for "event store, blob store, sync transport, clock, and task scheduling"
that the [production deployment architecture](production-deployment.md) says
are "introduced upstream or in an audited short-lived patch". No phase
deliverable owned that choice, no deferred decision covered it, and the
plan's highest-risk unknown #1 — whether Iroh Rooms will accept and maintain
the portable browser store, transport, and blob interfaces upstream — had a
risk-register entry but no named owner. This record closes that gap before
any phase is scheduled against an outcome the project does not control.

## Decision

Of the two arms in "introduced upstream or in an audited short-lived patch",
this record chooses the **audited short-lived patch**: until upstream accepts
the traits, Jeliya carries them as an audited patch series — a short-lived
fork of the pinned Iroh Rooms revision — and Phase 4 is planned against that
series, not against upstream acceptance.

- **The upstream proposal remains the exit path, not the plan of record.**
  The upstream and core maintainer owns proposing the portable traits to the
  Iroh Rooms project before Phase 4 implementation begins, and reports the
  proposal's status at every phase gate from Phase 0 onward.
- **The audit owner is the core maintainer.** Every revision of the patch
  series receives a security-focused diff review against the pinned upstream
  revision before anything consumes it, and that review is recorded with the
  release evidence.
- **The series is short-lived by rule, not by hope.** The change map's
  warning stands: "A long-lived private fork is a security and maintenance
  liability." Every phase gate reviews whether upstream has accepted the
  traits. If upstream declines them, continuing the fork is a new decision
  that must supersede this record with a re-costed maintenance plan; the fork
  must not simply persist by default.

## Recurring maintenance and audit cost

Choosing the patch arm buys schedule control and pays for it continuously.
The recurring cost, accepted here against the fork-liability warning above,
is:

- each rebase of the patch series onto a new reviewed upstream revision
  re-runs the exact-revision upstream regression suite — provisional-peer
  fanout, connection-generation teardown, synchronization isolation, and
  store retry/degradation — at the rebased result;
- each rebase receives a security-focused diff review of the full patch
  series by the core maintainer;
- each rebase refreshes the pin-rationale record described below;
- every release carries the audit obligation even without a rebase, because
  release qualification binds the exact revision.

The cost is bounded by the phase-gate review of upstream acceptance; it is
not accepted as a permanent line item.

## How the exact-revision pin rule is satisfied

The plan's rule "Every release pins and qualifies an exact upstream
revision" holds for an untagged trait revision on the same terms as the
existing untagged `a5d98b70…` pin rationale: the qualified revision is an
immutable commit hash — here, the rebased result of the patch series on a
reviewed upstream revision — recorded together with the reason no release
tag is used, and the exact-revision regressions must pass at that hash
before anything consumes it. An untagged trait revision is acceptable
exactly as far as the untagged upstream pin is: immutable, reviewed, and
qualified at the exact hash.

## What this record gates

- Under "No phase starts implementation work that depends on an unresolved
  go/no-go gate from the previous phase", Phase 4 implementation work could
  not start before this record existed; it now exists, and Phase 4 work must
  consume the traits only through the audited patch series it governs.
- This record is an input to the Phase 4 gate item "the exact
  upstream/browser-adapter revision receives security qualification": the
  qualification target is the patch-series revision named by the pin rule
  above.
- It is registered alongside the deferred decisions in the
  [production deployment decision](production-deployment-decision.md), so
  highest-risk unknown #1 has a named owner — the upstream and core
  maintainer — rather than only a risk-register entry.
