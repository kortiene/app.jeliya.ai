---
type: "Status Report"
title: "Known gaps and roadmap"
description: "Release blockers, deferred risks, owners, and next actions for the v0.5.0 evidence-backed technical preview."
tags: ["gaps", "release", "risks", "roadmap"]
timestamp: "2026-07-20T13:20:00Z"
status: "canonical"
implementation_status: "partial"
verification_status: "partial"
release_status: "partial"
audience: ["contributors", "maintainers", "product", "release-engineers"]
---

# Known gaps and roadmap

`v0.5.0` shipped on 2026-07-14: the release conditions the `NOW` phase tracked
were met (published safe pin, signed certifying direct and relay evidence,
hosted gates, complete verified artifact set). The table below records that
closure and the gaps that carry forward to the current post-release source
candidate on `main`: the pre-Phase-1 candidate `922f620…` (which repins
`iroh-rooms` to the untagged upstream revision `a5d98b70...` and earned signed
direct/relay evidence at that pair) plus merged PR #78 (Phase 1 protocol
primitives), the Phase 1 remediation (PRs #80–#85), the delta-reviewed
verdict-conditions PR #89, the micro-delta-reviewed hardening PR #90, and the
delta-reviewed issue #91 fix PR #94 (room-scoped device keys), bringing the
reviewed code surfaces to `4206984…` (interleaved `main` commits are
docs-only governance records). Phase 1 is implemented, CI-green, and
**its gate is closed**: see the
[Phase 1 go/no-go gate verdict](phase-1-gate-verdict.md) — rows #1–#6 pass by
tests; row #7's independent re-review returned APPROVE-WITH-CONDITIONS, the
risk-owner recorded GO (2026-07-22), and the approval was
[extended to `d610076` and `dcd940e`](phase-1-security-review.md#conditions-delta-review-2026-07-22)
and then [to `4206984`](phase-1-security-review.md#issue-91-delta-review-2026-07-23)
by the delta reviews. `4206984` is past the network-qualified `922f620…`
pair, so a release still needs fresh signed direct/relay evidence — and the
issue #91 fix makes requalification substantive, not just procedural: room
nodes now present per-room `EndpointId`s and invite tickets advertise the
room-bound device, exactly the surfaces the direct/relay runs exercise.

## NOW — closure status

| Area | Evidence now available | Remaining condition for the next release | Owner | Status |
|---|---|---|---|---|
| Public room-scoped authorization | centralized guard; 17 negative RPCs, local-file denial, and aggregate filtering passed locally and in both certifying network runs | preserve gates on the next candidate | core maintainer | closed for `v0.5.0` |
| Accepted-room provenance | failure-injected create/join ordering, serialized concurrent updates, cached reads, owner-only Unix state, and durable replacement semantics pass; hosted Windows job passes on `main` | preserve on the next candidate | core maintainer | closed |
| Upstream synchronization, provisional-peer, and store integrity | certified baseline for `v0.5.0` at `d0ceb0b…`; current `a5d98b70…` pin passes targeted fanout, isolation, and store-degradation regressions plus 806 core/net tests and the full Jeliya suites locally | rerun signed direct and relay qualification at `a5d98b70…` before the next release | upstream and core maintainer | current pin locally requalified; network qualification pending |
| Agent secrets | external agent data default, ignore and tracked-secret gates pass | keep controls on the next candidate | agent maintainer | closed |
| Dependency security | Cargo and npm report zero vulnerabilities; four unmaintained/yanked warnings have owner, mitigation, and expiry records | rerun against the next candidate's lockfiles | dependency owner | closed |
| CI completeness | the daemon-only six-job matrix passed twice at the frozen candidate `922f620…`, on push run `29713108134` and `workflow_dispatch` run `29713781499`, every job green on first attempt with no rerun; the earlier run `29699530741` at `105744b…` covered the then-current matrix and is not evidence for `922f620…`; manual dispatch does not publish | none for this condition; signed network qualification at `922f620…` + `a5d98b70…` is complete (direct `098c4979`, relay `8bda01e6`) | CI maintainer | twice-clean condition met at `922f620…` |
| Agent/fleet reliability | agent E2E passes; fleet stability passed 5/5; Linux orphan/zombie cleanup verified on `demo1` under UID `65534` | repeat in the next candidate's hosted gates | agent maintainer | closed |
| Direct network behavior | signed runs certify released `v0.5.0`, the prior `55024a4…` + `71fbb500…` snapshot, and the current `922f620…` + `a5d98b70…` pair (direct run `098c4979`, operator linux arm64) | none — both direct and forced-relay halves qualified at `922f620…` + `a5d98b70…` | verification owner | direct qualified at `922f620…` + `a5d98b70…` |
| Forced relay behavior | signed runs certify released `v0.5.0`, the prior `55024a4…` + `71fbb500…` snapshot, and the current `922f620…` + `a5d98b70…` pair (relay run `8bda01e6`; the relay-only verifier source-builds and self-attests on all three hosts) | none — both halves qualified at `922f620…` + `a5d98b70…` | verification owner | relay qualified at `922f620…` + `a5d98b70…` |
| Evidence authenticity | detached Ed25519 signatures over both certifying manifests verify against the committed public SPKI; private-key custody is out of band | keep custody; sign the next candidate's runs | release authority | closed |
| Unix installer integrity | behavioral checksum-before-extraction tests pass; `v0.5.0` installs via the version-pinned installer path | rerun against the next artifacts | release maintainer | closed |
| Windows installer integrity | hosted `windows-latest` behavioral job passes on `main`; a `v0.5.0` Windows zip and sidecar are published | rerun against the next artifacts | release maintainer | closed |
| Complete asset-set visibility | the publication workflow executed for `v0.5.0`: validation, sealing, isolated smoke, receipt verification, and draft-until-complete publication | re-execute for the next release under explicit authority | release authority | executed for `v0.5.0` |
| Complete artifact set | `v0.5.0` published all five daemon-plus-embedded-UI archives with sidecars | build and verify the next candidate's set together | release maintainer | closed for `v0.5.0` |
| Documentation alignment | status pages distinguish released `v0.5.0`, the prior signed `v0.6.0` snapshot, and the current untagged dependency candidate | bind fresh signed evidence after the network reruns | documentation owner | current for this snapshot |

No reachable high or critical advisory is currently unresolved. The four
maintenance/yank warnings are tracked with mitigation and an expiry of
2026-09-30; expiry requires reassessment, not silent acceptance.

## Explicit preview limitations

- Jeliya is daemon-only: it ships `jeliyad` with an embedded web UI and no
  desktop or mobile application for any platform;
- bare daemon binaries are unsigned; macOS notarization and Windows
  Authenticode are inactive;
- WCAG 2.1 AA remains a design target with targeted checks, not enforced or
  certified conformance;
- member removal cannot recall data already copied by an authorized peer;
  revocation semantics require a separate protocol and product decision;
- the current upstream pin is an immutable but untagged commit. It fixes the
  provisional-peer fanout and store-hole residuals from `v0.1.0-rc.3`, but a
  long-term tagged-release and maintenance path is still required;
- exhausted store retries or queue overflow produce a durable critical
  `store_degraded` decision. Operators still need a documented response to real
  disk failure; and
- mixed pre/post-repin fleets cannot complete joins, so joiners and admins must
  upgrade together: mixed `v0.5.0`/candidate rooms cannot complete joins in
  either direction, so a room's members, especially its admin, must move
  together. The published `v0.5.0` set is five daemon archives with no
  auto-update channel, so the upgrade message reaches an already-installed
  client only through the next release's notes and the installation
  instructions they point to — inside the product, the join failure itself is
  the only signal. The Phase 0 go/no-go gate therefore requires a coordinated
  fleet-upgrade plan before any hosted surface can meet an already-published
  client, and measuring the stranded fraction belongs to amendment A3 of the
  [production deployment decision](production-deployment-decision.md).

## Exit criteria for the next release

`v0.5.0` met its exit criteria and shipped on 2026-07-14. The next release
reaches a release-authority decision only when the same bar is met at the
new candidate:

1. the candidate's reviewed public pin (`a5d98b70…`, or a reviewed tagged
   successor carrying the same fixes) is carried by the final public commit;
2. signed direct and relay manifests bound to that commit and pin pass the
   release gate with `certifiable: true` (the `v0.5.0` evidence binds
   `c5f740e` + `d0ceb0b` and does not transfer);
3. every required hosted CI gate passes twice from clean environments;
4. Windows behavioral checks and the other target-specific gates pass;
5. the complete archive-and-sidecar set is built and verified before
   publication begins;
6. tag, daemon, changelog, and public names agree on the release version;
7. [Capability status](capability-status.md),
   [Platform matrix](platform-matrix.md),
   [Release versus main](release-vs-main.md), and
   [Verification evidence](verification-evidence.md) match that final commit;
8. explicit release authority is granted to the sole publishing job.

## NEXT — after the preview

- operate signing, notarization, and evidence keys with documented custody,
  rotation, and incident response;
- add comprehensive accessibility automation and scheduled manual audits;
- define member removal and key-rotation semantics before promising revocation;
- automate privacy-reviewed retained evidence publication after a successful
  release.

## LATER — separate product decisions

Native desktop and mobile applications, hosted agents, an agent marketplace,
new protocol event types, and other user-facing capabilities require separate
product, security, and architecture decisions. They remain outside this milestone.
