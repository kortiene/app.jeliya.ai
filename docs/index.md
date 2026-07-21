# Jeliya documentation

This directory is Jeliya's canonical docs-as-code wiki. Start with the project
foundations, then follow the section that matches the work you are doing. The
[documentation profile](PROFILE.md) defines metadata, lifecycle, linking, and
CI rules for every page in this wiki.

## Project foundations

- [README](../README.md) - Product overview, installation, first room, and contributor entry points.
- [Product](../PRODUCT.md) - Users, product purpose, principles, and accessibility commitments.
- [Design system](../DESIGN.md) - Visual language, components, responsive behavior, and interaction contracts.
- [Contributing](../CONTRIBUTING.md) - Contribution requirements, repository conventions, and required verification.
- [Security](../SECURITY.md) - Vulnerability reporting, threat-model boundaries, and current security posture.
- [Changelog](../CHANGELOG.md) - Shipped changes by release.

## Current status and evidence

- [Capability status](capability-status.md) - What is implemented, verified, and publicly released as of v0.5.0 and the post-release candidate.
- [Platform matrix](platform-matrix.md) - Runtime, packaging, verification, and release status by operating system and artifact.
- [Release versus main](release-vs-main.md) - Exact boundary between released v0.5.0, its certified evidence, and the post-release candidate on main.
- [Verification evidence](verification-evidence.md) - Revision-bound milestone ledger, remote-test record, and evidence-sanitization contract.
- [Known gaps and roadmap](known-gaps-roadmap.md) - Release blockers, deferred risks, owners, and the NOW/NEXT/LATER boundary.

## Architecture and protocols

- [Daemon protocol](PROTOCOL.md) - Normative transport-neutral contract between `jeliya-core` and every Jeliya client.
- [Room Workbench](room-workbench.md) - Decision record for the global-versus-room hierarchy, canonical routes, responsive shells, and status vocabulary.
- [Room attention](room-attention.md) - Decision record for evidence-backed room recency, device-local unread, and actionable attention, and the evidence rule each displayed field must satisfy.
- [Device-local self label](self-label.md) - Decision record for the editable, device-local self display name reusing the alias store keyed by the self identity id, its fallback, validation, migration, and privacy rules.
- [Cross-client design tokens](design-tokens.md) - Mapping from every design-token concept to its React custom property, the shared fixture, and the gate that enforces it.
- [Agent orchestration](agent-orchestration.md) - Normative contract for agent liveness, task claims, fleet reads, and UI projections.
- [Security and threat model](security-threat-model.md) - Assets, trust boundaries, threats, controls, and residual risks for the technical preview.
- [Production deployment decision](production-deployment-decision.md) - Decision record adopting the capability-aware hybrid architecture and the companion-backed first slice for app.jeliya.ai, and the six amendments binding its phase gates.
- [Production ownership record](production-ownership.md) - Who controls the jeliya.ai zone, CDN, relay, edge-token, and signing accounts, and who can approve a production change (Phase 0 deliverable, issue #24).
- [Production provider selection decision](provider-selection-decision.md) - Decision record confirming the DNS, CDN, edge-token, relay, object-store, IaC, and native-signing provider set for app.jeliya.ai, with its reversibility position (Phase 0 deliverable, issue #27).
- [Supported platform matrix decision](platform-matrix-decision.md) - Decision record fixing the first-slice supported desktop OS and browser matrix, its mobile position under amendment A4, the test-lane mapping, and the pairing-success denominator.
- [Portable Iroh Rooms traits decision](iroh-rooms-portable-traits-decision.md) - Decision record choosing the audited short-lived patch path for the browser peer's portable store, blob, transport, clock, and task-scheduling traits, with its audit owner and recurring cost.
- [Phase 0 go/no-go gate verdict](phase-0-gate-verdict.md) - Dated verdict against each of the six Phase 0 gate conditions for the v0.6.0 candidate (922f620 + a5d98b70), each with linked evidence (issue #31).
- [Code-signing deferral decision](signing-deferral-decision.md) - Decision record deferring code-signing (the signing gate and #25) until after the full system is deployed and tested, so signing never blocks development.

## Agents

- [Run the Jeliya agent](agent-guide.md) - Operational and security guide for the room-driven agent runner.

## Proposals

- [Agent marketplace architecture](agent-marketplace.md) - Proposed, not-yet-implemented hosted-agent marketplace architecture, trust model, product flow, and delivery plan.
- [Production deployment architecture](production-deployment.md) - Repository-grounded assessment, hybrid browser/native/server target, trust boundaries, infrastructure, release gates, and the first production slice for app.jeliya.ai.
- [Production deployment architecture review](production-deployment-review.md) - Adversarially verified findings, refuted candidates, and confirmed claims behind the six amendments carried by the deployment decision record.

## Operations and release evidence

- [Phase 0 relay-connect spike result](evidence/phase-0-relay-spike.md) - Recorded PASS verdict for the Phase 0 browser-to-native Iroh-through-authenticated-relay gate item (issue #23); Chromium, Firefox, and WebKit all pass.
- [Accessibility release checklist](accessibility-checklist.md) - The screen-reader and keyboard behaviours automated checks cannot prove, verified by hand before a release.
- [Real-network NAT runbook](realnet-runbook.md) - Procedure for proving direct or relayed connectivity across two networks.
- [Historical Gate A result](gate-a-result.md) - Older direct-connectivity evidence that does not certify the v0.5.0 candidate.
- [Signing and notarization](signing-notarization.md) - Release-security plan for macOS and Windows artifacts.

## Language, identity, and governance

- [Internationalization](i18n.md) - Language roadmap and engineering rules for maintainable localization.
- [French glossary](glossary-fr.md) - Canonical French terminology and localization decisions.
- [Naming decision](naming.md) - Decision record and trademark research supporting the rename to Jeliya.
- [Documentation profile](PROFILE.md) - Metadata, navigation, linking, and CI rules for this wiki.
