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
- [Relay load and cost ceilings decision](relay-load-and-cost-ceilings-decision.md) - Canonical / decided 2026-07-24 (issue #45): the closed-beta load profile and hard ceilings — 1,024 GiB/mo relay egress, 2M/day token mints, $900/mo all-in spend cap (alert fractions stated), sized at a conservative $0.15/GiB — for production, staging, CI, and dev relays, with the Phase 3 gate restated against them; blocks #49.
- [Relay-auth admission rule decision](relay-auth-admission-rule-decision.md) - Canonical / decided 2026-07-24 (issue #49): the layered rule that admits a relay-credential mint — companion-countersigned non-extractable control key (proof of possession over an endpoint-bound challenge), per-key quotas, and a global daily minting budget that auto-sheds at the #45 ceilings with a reserve for established paired keys; a privacy-preserving scarcity anchor (proof-of-work) is deferred behind a named trigger.
- [Trust, safety, and legal ownership decision](trust-safety-and-legal-decision.md) - Canonical / decided 2026-07-24 (issue #47, amendment A6): names the maintainer as sole operator and abuse/triage/launch owner, the GitHub-private-reporting beta abuse channel with per-class response times, the retention + lawful-basis position (72h security logs, no room content, EU relay residency, GDPR Art 6(1)(f) legitimate interest), and the takedown-limit statement (the operator cannot read content or recall distributed material); adds three A6 items to the Phase 3 launch gate. Legal review is a named pre-launch dependency.
- [Supported platform matrix decision](platform-matrix-decision.md) - Decision record fixing the first-slice supported desktop OS and browser matrix, its mobile position under amendment A4, the test-lane mapping, and the pairing-success denominator.
- [Portable Iroh Rooms traits decision](iroh-rooms-portable-traits-decision.md) - Decision record choosing the audited short-lived patch path for the browser peer's portable store, blob, transport, clock, and task-scheduling traits, with its audit owner and recurring cost.
- [Phase 0 go/no-go gate verdict](phase-0-gate-verdict.md) - Dated verdict against each of the six Phase 0 gate conditions for the v0.6.0 candidate (922f620 + a5d98b70), each with linked evidence (issue #31).
- [Phase 1 go/no-go gate verdict](phase-1-gate-verdict.md) - GO recorded 2026-07-22: risk-owner countersigned the row #7 APPROVE-WITH-CONDITIONS re-review against candidate `df28f6a`; Phase 2 may begin; row #2 OPEN as accepted risk (opt-in encryption, F5); verdict conditions tracked.
- [Phase 1 security review scope](phase-1-security-review-scope.md) - The review package for gate row #7: the wire formats, key lifecycle, and enforcement surfaces, with files, tests, and design rationale.
- [Phase 1 security review — findings record](phase-1-security-review.md) - Durable record of the original NOT APPROVED verdict (10 findings), the completed remediation path (Steps 0–7), and the Step 7 independent re-review verdict of 2026-07-22: APPROVE-WITH-CONDITIONS against pin `df28f6a` (no blocker/high; conditions tracked); supersedes the prior self-review.
- [Phase 1 evidence package and approval contract](phase-1-evidence-package.md) - Reproducible evidence package (exact commands, expected results, test-to-finding mapping, threat-model cross-reference) plus the codified security-review approval contract (independence, severity taxonomy, blocking threshold, risk-owner, re-review rules).
- [Phase 1 implementation plan](phase-1-plan.md) - Sequencing, dependency order, gate mapping, and per-deliverable tasks for the seven Phase 1 production-identity and protocol-primitive deliverables unlocked by the Phase 0 gate.
- [Recovery bundle decision](recovery-bundle-decision.md) - Canonical / partial (ADR #3, amended 2026-07-21): versioned authenticated-encryption recovery bundle keyed by a random 256-bit key, user-held custody, and optional opaque cloud hosting; Phase-1 D1 slice adopted, password wrap + wider payload + setup-time test_restore are Phase 2 / unwired.
- [Room device key decision](room-device-key-decision.md) - Canonical / complete (issue #91): deterministic per-room device keys derived from the profile device seed (versioned BLAKE3 derive_key context), resolved through the room's signed membership binding, with a legacy collision guard — fixes multi-room live-receive collision without new persisted secrets or recovery-bundle changes.
- [Companion control protocol decision](companion-control-protocol-decision.md) - Canonical / adopted 2026-07-23 (ADR #2, control-key lifetime default fixed at 30 days): mutually-authenticated E2EE browser-to-companion control protocol (Noise XX-equivalent), SAS-confirmed pairing, non-extractable bounded-lifetime control key, default-deny scopes, replay defense, and revocation; D5b is now implementable, conformance checked at the D5b/D6 review gate.
- [Companion control wire protocol v1 (D5b/D6)](control-wire-protocol.md) - Draft / partial: the byte-level wire ADR #2 defers to D5 — the `/jeliya/control/1` ALPN, the D6 version hellos bound into the Noise `Noise_XX_25519_AESGCM_SHA256` prologue, the transcript-derived SAS, scoped-RPC framing with per-session replay windows, pairing enrollment, rate limits, revocation teardown, and persistence. Implemented in `crates/jeliya-protocol` + `crates/jeliya-control`; the Iroh transport and browser controller are the remaining D5b work. The D5b/D6 independent review gate approves it.
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
- [Store-degraded runbook](store-degraded-runbook.md) - Operator procedure for detecting and responding to a durable CRITICAL `store_degraded` trust decision (Phase 1 D7).
- [Historical Gate A result](gate-a-result.md) - Older direct-connectivity evidence that does not certify the v0.5.0 candidate.
- [Signing and notarization](signing-notarization.md) - Release-security plan for macOS and Windows artifacts.

## Language, identity, and governance

- [Internationalization](i18n.md) - Language roadmap and engineering rules for maintainable localization.
- [French glossary](glossary-fr.md) - Canonical French terminology and localization decisions.
- [Naming decision](naming.md) - Decision record and trademark research supporting the rename to Jeliya.
- [Documentation profile](PROFILE.md) - Metadata, navigation, linking, and CI rules for this wiki.
