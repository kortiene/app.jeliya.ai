---
type: "Decision"
title: "Production provider selection — decision record"
description: "Decides the DNS, CDN/static host, edge-token service, dedicated relay deployment, object store, infrastructure-as-code tool, and native signing services for app.jeliya.ai, confirming the initial choice in the production deployment plan and recording its reversibility position."
tags: ["decision", "deployment", "infrastructure", "dns", "cdn", "relay", "signing", "phase-0"]
timestamp: "2026-07-20T21:10:00Z"
status: "canonical"
implementation_status: "planned"
verification_status: "unverified"
release_status: "unreleased"
audience: ["contributors", "maintainers", "release-engineers", "security-reviewers", "operators"]
---

# Production provider selection — decision record

**Status: DECIDED 2026-07-20 —** This record settles deferred decision 1 of the
[production deployment decision](production-deployment-decision.md) — "Final
CDN, edge-token, relay, and infrastructure provider selection" — for the first
production slice at `app.jeliya.ai`. It confirms the initial infrastructure
choice recorded at [Production deployment architecture](production-deployment.md)
lines 562-572 and replaces none of it. It decides intent only: nothing in this
record asserts that any provider account is provisioned, that any production
origin resolves, that any provider capability is verified, or that any artifact
is released or certified. The status pages — [Production ownership
record](production-ownership.md), [Signing and
notarization](signing-notarization.md), and [Capability
status](capability-status.md) — remain the source of truth for what exists,
and their implementation, verification, and release columns are not advanced by
this record.

This record gives the Phase 0 deliverable "confirm DNS, CDN, relay, and signing
ownership" ([Production deployment architecture](production-deployment.md),
Phase 0 deliverable) its subject — a named provider and a named owning account
holder for each surface. It does **not** close that ownership deliverable:
closure lives in the [Production ownership record](production-ownership.md),
which remains a `proposal` (issue [#24](https://github.com/kortiene/app.jeliya.ai/issues/24))
until its controlling-identity, deputy, fallback-provider, and account-identifier
TODOs are filled and the maintainer signs it `canonical`. This record settles the
provider-selection decision (issue [#27](https://github.com/kortiene/app.jeliya.ai/issues/27))
only; it does not authorize Phase 1 implementation.

## Decision

The initial infrastructure choice at [Production deployment
architecture](production-deployment.md) lines 562-572 is **confirmed in full**
and **replaced in part by none**. The selected set is:

| Surface | Provider | Owning account holder |
|---|---|---|
| DNS zone `jeliya.ai` (authoritative) | Cloudflare DNS | the maintainer (release authority); zone/account identifiers recorded in [Production ownership record](production-ownership.md) §1 |
| Static CDN and host for `app.jeliya.ai` / `staging.app.jeliya.ai` | Cloudflare Pages, receiving an already-built immutable artifact | the maintainer; project identifier recorded in [Production ownership record](production-ownership.md) §2 |
| Edge-token service behind `relay-auth.jeliya.ai` | Cloudflare Worker | the maintainer; Worker project identifier recorded in [Production ownership record](production-ownership.md) §2 |
| Dedicated relay 1 (primary region: North America) | Iroh managed dedicated relay | the maintainer; relay project identifier recorded in [Production ownership record](production-ownership.md) §2 |
| Dedicated relay 2 (failover region: Europe) | Iroh managed dedicated relay | the maintainer; relay project identifier recorded in [Production ownership record](production-ownership.md) §2 |
| Later component / recovery object store | Cloudflare R2, private bucket, protected by signed metadata and application encryption | the maintainer; bucket identifier recorded in [Production ownership record](production-ownership.md) §2 |
| Infrastructure-as-code | OpenTofu under `infra/` | the maintainer |
| macOS signing and notarization | Apple Developer ID + `xcrun notarytool` app-specific-password route | the maintainer (individual enrollment); see [Signing and notarization](signing-notarization.md) |
| Windows signing | Azure Artifact Signing (cloud HSM) | the maintainer (scoped Microsoft Entra principal); see [Signing and notarization](signing-notarization.md) |
| Linux release integrity | checksum + provenance publication (no platform signing service) | the maintainer; see [Signing and notarization](signing-notarization.md) |

The signing account holder for Apple Developer enrollment and for Authenticode
issuance is the maintainer (release authority), recorded by explicit reference
to [Signing and notarization](signing-notarization.md) "Procurement status
(Phase 0)" and "Custody, rotation, and incident response", which name the
holder, the custody model, and the dated procurement log. That record, not this
one, carries the procurement state and the calendar lead time.

Where the table names the maintainer as the owning account holder, the specific
account identifiers (Cloudflare zone ID, Pages and Worker project IDs, the two
Iroh relay project IDs, the R2 bucket name) are not yet provisioned and are
tracked as TODO markers in the [Production ownership
record](production-ownership.md). Naming the maintainer as the subject is what
closes the Phase 0 ownership deliverable for this record; filling the
identifiers is the separate, open work tracked on
[#24](https://github.com/kortiene/app.jeliya.ai/issues/24) and recorded in
[Production ownership record](production-ownership.md) §7 ("What does not yet
exist").

## Reversibility

The provider choice is reversible, as [Production deployment
architecture](production-deployment.md) lines 574-577 state. A provider
migration would require, per surface:

- **DNS** — re-delegation of the `jeliya.ai` zone to a new authoritative
  provider, re-issued CAA records, and re-issued TLS certificates. The planned
  OpenTofu DNS module under `infra/` ([Production deployment
  architecture](production-deployment.md) line 572) will make the record set
  portable once it exists; no `infra/` tree is present in the repository today,
  so record-set portability is future work, not a current capability. The
  registrar account and DNSSEC chain are the slow part regardless.
- **Static CDN / host** — republishing the already-built immutable artifact to a
  new static host and repointing the DNS record. The build is
  provider-independent because the CDN receives an artifact, not source.
- **Edge-token service** — re-implementing the `relay-auth.jeliya.ai` admission
  rule against a new compute platform. The admission rule is the portable part;
  the Cloudflare Worker binding is not.
- **Dedicated relays** — re-pointing the relay configuration in `infra/` at new
  relay endpoints. The threat-model residual escape — a self-hosted iroh-relay
  with HTTP-callout admission — is the documented fallback if a managed-relay
  provider's authentication or identity requirements cannot satisfy the threat
  model (see [Security threat model](security-threat-model.md) TB2 residual, and
  [Production ownership record](production-ownership.md) §3).
- **Object store** — re-creating the private bucket and re-uploading
  application-encrypted objects. Signed metadata and application encryption keep
  the store provider-independent at the object layer.
- **Signing** — re-enrollment and re-vetting on a new platform, which is
  calendar time (see [Signing and notarization](signing-notarization.md)).
  Signing is the least reversible surface because of CA vetting and Apple /
  Windows organizational identity.

If provider-specific relay authentication or identity requirements cannot
satisfy the threat model, Phase 0 must choose an equivalent static CDN, edge
token service, and dedicated relay deployment before implementation starts.
This record names the fallback for each surface in [Production ownership
record](production-ownership.md) §3 (Fallback provider set) rather than leaving
it to be chosen under pressure; that section's TODO markers are the open part
of the fallback decision.

## Relay credential model

The endpoint-bound short-lived credential **pattern** is proven at the transport
plane. Whether the **managed** Iroh relay service supports externally-issued,
endpoint-bound admission tokens at production scale is **unverified** and is
recorded as such here, pending vendor/config confirmation. The Phase 0
relay-connect spike ([Phase 0 relay-connect spike
result](evidence/phase-0-relay-spike.md), issue
[#23](https://github.com/kortiene/app.jeliya.ai/issues/23)) recorded PASS on
Chromium, Firefox, and WebKit: a browser obtains a short-lived (60 s),
endpoint-bound credential from a relay-auth HTTP service after Ed25519 proof of
possession, presents it as the relay admission token, and establishes an
end-to-end-encrypted iroh connection through a dedicated relay. That run used a
dedicated **local** `iroh-relay 1.0.1` server with a custom `AccessControl`; it
proves the credential pattern and the browser-to-native transport, not that a
managed Iroh relay can be configured to honour externally-issued tokens. It
discharges the Phase 0 gate item "a browser reaches a native test endpoint
through an authenticated relay" and answers the planning assumption "Dedicated
relay service supports the required endpoint-bound short-lived credentials"
([Production deployment architecture](production-deployment.md), planning
assumptions) at the transport plane only. If vendor/config confirmation for the
managed Iroh relays does not satisfy the threat model, the equivalent
self-hosted design — a self-hosted iroh-relay with HTTP-callout admission (see
Reversibility, and [Security threat model](security-threat-model.md) TB2
residual) — is the recorded fallback path, selected instead.

Two properties of the credential model are **binding design requirements** of
this record, restated against the relay-design section ([Production deployment
architecture](production-deployment.md) lines 547-552). They are requirements,
not verified production properties:

- The project API secret must never enter static assets. The spike's
  static-asset secret scan (12 candidate key-shaped strings across the served
  HTML/JS/wasm, none matching the spike's relay-auth signing key) confirms only
  that the **spike's** signing material was absent from the spike's served
  assets; the spike had no managed-relay project API secret at all, so that scan
  does not certify the production Worker/Pages secret-bundling posture. The
  production design keeps the project secret server-side in the
  `relay-auth.jeliya.ai` Worker and mints per-peer endpoint-bound tokens; a
  secret-specific gate on the real Worker/Pages build must close this before
  launch and is recorded as open.
- Native companions must use the same short-lived credential policy rather than
  embedding a global project secret.

What is **not** settled by this record, and is explicitly out of scope:

- The production token format, signing algorithm, admission rule, and
  relay-auth signing-key custody model. The spike's token format is
  spike-quality and is recorded as **not** the one production should adopt
  ([Phase 0 relay-connect spike result](evidence/phase-0-relay-spike.md) "What
  the spike does and does not prove"). The production custody model (static
  key, sealed secret, KMS-backed key, or other) is the unresolved decision
  recorded in [Production ownership record](production-ownership.md) §2
  "Relay-auth signing-key custody", and must be chosen before the launch
  relay-auth design is finalised. The relay-auth admission rule and the
  credential-minting cost channel are separately deferred (issue
  [#49](https://github.com/kortiene/app.jeliya.ai/issues/49)).
- Whether a managed Iroh relay can be configured to accept an
  externally-issued, endpoint-bound admission token at production scale. The
  spike ran against a dedicated local `iroh-relay 1.0.1` server with a custom
  `AccessControl`; the production managed-relay configuration that admits
  externally-issued tokens is implementation work for Phase 3, not a Phase 0
  decision, and is recorded as unverified here.

## Relay topology and sensitive metadata

The selection covers two dedicated managed relays, one in North America and one
in Europe, matching [Production deployment architecture](production-deployment.md)
lines 544-545, and preserves the ability to move to self-hosted relays through
configuration and infrastructure-as-code (OpenTofu under `infra/`) as required
at lines 553-554.

Relays are not room members and retain no room history. The chosen design treats
source IPs, endpoint routing, timing, and traffic volumes as sensitive metadata
even though room content remains encrypted from the relay ([Production
deployment architecture](production-deployment.md) lines 555-556). That is the
lens through which the managed-relay provider's authentication and identity
requirements are judged against the threat model: a managed relay that required
identity disclosure, source-IP logging, or traffic-volume reporting
inconsistent with [Security threat model](security-threat-model.md) would
trigger the fallback in the Reversibility section above. This
metadata-sensitivity judgement is recorded here as the condition the chosen
provider must continue to meet; it is not a one-time check.

## Cost basis

Recurring relay cost is measured as recorded at [Production deployment
architecture](production-deployment.md) lines 829-832:

```text
monthly relay cost =
  relay instance-hours
  + relayed GiB * provider egress rate
  + managed support or SLA charges
```

Per-user pricing is not published until real room size, online time, and
file-transfer distributions are measured ([Production deployment
architecture](production-deployment.md) lines 836-837). Browser peers are
always relayed, so file traffic can dominate cost; cost ceilings are now
published in the [relay load-and-cost-ceilings
record](relay-load-and-cost-ceilings-decision.md) (#45) as **aggregate** caps —
a $900/month all-in spend cap, a 1,024 GiB/month egress ceiling across all
production relays, a 2,000,000/day token-mint ceiling, and a 5 ms p95 relay-auth
CPU ceiling, each with alert fractions. That record's cost table carries the
per-environment (production, staging, CI, dev) arithmetic, and the Phase 3 gate
is restated against these ceilings there.

## Rejected alternatives

- **Hosted gateway / server-trust architecture** — rejected for the reasons in
  [Production deployment decision](production-deployment-decision.md): it would
  replace Jeliya's privacy and local-first boundaries with server trust.
  Reversing to it would be a product-strategy change, not a provider migration.
- **Browser-only peer (no companion, no relayed native)** — rejected in the
  same record; the repository contains neither the browser storage nor the
  network runtime a browser-only peer needs. Reversing to it depends on Phase 4
  work that does not exist yet.
- **Self-hosted relays from day one** — rejected as the primary because the
  managed-relay path satisfies the threat model at lower operational cost and
  preserves the self-hosted fallback through `infra/`. The cost of reversing to
  self-hosted relays is the availability and on-call cost the plan moves to the
  team ([Production deployment architecture](production-deployment.md) lines
  825-827).
- **A raw `.pfx` Windows signing secret** — rejected in [Signing and
  notarization](signing-notarization.md); its procedure is no longer documented
  and its secrets must never be created. Reversing to it would re-introduce a
  custodied certificate file against the recorded decision.

## What this record does not assert

- It does not assert that any Cloudflare, Iroh, Azure, or Apple account exists;
  [Production ownership record](production-ownership.md) §7 records that none is
  provisioned.
- It does not assert that `jeliya.ai`, `app.jeliya.ai`,
  `staging.app.jeliya.ai`, or `relay-auth.jeliya.ai` resolves; the decision
  record noted no resolvable record at decision time, and [Production ownership
  record](production-ownership.md) §1 records that none resolves now.
- It does not assert that any production relay-auth admission rule is final;
  the spike proved the transport pattern, the production custody model is open
  (see Relay credential model).
- It does not advance the implementation, verification, or release status of
  any provider surface; those columns live in [Production ownership
  record](production-ownership.md), [Signing and notarization](signing-notarization.md),
  and [Capability status](capability-status.md).

## Acceptance criteria mapping

This record maps to the acceptance criteria of
[#27](https://github.com/kortiene/app.jeliya.ai/issues/27):

- Decision record under `docs/`, reachable from `docs/index.md`, `node
  scripts/check-docs.mjs` passes — this file, linked from [index.md](index.md).
- `type: "Decision"` and the ten required front-matter fields with controlled
  values — front-matter above.
- Names which of the initial choices are confirmed and which replaced —
  Decision section: all confirmed, none replaced.
- Names provider and owning account holder for DNS, CDN/static host,
  `relay-auth.jeliya.ai`, relay operator + two regions, object store, IaC tool,
  and macOS/Windows/Linux signing — Decision table.
- States whether the selected relay supports endpoint-bound short-lived
  credentials, or names an equivalent self-hosted design — Relay credential
  model section; the self-hosted fallback is named in Reversibility.
- States the reversibility position and what a migration requires —
  Reversibility section.
- Names the account holder for Apple Developer enrollment and Authenticode
  issuance, or defers each by explicit reference — Decision table and Decision
  section, deferring to [Signing and notarization](signing-notarization.md).
- Opens with a DECIDED status line with a date, asserts nothing as
  verified/released/certified — Status line above; front-matter
  implementation_status `planned`, verification_status `unverified`,
  release_status `unreleased`.
- Settles ADR item 1 by naming the static CDN and host, the edge token service,
  and the dedicated relay deployment — Decision table.
- States whether the chosen relay lets a browser obtain a short-lived
  endpoint-bound credential after proof of possession, citing the Phase 0 gate
  result — Relay credential model section, citing [Phase 0 relay-connect spike
  result](evidence/phase-0-relay-spike.md).
- States the project API secret and native-companion credential rules as binding
  design requirements (the spike scan does not certify the production
  secret-bundling posture) — Relay credential model section.
- Covers two dedicated managed relays (NA + EU) and preserves the self-hosted
  path through IaC — Relay topology section.
- Treats source IPs, routing, timing, and traffic volumes as sensitive metadata
  when judging provider relay-auth/identity against the threat model — Relay
  topology section.
- States the recurring cost basis and that per-user pricing is unpublished
  until measured — Cost basis section.
- Records rejected alternatives and the cost of reversing the selection —
  Rejected alternatives section.

## Citations

- [Production deployment architecture](production-deployment.md) — initial
  infrastructure choice (lines 562-572), reversibility (lines 574-577), relay
  design (lines 544-559), cost basis (lines 826-840), Phase 0 deliverable and
  gate, planning assumptions, ADR item 1.
- [Production deployment decision](production-deployment-decision.md) — deferred
  decision 1, rejected architecture alternatives, signing lead time, no-DNS
  note.
- [Production ownership record](production-ownership.md) — owning account
  holders, account-identifier TODOs, fallback provider set, environment
  separation, "what does not yet exist".
- [Signing and notarization](signing-notarization.md) — signing account holder,
  custody, the `.pfx` rejection.
- [Phase 0 relay-connect spike result](evidence/phase-0-relay-spike.md) —
  transport-plane PASS for browser-to-native through an authenticated relay;
  spike-quality token caveat.
- [Security threat model](security-threat-model.md) — TB2 self-hosted-relay
  fallback, environment bleed, credential-minting-as-abuse-channel.
