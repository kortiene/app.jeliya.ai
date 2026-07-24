---
type: "Reference"
title: "Production ownership record"
description: "Who controls the jeliya.ai zone, CDN, relay, edge-token, and signing accounts, and who can approve a production change — the Phase 0 ownership deliverable (issue #24)."
tags: ["phase-0", "ownership", "governance", "security", "dns", "cdn", "relay", "signing"]
timestamp: "2026-07-20T20:50:00Z"
status: "proposal"
implementation_status: "planned"
verification_status: "partial"
release_status: "unreleased"
audience: ["maintainers", "release-engineers", "security-reviewers", "operators"]
---

# Production ownership record

This is the Phase 0 deliverable "confirm DNS, CDN, relay, and signing
ownership" from [Production deployment
architecture](production-deployment.md#dependency-ordered-roadmap-and-gates).
It records **who controls** each production-trust account, **who can
approve** a production change, and **what the fallback is** when a chosen
provider cannot satisfy the threat model. It is the single place an incident
commander looks during a compromise to find "who can revoke this, right now."

> **This record is a partial draft.** Fields marked `<TODO: ...>` require the
> maintainer's direct input (account identifiers, owner names, deputy names,
> provider choices). Every TODO maps to one acceptance criterion on
> [#24](https://github.com/kortiene/app.jeliya.ai/issues/24). The record's
> `status` stays `proposal` until every TODO is filled and the maintainer
> signs it as `canonical`.

## 1. Registrar, DNS zone, and controlling identity

| Property | Value |
|---|---|
| Domain | `jeliya.ai` |
| Registrar account | `<TODO: registrar name + account identifier — #24 criterion 1>` |
| Registrar account owner | `<TODO: the human identity (name or role) that controls the registrar login; must match the legal entity behind app.jeliya.ai per amendment A6>` |
| Registrar account MFA | `<TODO: hardware key / TOTP; record the recovery-custody arrangement>` |
| DNS zone control | `<TODO: the service that hosts the authoritative zone (registrar-managed, Cloudflare, Route 53, etc.) and the identity that can edit records>` |
| DNSSEC | planned (see [Threat model](security-threat-model.md): DNSSEC, restrictive CAA, managed TLS renewal); `<TODO: enable state recorded here once configured>` |
| CAA record | `<TODO: the CA(s) authorised to issue for jeliya.ai, recorded once the CDN/TLS provider is chosen>` |

### Current resolution state (recorded 2026-07-20)

The decision record noted "`app.jeliya.ai` had no resolvable A, AAAA, or
CNAME record at the time of this record." That remains the case for every
production name. None of these implies a production origin exists:

| Name | A | AAAA | CNAME | State |
|---|---|---|---|---|
| `jeliya.ai` | — | — | — | **does not resolve** |
| `app.jeliya.ai` | — | — | — | **does not resolve** |
| `staging.app.jeliya.ai` | — | — | — | **does not resolve** |
| `relay-auth.jeliya.ai` | — | — | — | **does not resolve** |

## 2. CDN, edge-token service, and dedicated relay projects

Phase 3 deploys DNS, TLS, CDN, CSP, and two dedicated relays onto whatever
these accounts turn out to be. None exists yet; this section records the
plan so a launch blocker or single-point-of-failure cannot hide in an
unowned account.

| Surface | Provider + account | Controlling identity | Billing owner |
|---|---|---|---|
| Static CDN / host for `app.jeliya.ai` | `<TODO: #24 criterion 2>` | `<TODO>` | `<TODO>` |
| Edge token service behind `relay-auth.jeliya.ai` | `<TODO: e.g. Cloudflare Worker, separate Worker project>` | `<TODO>` | `<TODO>` |
| Dedicated relay 1 (primary region) | `<TODO: provider + project id>` | `<TODO>` | `<TODO>` |
| Dedicated relay 2 (failover region) | `<TODO: provider + project id>` | `<TODO>` | `<TODO>` |
| Relay-auth signing-key custody | `<TODO: UNRESOLVED production custody decision — the Phase 0 spike (issue [#68](https://github.com/kortiene/app.jeliya.ai/issues/68), [phase-0-relay-spike.md](evidence/phase-0-relay-spike.md) lines 127-131) generated an Ed25519 key in-process per restart as explicit spike-quality behaviour that the evidence record states is *not* the format/signing algorithm/admission rule production should adopt. A per-restart key either invalidates in-flight tokens or forces the verifying key to be re-synchronised to every relay before it can admit clients; the launch custody model (static key, sealed secret, KMS-backed key, or other) must be chosen and recorded here before the launch relay-auth design is finalised>` | `<TODO>` | n/a (no billing surface) |

### Cost ceilings

[Production deployment architecture](production-deployment.md) names "cost
ceilings" as a Phase 3 gate. These are now **recorded** in the [relay
load-and-cost-ceilings record](relay-load-and-cost-ceilings-decision.md) (#45):
a $900/month all-in spend cap, a 1,024 GiB/month relay-egress ceiling, and a
2,000,000/day token-mint ceiling, each with alert fractions, sized at a
conservative $0.15/GiB. The alert-and-automatic-cutoff that sheds minting when a
ceiling is reached is the separate admission-rule decision (issue #49). The open
item that remains here is the per-provider account identifiers and the
relay-auth signing-key custody model in §2, not the ceilings themselves.

## 3. Fallback provider set

[Production deployment architecture](production-deployment.md) lines 565-568
make the provider choice reversible: if provider-specific relay
authentication or identity requirements cannot satisfy the threat model,
Phase 0 must choose an equivalent static CDN, edge token service, and
dedicated relay deployment before implementation starts. This section
records that fallback so it is a decision, not a panic.

| Surface | Primary (chosen above) | Pre-recorded fallback |
|---|---|---|
| Static CDN / host | `<TODO>` | `<TODO: #24 criterion 3>` |
| Edge token service | `<TODO>` | `<TODO>` |
| Dedicated relays (×2) | `<TODO>` | `<TODO: self-hosted iroh-relay with HTTP-callout admission is the documented escape (see [Threat model](security-threat-model.md) TB2 residual)>` |

The fallback decision must be written down **before** the primary is
committed, not after it fails — the point of the Phase 0 gate is that a
provider-replacement path exists in writing.

## 4. Production-approval authority and signing custody

The production-approval authority is the human who can authorise a release
to ship from the protected production environment. Signing custody is the
human who holds (or can rotate) each platform signing credential.

| Role | Holder | Deputy | Degraded mode while holder unavailable |
|---|---|---|---|
| Production-approval authority | `<TODO: #24 criterion 4>` | `<TODO>` | `<TODO: must match "no promotions" minimum; record the exact operations blocked>` |
| Apple Developer account + notarization app-specific password | maintainer (per [Signing](signing-notarization.md)) | `<TODO: named deputy — currently no deputy exists, recorded as a gap at signing-notarization.md:116-118>` | no promotions and no signing-enabled releases; rollback to already-published artifacts only (recorded at [Signing](signing-notarization.md):114-118) |
| Windows / Azure Artifact Signing | maintainer (per [Signing](signing-notarization.md)) | `<TODO: named deputy>` | as above |
| Linux (checksum + provenance) | maintainer | `<TODO>` | `<TODO>` |
| Ed25519 evidence signing key | release authority, out of band | `<TODO>` | no signed qualification runs until the key custodian is reachable; existing signed manifests remain valid |

The degraded modes above are the existing, documented signing-custody
behaviour from [Signing and notarization](signing-notarization.md). What is
missing is a **named deputy** for each credential — the single documented
gap that this record is responsible for closing.

### Incident-response quick reference

On suspected compromise of any of the above, the first action is to **cut
off the ability to produce new signatures / approvals**, then revoke what
was issued. The per-credential revocation procedure is recorded at
[Signing and notarization](signing-notarization.md):104-113 and is not
duplicated here — this record names the **people**, that record names the
**mechanism**.

## 5. Environment separation

[Production deployment architecture](production-deployment.md) lines 560-562
require separate development, staging, and production origins, relay
projects, trust roots, credentials, and browser storage. This section
records the concrete plan.

| Dimension | Development | Staging | Production |
|---|---|---|---|
| Origin | `localhost` (and per-branch preview deploys **only if isolated** per the note below) | `staging.app.jeliya.ai` | `app.jeliya.ai` |
| Relay project | `<TODO: dedicated test relay or loopback>` | `<TODO: dedicated staging relay>` | dedicated relay 1 + relay 2 (§2) |
| Trust root | local self-signed | `<TODO: staging CA / internal>` | Web PKI + `<TODO: pinning decision>` |
| Signing credential | none (unsigned dev builds) | none (unsigned staging builds) | Apple Developer ID + Azure Artifact Signing |
| Browser storage | per-developer profile | dedicated staging browser profile | per-user production profile |
| Evidence key | not used | not used | Ed25519 production key (out of band) |
| GitHub environment | `<TODO: dev env name or none>` | `<TODO: staging env name>` | `<TODO: production env name — must require manual approval per production-deployment.md:670>` |

`<TODO: #24 criterion 5 — record the concrete GitHub environment names once
they exist, and confirm that staging credentials cannot mint production
relay capacity (the threat-model risk of environment bleed:
security-threat-model.md TB2 "Environment bleed").>`

**Preview-deploy isolation (threat-model residual,
[security-threat-model.md](security-threat-model.md) line 261).** Per-branch
preview deploys (Cloudflare Pages preview, Vercel, etc.) become near-production
origins that lack the production header set, HSTS, DNSSEC, and CAA controls,
and that any pairing or relay-auth flow would accept unless it pins the exact
production origin. Before preview deploys are enabled on the production CDN
project, EITHER disable them at the provider OR record them here as a separate
isolated environment with **no** production trust roots, **no** production
relay-auth or relay capacity, and **no** shared browser storage.
`<TODO #24: record the choice (disable vs isolated), and if isolated, the
exact origin allowlist that pairing and relay-auth pin to. Until that choice
is recorded, preview deploys for the production CDN project remain disabled.>`

## 6. Credential strategy

Every account in §1 and §2 must be reached through the narrowest credential
the provider supports, preferring workload identity / OIDC where available and
otherwise a scoped, rotated deployment token. **No shared personal login
remains** — including the registrar login that controls the `jeliya.ai` zone
and the authoritative-DNS edit credential, either of which can redirect or
take over `app.jeliya.ai` before any CDN or relay control matters. Production
DNS records are managed by OpenTofu under `infra/`
([production-deployment.md](production-deployment.md):572,869), so the
registrar and DNS credentials are deployment credentials for this section,
not out-of-band personal logins.

| Surface | Credential type | Rotation |
|---|---|---|
| Registrar account (zone control of `jeliya.ai`) | `<TODO: scoped API token with only DNS/zone-delegation scope, or OIDC via the registrar's OpenTofu provider — personal console login retained only for break-glass recovery>` | revocable + re-issuable from a second factor-controlled recovery path; rotate `<TODO: cadence>` |
| Authoritative DNS zone (record edits via OpenTofu) | `<TODO: OpenTofu provider auth via GitHub Actions OIDC workload identity, else scoped API token in GitHub Actions secret>` | `<TODO: token rotation cadence; OpenTofu-applied record changes recorded in commit history>` |
| Static CDN deploy | `<TODO: OIDC via GitHub Actions / scoped deploy token>` | `<TODO>` |
| Edge token service deploy | `<TODO>` | `<TODO>` |
| Relay project deploy | `<TODO>` | `<TODO>` |
| Apple notarization | app-specific password in GitHub Actions secret (per [Signing](signing-notarization.md)) | revocable + re-issuable from the Apple account |
| Azure Artifact Signing | scoped Microsoft Entra principal (per [Signing](signing-notarization.md)) | short-lived certs rotate automatically inside the service; Entra principal reviewed `<TODO: cadence>` |
| Evidence signing key | out-of-band private key | `<TODO: rotation procedure>` |

`<TODO: #24 criterion 6 — record, for each surface, that the GitHub
environment uses the narrowest credential available and that no shared
personal login remains. This is what the threat model's TB1/TB2 residual
("a compromised origin or CDN") is downstream of.>`

## 7. What does not yet exist

This record states explicitly, rather than implying:

- `jeliya.ai`, `app.jeliya.ai`, `staging.app.jeliya.ai`, and
  `relay-auth.jeliya.ai` **do not resolve** (§1).
- No CDN, edge-token service, or dedicated relay project has been
  provisioned (§2).
- No Apple Developer enrollment has been submitted and no Azure subscription
  + Artifact Signing account has been created (see [Signing and
  notarization](signing-notarization.md):124-125 dated log).
- No production-approval deputy is named (§4).
- No GitHub production environment requiring manual approval is configured
  (§5, §6).

These are the Phase 0 ownership gaps. They close when each `<TODO>` above is
filled and the maintainer signs this record as `canonical`.

## Maintenance

- Update this record whenever a provider choice is made, a credential is
  rotated, or a holder/deputy changes. Do not let it drift from reality —
  during an incident is the worst time to discover the record is stale.
- The record is `canonical` only when zero `<TODO>` markers remain and the
  maintainer has signed it; until then it is `proposal`.

## Citations

- [Production deployment architecture](production-deployment.md) — Phase 0 deliverable, environment separation, cost ceilings, fallback provider gate.
- [Production deployment decision](production-deployment-decision.md) — amendments A6 (legal owner), A2 (hostile-frontend containment), A3 (companion update path) all depend on knowing who owns what.
- [Signing and notarization](signing-notarization.md) — per-credential custody, rotation, incident response, and the existing "named deputy does not exist yet" gap.
- [Security threat model](security-threat-model.md) — TB1/TB2/TB3 boundaries, DNS compromise, credential-minting-as-abuse-channel, environment bleed.
