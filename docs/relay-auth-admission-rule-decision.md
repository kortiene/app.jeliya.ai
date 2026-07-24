---
type: "Decision"
title: "Relay-auth admission rule and minting-cost bound — decision record"
description: "Defines what admits a relay-credential mint at relay-auth.jeliya.ai: a layered rule that mints only to a companion-countersigned non-extractable control key (proof of possession over an endpoint-bound challenge), bounds volume with per-control-key quotas and a global daily minting budget that sheds automatically at the #45 ceilings, reserves capacity for established paired keys under shed, and defers a privacy-preserving scarcity anchor behind a named trigger. Issue #49."
tags: ["decision", "deployment", "relay", "relay-auth", "abuse", "cost", "security", "phase-3"]
timestamp: "2026-07-24T13:00:00Z"
status: "canonical"
implementation_status: "planned"
verification_status: "unverified"
release_status: "unreleased"
audience: ["contributors", "maintainers", "release-engineers", "operators", "security-reviewers"]
---

# Relay-auth admission rule and minting-cost bound — decision record

**Status: DECIDED 2026-07-24 —** This record settles issue
[#49](https://github.com/kortiene/app.jeliya.ai/issues/49): it replaces the
undefined "after proof of possession" at
[Production deployment architecture](production-deployment.md) (relay-auth
admission) with a stated admission rule, and bounds credential minting as an
adversarial cost channel. It sets the *admission rule and the automatic cutoff*;
the *numeric ceilings the cutoff sheds against* are the
[relay load-and-cost-ceilings record](relay-load-and-cost-ceilings-decision.md)
(#45), which blocks and precedes this one. It decides intent and design only: it
asserts no provisioned relay-auth service and no measured production behavior.

## 0. The problem this closes

The relay design said a browser obtains a credential "after proof of possession"
without stating what is possessed or what admits. There are no accounts
([Production deployment architecture](production-deployment.md) "no tenant,
account, authorization-domain, quota, or public audit model"), and **an endpoint
identity is a keypair anyone generates offline** — so the "per-IP and
per-endpoint" limits do not bind: per-endpoint is free, and per-IP is defeated by
a proxy pool. Left open, the token service converts any keypair into paid relay
capacity, and the cost formula's `relayed GiB * provider egress rate` term is
unbounded ([Security threat model](security-threat-model.md), "Credential minting
as an abuse and cost channel").

**The honest fork:** who absorbs abuse — the budget (money, capped by #45) or
honest users (availability, if a shed locks everyone out)? The decision below is
a *layered* rule that bounds cost absolutely, raises the abuse floor, keeps honest
paired users online under pressure, and names the trigger to escalate.

## 1. The admission rule

relay-auth issues a relay credential when, and only when, all of the following
hold. This states **what is possessed, what is proven, and what admits**.

**Possessed.** A non-extractable browser **control key** `K` (the WebCrypto key
from amendment A1), plus a **companion countersignature** `σ_C` — a statement
signed by the paired companion during the D5b pairing ceremony asserting
"companion `C` admitted control key `K`, valid `[t, t+L]`" — plus the endpoint id
`E` the browser will present to the relay.

**Proven.**
1. **Possession of `K`:** a signature by `K` over a relay-auth challenge nonce
   bound to `E` (fresh challenge per mint; the token is endpoint-bound to `E`).
2. **A completed pairing:** `σ_C` verifies under the companion control-signing
   construction, so `K` was admitted through a real pairing ceremony, not a bare
   keypair.

**Admits.** A short-lived (≤ 60 s), endpoint-bound token is issued **iff** (1) and
(2) verify **and** `K` is within its per-key mint quota (§2) **and** the global
minting budget is not in shed — or, if in shed, `K` is an *established* key
drawing from the reserve (§3).

> **What the countersignature does and does not do — stated plainly.**
> relay-auth holds no pairing registry and companions are self-generated, so
> `σ_C` proves *a* pairing occurred, not that the companion is *distinct* or
> *legitimate*. It is a **floor-raiser and shape-binder** (an attacker must run
> the full companion pairing ceremony and hold a companion key per Sybil
> identity, and every token is scoped + short-TTL + endpoint-bound), **not a
> Sybil volume bound.** The volume bound comes from §2 and §3. This limitation is
> accepted, and its escalation path is §4.

## 2. Quotas and the global minting budget

These are the controls that **do not depend on endpoint identity being scarce**,
which the pre-existing per-IP / per-endpoint limits required.

| Control | Value (recommended, tunable) | Bounds |
|---|---|---|
| Per-control-key mint quota | 120 mints / rolling hour / `K` | a single key's linear consumption (2× the 1-per-minute re-mint rate) |
| Global daily minting budget | 2,000,000 mints / day | total mint volume — from #45 §2b |
| Global egress ceiling | 1,024 GiB / month | the `relayed GiB × egress rate` term — from #45 §2a |
| Global spend cap | $900 / month all-in | the invoice — from #45 §2c |

**Alerts** inherit #45: 60% / 85% on mints-per-day and egress, 70% / 90% on
spend. **Automatic shed:** when any global ceiling is reached, relay-auth stops
minting new tokens (existing relay sessions are not torn down) and alerts. This
bounds the cost formula's `relayed GiB × provider egress rate` term at
[Production deployment architecture](production-deployment.md) (relay cost
formula).

## 3. Shed policy — reserve for established paired keys

A flat global shed would let an abuse-driven ceiling hit lock out honest new
sessions. Instead, relay-auth keeps a **TTL'd set of *established* control keys** —
a key that completed ≥ 1 successful mint-and-relay-connect in the trailing 7 days
(a bounded, expiring set of key hashes, adding no identity linkage beyond the
mint requests relay-auth already observes per
[Security threat model](security-threat-model.md) TB2).

- **Reserve:** 25% of the daily minting budget is reserved for established keys.
- **Under shed:** established keys continue to mint from the reserve within their
  per-key quota; **new / unestablished keys are refused first.** Honest users who
  have already paired and connected stay online; a Sybil flood of fresh keys hits
  the wall first.

## 4. Deferred scarcity anchor + named trigger

No privacy-preserving scarcity anchor (proof-of-work, attestation, CAPTCHA) ships
in the first slice — it would add honest-user friction and, for attestation, a
third party and metadata cost against the local-first, no-accounts grain. It is
**deferred behind a named, measurable trigger.**

**Trigger to adopt an adaptive proof-of-work anchor** (recorded in a follow-up
decision when it fires): either
- automatic shed is triggered by **new / unestablished keys more than once in any
  rolling 7-day window**, or
- the global daily minting budget is **exhausted by non-established keys on ≥ 2
  days in a rolling 30-day window**.

On trigger, adopt **adaptive proof-of-work** on mint requests — honest cost ≈ 0,
a flood pays escalating cost, no third party and no account. Attestation/CAPTCHA
remain rejected for the reasons above unless PoW proves insufficient.

## 5. What exercises this rule (Phase 0 vs Phase 3)

The Phase 0 relay-connect spike proved the **transport plane** with a
spike-quality token (Ed25519 proof-of-possession, 60 s, endpoint-bound) that
carried **no** companion countersignature and **no** quotas — explicitly a
transport-plane stand-in, recorded as *not* the production rule
([Phase 0 relay-connect spike result](evidence/phase-0-relay-spike.md) "What the
spike does and does not prove";
[Production provider selection decision](provider-selection-decision.md) "Relay
credential model"). **No production gate is passed on that stand-in.** The
admission rule defined here is the one the **Phase 3** real-relay validation and
load test exercise; adopting it in the managed-relay `AccessControl` is Phase 3
implementation work.

## 6. Relay-auth key custody (pointer, not decided here)

relay-auth holding the project credential means its compromise equals
project-secret compromise ([Security threat model](security-threat-model.md),
"Relay-auth service compromise"). The **custody model** (static key, sealed
secret, or KMS-backed key) is tracked in the
[Production ownership record](production-ownership.md) §2 "Relay-auth signing-key
custody" and must be chosen before the launch relay-auth design is finalised.
This record does not settle it; the admission rule above is independent of which
custody model is chosen.

## 7. Edits applied with this record

- [Production deployment architecture](production-deployment.md) relay-auth
  admission bullet — "after proof of possession" replaced by a pointer to §1's
  rule (AC1).
- [Production deployment architecture](production-deployment.md) "Abuse controls"
  list — gains per-control-key mint quotas and a global daily minting budget that
  do not depend on endpoint scarcity (AC2).
- [Production deployment architecture](production-deployment.md) highest-risk
  unknown 2 ("Browser relay-auth token issuance and proof-of-possession
  behavior") — restated as settled by this record, residual named (AC6).

## 8. Acceptance-criteria mapping (issue #49)

- *Admission rule replaces "after proof of possession" and states what is
  possessed, proven, and what admits — issuance to a companion-paired control
  key, a rate token, or recorded open minting* — §1 (companion-paired control key
  chosen; rate token deferred §4; open minting rejected).
- *Abuse-control list gains per-issuance quotas, a quota not dependent on endpoint
  scarcity, and a global daily minting budget* — §2, edit §7.
- *A stated GiB and monthly spend cutoff sheds minting automatically and alerts at
  a stated fraction* — §2 (from #45 §2a/§2c), §3.
- *The Phase 0 deliverable and gate exercise the chosen admission rule, not an
  unauthenticated stand-in* — §5 (Phase 0 spike is a transport-plane stand-in by
  record; the rule is exercised at Phase 3; no production gate rides the
  stand-in).
- *The Phase 3 gate names this published cutoff as the ceiling it is evaluated
  against* — the [#45 record](relay-load-and-cost-ceilings-decision.md) §4 restated
  the gate line against the published ceilings; this record defines the cutoff
  that enforces them.
- *Highest-risk unknown 2 is closed or restated* — §7 edit closes it for the
  admission-rule dimension; the residual Sybil-companion availability risk is
  named (§1 note, §3, §4).

## 9. Citations

- [Production deployment architecture](production-deployment.md) — relay-auth
  admission ("after proof of possession"), no-accounts model, abuse-control list,
  cost formula, Phase 0 relay deliverable/gate, Phase 3 gate, highest-risk
  unknown 2.
- [Relay load-and-cost-ceilings record](relay-load-and-cost-ceilings-decision.md)
  (#45) — the egress / mint / spend ceilings and alert fractions this rule sheds
  against.
- [Security threat model](security-threat-model.md) — TB2 relays/relay-auth,
  credential-minting-as-cost-channel, relay-auth-compromise, control-traffic
  observation.
- [Companion control protocol decision](companion-control-protocol-decision.md)
  and [Companion control wire protocol](control-wire-protocol.md) — the
  non-extractable control key and the pairing ceremony the countersignature comes
  from.
- [Phase 0 relay-connect spike result](evidence/phase-0-relay-spike.md) —
  transport-plane PASS; spike-quality token is not the production rule.
- [Production provider selection decision](provider-selection-decision.md) —
  relay credential model, custody-model pointer.
