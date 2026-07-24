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

relay-auth admits a mint in one of two tiers, both stating **what is possessed,
what is proven, and what admits**. The difference is whether a pairing exists yet.

### 1a. Post-pairing tier (the normal path)

**Possessed.** A non-extractable browser **control key** `K` (the WebCrypto
**X25519** key from amendment A1), a **companion countersignature** `σ_C` — a
statement signed by the paired companion during the D5b pairing ceremony
asserting "companion `C` admitted control public key `K_pub`, valid `[t, t+L]`" —
and the endpoint id `E` the browser will present to the relay.

**Proven.**
1. **Possession of `K` — by DH key-confirmation, not a signature.** `K` is an
   X25519 key usable only via `deriveBits`
   ([control-wire protocol](control-wire-protocol.md)); it **cannot sign**. So
   relay-auth's challenge is an ephemeral X25519 public key `R_pub` plus a fresh
   nonce bound to `E`; the browser computes `s = deriveBits(K_priv, R_pub)` and
   returns `HMAC(s, nonce ‖ E)`. relay-auth recomputes `s` from its ephemeral
   private key and `K_pub` (carried in `σ_C`) and checks the HMAC. Only the holder
   of `K`'s private half can produce it, and it uses the one operation the
   non-extractable key supports.
2. **A completed pairing:** `σ_C` verifies under the companion control-signing
   construction, binding `K_pub` to a real pairing ceremony, not a bare keypair.

**Admits.** A short-lived (≤ 60 s), endpoint-bound token is issued **iff** (1) and
(2) verify **and** `K` is within its per-key mint quota (§2) **and** the mint fits
the bucketed budget accounting (§3).

### 1b. Pre-pairing (bootstrap) tier

A browser's *first* pairing needs a relay connection to reach the companion for
the SAS ceremony — but no `σ_C` exists yet, so requiring one would **deadlock
first use**. relay-auth therefore admits a **bootstrap credential** carrying no
`σ_C`, **scoped to the pairing ALPN only** (it cannot open a room-data relay
session), on:

- **Possession of `K`** by the same DH key-confirmation as 1a (`K` is generated at
  first load, before any pairing; the browser presents `K_pub` directly), and
- **a much tighter, separate quota** — the bootstrap sub-bucket (§3) is the
  smallest, and is the **first place the deferred proof-of-work anchor (§4)
  applies**, because it is the only surface not bound by a pairing.

The companion endpoint reaches the relay under the **native-companion credential
policy** (not this browser path), so both sides of a first pairing can connect.

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

**Alerts** inherit #45: 60% / 85% on mints-per-day and egress, 70% / 90% on spend.

**Enforcement spans two planes — a mint-shed alone is not a hard ceiling.** A
browser already holding a token keeps relaying bytes, so refusing new mints does
not by itself bound egress. The GiB/spend ceiling is hard because it is enforced
on both planes:

- **Control plane (this record):** when a budget bucket (§3) is exhausted,
  relay-auth stops minting new tokens for that bucket and alerts. Because tokens
  are ≤ 60 s and endpoint-bound, an active session must re-mint within a minute,
  so a shed **starves in-flight sessions of renewals within one TTL**.
- **Data plane (binding requirement on the relay, implemented in Phase 3 #50):**
  each relay meters aggregate egress and, at the published GiB/spend ceiling,
  **throttles then terminates the highest-egress sessions and refuses new
  admissions**, on top of the per-connection byte/rate limits already in the
  abuse-control list. The mint-shed bounds *arrival*; the relay meter bounds
  *in-flight* egress. Together they bound the cost formula's
  `relayed GiB × provider egress rate` term at
  [Production deployment architecture](production-deployment.md) (relay cost
  formula).

## 3. Budget accounting, buckets, and the established-key reserve

A flat global shed would let an abuse-driven ceiling lock out honest new sessions,
and a single global counter cannot protect a reserve. So the daily budget is
accounted in **two buckets, reset at 00:00 UTC**, maintained atomically by
relay-auth against its own mint ledger (the authoritative event source):

| Bucket | Share of 2,000,000 mints/day | Who draws from it |
|---|---|---|
| **New / unestablished** | 75% (1,500,000/day); the §1b bootstrap tier draws from a tighter sub-cap inside this bucket | control keys not in the established set |
| **Established reserve** | 25% (500,000/day) | control keys in the established set only |

An **established** key is one that completed ≥ 1 successful mint-and-relay-connect
in the trailing 7 days — a bounded, expiring set of key hashes, adding no identity
linkage beyond the mint requests relay-auth already observes
([threat model](security-threat-model.md) TB2).

- **New-key shed fires when the 75% bucket is exhausted — not when the global
  ceiling is reached** — so the 25% reserve is genuinely protected: an established
  key can still mint after new-key minting has shed. Established minting sheds only
  when the reserve itself is exhausted.
- **Attribution is per mint, by establishment state at mint time**, decremented
  atomically from the matching bucket. The escalation trigger (§4) counts
  **new-bucket shed events** against these defined counters and the UTC daily
  window, so "exhausted by non-established keys" is a measured quantity.

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

## 5. What exercises this rule — Phase 0 was a stand-in; AC4 is carried to Phase 3

The Phase 0 relay-connect spike proved the **transport plane** with a
spike-quality token (Ed25519 proof-of-possession, 60 s, endpoint-bound) that
carried **no** companion countersignature, **no** DH key-confirmation against the
control key, and **no** quotas — explicitly a stand-in, recorded as *not* the
production rule ([spike result](evidence/phase-0-relay-spike.md) "What the spike
does and does not prove";
[provider selection](provider-selection-decision.md) "Relay credential model").

**#49's acceptance criterion that "the Phase 0 deliverable and gate exercise the
chosen admission rule" is therefore NOT satisfied by the closed Phase 0 gate, and
this record does not claim it is.** The Phase 0 gate stays discharged on the
transport-plane stand-in — it proved connectivity, not admission. The chosen rule
is exercised instead by the **Phase 3** real-relay validation (`web-ci.yml`
real-relay lane) and the Phase 3 load test; that is where this criterion is met.
No production gate is passed on the stand-in.

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
  rule, naming the DH key-confirmation and the two-plane enforcement (AC1).
- [Production deployment architecture](production-deployment.md) "Abuse controls"
  list — gains per-control-key mint quotas, a bucketed global daily minting
  budget, and the relay-side aggregate-egress cutoff (AC2).
- [Production deployment architecture](production-deployment.md) highest-risk
  unknown 2 — restated as settled by this record, residual named (AC6).
- [Security threat model](security-threat-model.md) "Credential minting as an
  abuse and cost channel" — updated from "the architecture defines no minting
  admission rule" to reference this decided rule, so the canonical threat model
  no longer contradicts it.
- [Relay load-and-cost-ceilings record](relay-load-and-cost-ceilings-decision.md)
  §2a — the "hard ceiling" claim corrected to name both planes (mint-shed plus
  the relay-side egress cutoff), not the mint-shed alone.

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
  unauthenticated stand-in* — **not met on Phase 0 evidence; carried to Phase 3**
  (§5). This record does not mark the closed Phase 0 gate as satisfying the
  criterion; the rule is exercised by the Phase 3 real-relay validation.
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
