---
type: "Decision"
title: "Relay load profile and cost ceilings — decision record"
description: "Publishes the beta load profile (concurrent sessions, rooms, message rate, p95 event size) and the hard resource and cost ceilings — relay egress, relay-auth Worker requests and CPU, and a $900/month spend cap with alert fractions — for every relay environment the plan mandates (production, staging, CI test, dev), sized at a conservative $0.15/GiB egress rate, and restates the Phase 3 gate against them. Issue #45."
tags: ["decision", "deployment", "relay", "cost", "load", "ceilings", "phase-3"]
timestamp: "2026-07-24T12:30:00Z"
status: "canonical"
implementation_status: "planned"
verification_status: "unverified"
release_status: "unreleased"
audience: ["contributors", "maintainers", "release-engineers", "operators", "security-reviewers"]
---

# Relay load profile and cost ceilings — decision record

**Status: DECIDED 2026-07-24 —** This record settles issue
[#45](https://github.com/kortiene/app.jeliya.ai/issues/45): it publishes the beta
load profile and the hard resource and cost ceilings, and restates the Phase 3
gate line "load tests stay inside resource and cost ceilings"
([Production deployment architecture](production-deployment.md) line 1023) against
them. It decides intent and targets only: it asserts no provisioned account, no
running relay, and no measured production traffic. The
[Production ownership record](production-ownership.md) and
[Capability status](capability-status.md) remain the source of truth for what
exists; this record does not advance their implementation, verification, or
release status.

This record sets the *ceilings*. The *admission rule and the automatic minting
cutoff that enforces them* are the separate decision in issue
[#49](https://github.com/kortiene/app.jeliya.ai/issues/49), which is blocked by
this one because #49's cutoff has no number to shed against until these ceilings
exist.

> **Egress-rate basis — conservative, reconfirm before provisioning.** The repo
> records the Iroh managed-relay **instance-hour** price ($0.27/hr) but not its
> managed **egress** rate. This record sizes egress cost at a deliberately
> conservative **$0.15/GiB** so a surprise invoice cannot exceed the ceilings.
> Reconfirm the real rate with Iroh before provisioning: a confirmed rate **≤
> $0.15/GiB only adds headroom** and does not reopen this record; a confirmed rate
> **> $0.15/GiB reopens §2a and §2c** (the egress and spend ceilings) and must be
> re-decided before launch.

## 1. Load profile (first production slice / closed beta)

The profile names the traffic the Phase 3 load test drives and the ceilings are
sized against. Browser peers are **always relayed**
([Production deployment architecture](production-deployment.md) lines 545-548), so
every relayed byte counts once per receiving peer (the "fanout" column).

| Dimension | Value | Basis / note |
|---|---|---|
| Peak concurrent paired sessions | 200 | companion↔browser control sessions live at once |
| Concurrent active rooms | 100 | rooms with ≥1 online peer |
| Mean room size (relayed recipients) | 3 members → fanout ×2 | each authored event relays to the other members |
| Aggregate chat event rate | 5 events/s sustained (22 h/day), 25 events/s peak (2 h/day) | across all rooms |
| p95 chat event size | 4 KiB | control-wire framed event; oversize refused pre-nonce |
| File transfers relayed | 1,000 sends/day; mean 4 MiB, p95 8 MiB, hard per-file cap 100 MiB | file traffic dominates egress; the per-file cap bounds the tail |
| Peak relay connections | 400 | ~2× concurrent sessions (both directions / reconnects) |

## 2. Hard ceilings (with alert fractions)

Each ceiling states an alert threshold as a fraction of the ceiling, per #45
acceptance criterion 2. Reaching a ceiling triggers the automatic action defined
in **#49** (this record sets the number; #49 sheds against it).

### 2a. Relay egress

Derived from §1 across the **full** profile — the peak window and the file tail,
not the sustained rate alone (inputs shown so they can be re-derived):

- Chat: (5 ev/s × 22 h + 25 ev/s × 2 h) × 3600 = 576k events/day × 4 KiB × fanout 2 ≈ 4.4 GiB/day × 30 ≈ **~132 GiB/mo** (peak window included, not sustained-only)
- Files: 1,000/day × **mean** 4 MiB × fanout 2 ≈ 7.8 GiB/day × 30 ≈ **~234 GiB/mo** (aggregate egress tracks the mean, not p95; the 100 MiB per-file cap bounds the tail so no single send is unbounded)
- Typical total ≈ **~370 GiB/mo**; ceiling set at ~2.8× for reconnect + overhead + burst:

| Ceiling | Value | Alert at |
|---|---|---|
| Relay egress, all production relays | **1,024 GiB / month** | 60% (`614 GiB`), 85% (`870 GiB`) |

The ceiling is **hard because it is enforced on two planes**, not because the
profile cannot exceed it: at 1,024 GiB the control-plane **mint-shed** refuses new
tokens (and the ≤ 60 s token TTL starves in-flight sessions of renewals), while
the relay **data plane** meters aggregate egress and throttles then terminates the
highest-egress sessions and refuses new admissions (see the [relay-auth admission
rule record](relay-auth-admission-rule-decision.md) §2). So a run whose file-size
tail or peak burst would carry it past the ceiling is stopped **at** the ceiling.
The profile sets the headroom; the two-plane enforcement makes it a bound, not a
prediction.

### 2b. Relay-auth edge-token service (Cloudflare Worker)

| Ceiling | Value | Alert at |
|---|---|---|
| Token-mint requests per day | **2,000,000 / day** | 60% (`1,200,000`), 85% (`1,700,000`) |
| CPU-ms per request (p95) | **5 ms** | 80% (`4 ms`) |

*Basis:* a token is short-lived and endpoint-bound (the Phase 0 spike minted a
60 s token after one Ed25519 proof-of-possession, ~323 bytes; verify is cheap).
200 concurrent sessions re-minting ~1×/min ≈ 288k/day, so 2M/day is ~7× headroom.
**This is the volume #49's admission rule and cutoff bound** — an uncapped minter
converts any keypair into relay capacity billed to Jeliya.

### 2c. Monthly all-in spend cap

| Ceiling | Value | Alert at |
|---|---|---|
| All-in monthly spend, first slice | **$900 / month** | 70% (`$630`), 90% (`$810`) |

Set above the complete modeled all-in (§3): ~$644/mo typical and ~$742/mo at the
egress ceiling — both including the $150 managed-support/SLA allowance — leaving
~$158 (≈ 18%) of headroom before the cap binds. At the cap, token minting sheds
automatically (mechanism: **#49**). Spend cannot be un-spent, so the cap binds
before availability.

## 3. Cost table — every relay environment the plan mandates

The plan requires **separated development, staging, and production relay
projects** ([Production deployment architecture](production-deployment.md) lines
587-589), **dedicated staging relays** (line 674), and **a dedicated CI test
relay, not only a mock** (line 658). The initial cost model priced only the two
production relays; this table adds the omitted environments so the fixed total
covers them all.

Instance-hour arithmetic at the recorded Iroh managed-relay price **$0.27/hr**,
720 hr per 30-day month; egress at the conservative **$0.15/GiB** basis.
Non-production relays are **ephemeral — run only during CI / promotion windows** —
which is the stated mitigation for their cost.

| Environment | Relays | Run pattern | Instance-hours/mo | Instance-hour cost | Egress cost |
|---|---|---|---|---|---|
| **Production** | 2 (NA + EU) | continuous | 2 × 720 = 1,440 | **$388.80** | up to `1,024 GiB × $0.15 = $153.60` |
| **Staging** | 1 | CI/promotion windows, ~3 hr/day | ~90 | **~$24.30** | ≤ 5 GiB synthetic → **≤ $0.75** |
| **CI test** | 1 | per-PR ephemeral, ~150 runs × 15 min | ~37.5 | **~$10.13** | ≤ 5 GiB synthetic → **≤ $0.75** |
| **Dev** | 1 | developer-initiated, ~20 hr/mo | ~20 | **~$5.40** | ≤ 5 GiB → **≤ $0.75** |
| Edge-token Worker (relay-auth) | — | continuous | — | **~$5–10** (Workers Paid) | — |
| Managed support / SLA | — | reserved allowance | — | **$150** (allowance) | — |
| **Initial fixed total** | | | | **~$436 + $150 SLA** | + egress |

Every mandated environment and charge is quantified against the cap (the
`+ managed support or SLA charges` term of the cost formula at
[Production deployment architecture](production-deployment.md) lines 829-832 is
the $150 allowance line above):

- *Typical all-in* = fixed ~$436 + $150 SLA + typical prod egress (~370 GiB × $0.15 ≈ $55.50) + non-prod egress (≤ ~$2.25) ≈ **~$644/mo**.
- *At the §2a egress ceiling* = fixed ~$436 + $150 SLA + prod egress $153.60 + non-prod egress ≤ $2.25 ≈ **~$742/mo**.

Both are inside the **$900** cap, leaving ~$158 (≈ 18%) of headroom above the
complete at-ceiling spend before the cap itself binds. If managed support / SLA
charges exceed the $150 allowance, revisit the cap.

## 4. Restated Phase 3 gate line

Per #45 acceptance criterion 4, the gate line at
[Production deployment architecture](production-deployment.md) line 1023 —
"load tests stay inside resource and cost ceilings" — is restated as:

> *load tests at the profile in §1 of the relay load-and-cost-ceilings record
> stay within the published egress, request, CPU, and spend ceilings of §2.*

This edit is applied to `production-deployment.md` in the same change that lands
this record.

## 5. Boundary with #49 (what this record does not decide)

- It does **not** define what admits a token mint (paired-control-key vs. rate
  token vs. open minting) — that is #49.
- It does **not** implement the automatic cutoff; it states the number the cutoff
  sheds against.
- It does **not** provision or size any real relay; §1's numbers are the *target*
  the Phase 3 load test is run at, not measured production load.

## 6. Acceptance-criteria mapping (issue #45)

- *Load profile naming concurrent paired sessions, rooms, aggregate message rate,
  and p95 event size* — §1.
- *Hard ceilings for relay egress GiB/month, relay-auth Worker requests/day and
  CPU-ms/request, and a monthly all-in spend cap, each with its alert threshold as
  a fraction of the ceiling* — §2.
- *Cost table carries rows for the dedicated staging relays (line 674) and the
  dedicated CI test relay (line 658), or states the mitigation with the hourly
  arithmetic* — §3 (ephemeral CI-window mitigation, arithmetic shown).
- *Phase 3 gate line restated to name the published profile and ceilings* — §4.

## 7. Citations

- [Production deployment architecture](production-deployment.md) — abuse controls
  and cost model ("Initial monthly cost model"; $0.27/hr, ~$389/mo for two
  relays), cost formula (lines 829-832), relay environment separation (587-589),
  dedicated staging relays (674), dedicated CI test relay (658), Phase 3 gate
  (line 1023), always-relayed browser peers (545-548).
- [Production provider selection decision](provider-selection-decision.md) — two
  managed Iroh relays (NA + EU), Cloudflare Worker edge-token service, cost basis,
  per-user pricing unpublished until measured.
- [Phase 0 relay-connect spike result](evidence/phase-0-relay-spike.md) — 60 s
  endpoint-bound token, ~323-byte token, Ed25519 proof-of-possession cost basis.
- Issue [#45](https://github.com/kortiene/app.jeliya.ai/issues/45) (this record) and
  issue [#49](https://github.com/kortiene/app.jeliya.ai/issues/49) (admission rule
  and cutoff, blocked by this record).
