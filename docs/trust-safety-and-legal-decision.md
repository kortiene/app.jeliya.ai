---
type: "Decision"
title: "Trust, safety, and legal ownership — decision record"
description: "Discharges amendment A6 for the first public launch: names the operating legal entity and the abuse-contact, triage, launch-approval, and legal/retention owners; states the abuse-report channel and per-class response times and duties; states the retention and lawful-basis position (72h security logs, no room content, EU relay residency, GDPR Art 6(1)(f)); and states plainly what the end-to-end architecture can and cannot do about content already distributed. Issue #47."
tags: ["decision", "deployment", "legal", "trust-and-safety", "privacy", "abuse", "phase-3"]
timestamp: "2026-07-24T17:00:00Z"
status: "canonical"
implementation_status: "planned"
verification_status: "unverified"
release_status: "unreleased"
audience: ["maintainers", "operators", "security-reviewers", "product", "release-engineers"]
---

# Trust, safety, and legal ownership — decision record

**Status: DECIDED 2026-07-24 —** This record discharges amendment **A6**
([production deployment decision](production-deployment-decision.md) §A6) and
settles issue [#47](https://github.com/kortiene/app.jeliya.ai/issues/47) for the
first public launch (Phase 3, the first production launch gate). It names the
owners and states the trust-and-safety, retention, lawful-basis, and
takedown-limit positions the launch gate requires.

> **Not legal advice.** The retention, lawful-basis, and residency positions below
> are a defensible **starting position** written by the maintainer, not advice from
> counsel. A qualified privacy lawyer **must** review them — records of processing,
> any required data-processing agreements, and the published privacy-policy / ToS
> text — **before public launch**. That review is a named pre-launch dependency
> (§8), not an optional follow-up.

## 1. Operating entity and owners

app.jeliya.ai is operated by **the maintainer as an individual** (sole operator);
there is no company entity behind the first launch. For a solo beta the safety,
legal, and approval roles are concentrated in one person and can split later.

| Role | Holder |
|---|---|
| Operating legal entity | the maintainer, as an individual sole operator — full legal name and postal contact are a publication fill-in (§8), required for the privacy policy / ToS; cross-referenced from [production ownership record](production-ownership.md) §1 |
| Abuse contact + triage owner | the maintainer |
| Trust-and-safety / launch-approval authority | the maintainer (already the production-approval authority in [production ownership record](production-ownership.md) §4) |
| Legal / retention owner | the maintainer, pending the external legal review (§8) |

Concentrating every role in one person is a **stated governance risk** for a
public messaging product: there is no deputy for abuse triage or launch approval.
The [production ownership record](production-ownership.md) §4 already records the
"no deputy" gap; naming distinct owners is the recommended step before scaling
past a closed beta.

## 2. Abuse reporting: channel, triage owner, response times, and duties

**Channel (beta).** User reports route through **GitHub private vulnerability
reporting**, linked from the origin's help/report UI, and the in-product
block/report tool directs here. The triage owner is the maintainer (§1).

> **Honest limitation — beta stopgap.** GitHub private reporting is
> developer-facing and conflates security reports (#48) with user-safety reports,
> and it is not a first-class "abuse contact **at the origin**." A dedicated,
> user-facing origin abuse channel (e.g. `abuse@jeliya.ai`) is a **named follow-up
> before scaling beyond the closed beta** (§8).

**Response times and duties per report class.** Because Jeliya is end-to-end
encrypted and local-first, the operator cannot read room content and cannot recall
distributed material (§4); duties are bounded by what the operator can actually do.

| Report class | Triage / response time | Duty (bounded by §4) |
|---|---|---|
| Illegal content (e.g. CSAM) or credible threat to life | triage immediately; act ≤ 24 h | refer to the relevant authority; preserve the minimal connection metadata held within the 72 h window (§3); apply available infra measures (revoke an identifiable relay credential / control key). The operator cannot read content or delete it from peers. |
| Harassment or unlawful abuse of the service | ≤ 72 h | surface the user-side block/report tooling; revoke relay credentials tied to an identifiable abusing endpoint where possible |
| Spam / ToS violation / other | best-effort, ≤ 7 days | apply available controls; document |

## 3. Retention and lawful basis

**Data processed.** The relay necessarily observes **connection metadata** — source
IP, endpoint routing, timing, and byte volume — and **never room content** (rooms
are end-to-end encrypted; the relay is not a room member,
[threat model](security-threat-model.md) TB2). There are **no accounts**, so no
account-level personal data exists.

**Retention (per [production deployment architecture](production-deployment.md)
"Availability… and cost").**
- Raw security access logs retained **no more than 72 hours initially**, with
  restricted access and documented incident exceptions (line 786).
- Aggregate metrics inside the service where possible; beta client telemetry is
  **opt-in** with a rotating, unlinkable session ID; CSP reports scrubbed; query
  logging disabled where the provider allows (lines 787-790).

**Residency.** The failover relay is in the **EU** (lines 545-546), so the
connection metadata that relay processes is subject to EU data-protection law.

**Lawful basis.** **GDPR Art 6(1)(f) — legitimate interest**: operating a secure
relay and protecting the service and its users requires processing the minimal
connection metadata above. The balancing test against user rights is met by
**data minimization** — 72 h retention, no room content, aggregation, no linkable
identity, and no accounts. (Subject to the legal review in §8.)

**Data-subject rights** are constrained by design: with no accounts and minimal,
short-lived, largely unlinkable data, most requests have little to act on; a
request is received via the §2 channel and handled within the retention window.

## 4. What the architecture can and cannot do about distributed content

This is the constraint A6 exists to make explicit, drawn from the architecture:

**The operator CAN:** revoke a relay credential or a browser control key; rotate
relay tokens; act on abuse of the relay / origin / CDN infrastructure it controls;
respond to lawful orders concerning the ≤ 72 h connection metadata it holds;
publish safety guidance and in-product block/report tooling.

**The operator CANNOT (architectural, not a policy choice):**
- **read room content** — rooms are end-to-end encrypted and the relay is not a
  member;
- **delete a message or file from a peer's device** once delivered;
- **recall material already received** ([production deployment
  architecture](production-deployment.md) line 377);
- **prevent an authorized room peer from copying content** — "signatures prevent
  forgery; they do not prevent an authorized peer from copying content" (line 292,
  TB4).

Key or device **revocation blocks future authorship and future encrypted epochs,
not past receipt**. The consequence, stated plainly to users: the primary safety
controls are **user-side** (block, leave, report) plus the operator's limited
relay/credential measures — the operator cannot take down content that has already
reached a peer.

## 5. Privacy policy and terms of service

The operator commits to **publishing a privacy policy and terms of service at
app.jeliya.ai**, in EN and FR (matching the product's localization), carrying the
§3 retention / basis / residency position and the §4 takedown-limit statement.
**Publication is Phase 3 implementation** (it needs the origin); this record fixes
their substance. The legal review (§8) gates the published text before launch.

## 6. Phase 3 gate items (added by this record)

The first production launch gate ([production deployment
architecture](production-deployment.md) "Go/no-go gate") does not pass until each
of these is **published at the origin**:
- the abuse contact and its triage owner (§1–§2);
- the retention and lawful-basis position (§3);
- the takedown-limit statement (§4).

## 7. Edits applied with this record

- [production deployment architecture](production-deployment.md) block/report
  bullet — names the recipient, triage owner, and per-class duty via this record.
- [production deployment architecture](production-deployment.md) retention line —
  points to the §3 lawful-basis / residency position.
- [production deployment architecture](production-deployment.md) Phase 3 go/no-go
  gate — gains the three A6 items in §6.

## 8. Pre-launch fill-ins and open items

- the maintainer's **full legal name and postal contact** for the privacy policy /
  ToS (fill in [production ownership record](production-ownership.md) §1);
- a **formal privacy/legal review** with records of processing and any required
  DPA, and sign-off on the published privacy-policy / ToS text (§ note above);
- a **dedicated user-facing origin abuse channel** before scaling beyond the
  closed beta (§2);
- a **named deputy** for abuse triage and launch approval (the §1 governance risk).

## 9. Acceptance-criteria mapping (issue #47)

- *A published abuse contact with a named triage owner and a stated response time
  per report class* — §2 (beta channel + the response-time table; the user-facing
  origin channel is the §8 follow-up).
- *The block/report bullet names its recipient, triage owner, and duty per class* —
  §2, edit §7.
- *A retention and lawful-basis position covering the 72 h logs and the EU relay
  residency* — §3.
- *The legal entity is named, with a privacy policy and ToS published at the
  origin* — §1 names the entity; §5 commits to publication (Phase 3), with the
  legal name and text as §8 fill-ins.
- *An explicit statement of what the architecture can and cannot do about
  distributed content* — §4.
- *The Phase 3 gate carries the abuse contact + triage owner, the retention /
  lawful-basis position, and the takedown-limit statement as gate items* — §6,
  edit §7.

## 10. Citations

- [production deployment decision](production-deployment-decision.md) §A6.
- [production deployment architecture](production-deployment.md) — block/report
  bullet (line 839), 72 h security-log retention (line 786) and the surrounding
  retention controls (787-790), EU relay (545-546), takedown limits (292, 377),
  the Phase 3 go/no-go gate.
- [production ownership record](production-ownership.md) — §1 controlling
  identity, §4 production-approval authority and the "no deputy" gap.
- [security threat model](security-threat-model.md) — TB2 relay metadata, TB4 room
  membership and copying.
- Issue [#47](https://github.com/kortiene/app.jeliya.ai/issues/47); amendment A6.
