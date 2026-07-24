# Security

Jeliya is a network daemon people run on their own machines, holding their own
keys and data. Security reports are taken seriously and handled privately.

## Reporting a vulnerability

Use **GitHub's private vulnerability reporting**: the
[Security tab](https://github.com/kortiene/app.jeliya.ai/security) → "Report a
vulnerability". That opens a private advisory only the maintainer can see. Once
the production origin ships, it will advertise this channel at
`https://app.jeliya.ai/.well-known/security.txt` (RFC 9116).

Please include what you can: affected component (`jeliyad`, `jeliya-core`,
the companion control protocol, the `relay-auth.jeliya.ai` Worker, the web UI,
the agent runner), a reproduction, and the impact as you understand it. Please
don't open a public issue for something exploitable before it's fixed.

This channel is for **security** defects. User-safety reports (abuse, harmful
content, a hostile peer) route through the abuse channel in
`docs/trust-safety-and-legal-decision.md`; during the closed beta both use this
same private-reporting form.

If the "Report a vulnerability" button is ever missing, open a plain issue
saying only "security — requesting a private channel" with **no details**,
and the maintainer will reach out.

## What to expect — honestly

This is a small open-source project, not a company:

- **No bug bounty.** Credit in the release notes if you want it.
- **Best-effort response.** The aim is an acknowledgment within a week and a
  fix prioritized by real impact; there is no SLA.
- **No embargo theater.** Once a fix ships, the advisory is published and
  the release notes say plainly what was wrong.
- **Origin fixes get an advisory too.** The hosted origin can be patched
  silently with no release artifact, so **every vulnerability fixed in the
  hosted origin** (the web app, service worker, `relay-auth.jeliya.ai` Worker,
  or companion control ALPN) still receives a **published GitHub Security
  Advisory** naming the surface and the fix's deploy time. When the defect
  plausibly exposed user data or metadata, required a credential/relay-token
  rotation, enabled a hostile origin to observe rendered content or elevate a
  companion scope, or warranted a browser control-key revocation, a **scoped
  user notification** is sent as well. See
  `docs/vulnerability-disclosure-decision.md`.

## Scope notes

- An agent runner executes tasks on the machine it runs on, gated by a
  sender allowlist — that is a documented trust decision, not a
  vulnerability (see the trust model in `docs/agent-guide.md`). Bypassing
  the allowlist, however, absolutely is one.
- The daemon binds to `127.0.0.1` only; anything that gets it listening on
  another interface without explicit intent is a vulnerability.
- Release binaries are currently unsigned (`docs/signing-notarization.md`
  tracks the plan). Release `v0.4.3` publishes `.sha256` sidecars, but its
  installer implementation does not verify them automatically before
  extraction. That verification is a mandatory `v0.5.0` gate; verify older
  downloads manually.
- The **companion control protocol** (`crates/jeliya-companion/`) is a native
  service that speaks a mutually-authenticated, end-to-end-encrypted Iroh control
  ALPN and exposes **no public HTTP listener**. Its archives ship **unsigned**
  until the post-deploy signing gate (`docs/signing-deferral-decision.md`), so
  tampered/unsigned companion distribution is in scope, not out of it. It is reached only
  after SAS-confirmed pairing, and grants are default-deny, scoped, and
  bounded-lifetime (`docs/companion-control-protocol-decision.md`). Driving the
  companion *within a granted scope* is the documented trust decision. Getting
  it to listen on a public interface, or bypassing pairing, elevating a scope
  beyond what was granted, replaying a control frame, or evading revocation, is
  a vulnerability.
- The **`relay-auth.jeliya.ai` Worker** mints short-lived, endpoint-bound relay
  credentials under a stated admission rule
  (`docs/relay-auth-admission-rule-decision.md`); it is not a room member and
  holds no room content. Observing source IPs, endpoint routing, and short-lived
  key hashes is the documented, pseudonymous metadata boundary. Minting without
  the proof of possession the requested tier requires (post-pairing mints need a
  companion-countersigned control key; the bootstrap path is pairing-ALPN-scoped
  and mints without one under a tighter quota), bypassing the admission rule or
  its quotas, or leaking the project secret into static assets or logs, is a
  vulnerability.
