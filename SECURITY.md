# Security

Jeliya is a network daemon people run on their own machines, holding their own
keys and data. Security reports are taken seriously and handled privately.

## Reporting a vulnerability

Use **GitHub's private vulnerability reporting**: the
[Security tab](https://github.com/kortiene/app.jeliya.ai/security) → "Report a
vulnerability". That opens a private advisory only the maintainer can see.
This is the whole channel: Jeliya is distributed as an installed daemon and
operates no public origin, so there is no `security.txt` to serve. (If a hosted
origin is ever built, advertising this same channel at
`https://app.jeliya.ai/.well-known/security.txt` (RFC 9116) re-enters with it.)

Please include what you can: affected component (`jeliyad`, `jeliya-core`, the
web UI, the agent runner, the installers, or the release-evidence pipeline), a
reproduction, and the impact as you understand it. Please
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
- **Silently-patchable surfaces get an advisory too.** This rule existed for
  the hosted origin, which could be patched with no release artifact to attach
  a note to. That origin is deferred and no such surface is operated today, so
  the rule is **vacuous rather than repealed**: it re-enters automatically with
  any surface the project can fix without shipping a release. Every
  vulnerability fixed in such a surface receives a **published GitHub Security
  Advisory** naming the surface and the fix's deploy time, and a **scoped user
  notification** when the defect plausibly exposed user data or metadata or
  required a credential rotation. See
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
- The **companion control protocol** and the **`relay-auth.jeliya.ai` Worker**
  were in scope here and are **removed from it**. The
  [desktop-operator-first scope decision](docs/desktop-first-scope-decision.md)
  deleted the companion control plane and its three crates, and deferred the
  relay plane, so neither surface exists to be attacked and neither ever
  shipped in a release. Reports about them describe code that is not
  distributed; `docs/control-wire-protocol.md` is retained as the record of
  what the wire was.
