---
type: "Decision"
title: "Trusted Types policy allowlist — decision record"
description: "Names an explicit trusted-types directive in the production header set alongside require-trusted-types-for 'script'. The shell creates exactly one narrow policy, jeliya-sw, to mint the TrustedScriptURL for service-worker registration; any off-allowlist trustedTypes.createPolicy() throws, and no policy named default is created. The allowlist is scoped to the current React/Vite shell and re-examined — not pre-broadened — when the worker-hosted Wasm runtime lands. The CSP and Trusted Types per-PR tests assert an off-allowlist policy throws and that service-worker registration still succeeds under the served directive. Issue #46."
tags: ["decision", "deployment", "security", "trusted-types", "csp", "phase-3"]
timestamp: "2026-07-24T20:00:00Z"
status: "canonical"
implementation_status: "planned"
verification_status: "unverified"
release_status: "unreleased"
audience: ["maintainers", "operators", "security-reviewers", "frontend", "release-engineers"]
---

# Trusted Types policy allowlist — decision record

**Status: DECIDED 2026-07-24 —** This record names the **`trusted-types`** directive
that the production header set must carry alongside the baseline CSP's
`require-trusted-types-for 'script'`, closing the policy-creation gap review finding
**F21** ([production deployment architecture review](production-deployment-review.md)
§F21) identified for issue [#46](https://github.com/kortiene/app.jeliya.ai/issues/46).
The directive and its enforcement tests are **decided here**; serving the header and
wiring the tests are the same change that lands the service worker, carried as
**Phase-3 build** (§5, §7). The acceptance-criteria mapping (§8) marks each item.

## 1. The directive

The baseline CSP gains one directive:

```text
require-trusted-types-for 'script';
trusted-types jeliya-sw;
```

`trusted-types jeliya-sw;` is an **allowlist of exactly one policy name**. The shell
may create a Trusted Type policy only if it is named `jeliya-sw`; any
`trustedTypes.createPolicy()` with a different name — including `default` — throws a
`TypeError`. This is the decided posture: **one narrow named policy, and no `default`
policy.**

**Why an explicit `trusted-types` is required.** `require-trusted-types-for 'script'`
already forces DOM XSS sinks to accept only typed values, but it does **not** restrict
*which* policies exist, and `trusted-types` does **not** fall back to
`default-src 'none'` (it is not a fetch directive). Without the directive, policy
creation is unrestricted: a script gadget that survives `script-src 'self'` can
register a permissive policy — in particular a `default` policy, which applies to
*every* sink — and regain the DOM sinks the first directive closed. Naming the
allowlist makes policy creation auditable and denies that regain path.

**Why not `trusted-types 'none'`.** `'none'` disallows creating *any* policy. The
plan requires a service worker (`ui/src/sw.ts`, [change map](production-deployment.md);
Phase-3 deliverable) and `ServiceWorkerContainer.register()` is a **TrustedScriptURL
sink**. Under `require-trusted-types-for 'script'`, registering the worker needs a
`TrustedScriptURL` minted by a policy; with `'none'` no policy can exist, so the
service worker could never register. `'none'` is therefore excluded while the SW is
in the plan.

**Why not a `default` policy.** A single policy named `default` intercepts every
TrustedScriptURL / TrustedScript sink centrally, which is simpler at the call site but
is the classic Trusted Types footgun: a `default` policy is exactly what a surviving
script gadget would register to re-open all sinks, and it dissolves the auditability a
named allowlist buys. A `default` policy is **not** created; per the acceptance
criteria it may be introduced only with a **recorded security review**, which this
record does not grant.

## 2. What `jeliya-sw` does

The shell's startup code creates the policy once and uses it to mint the typed value
the service-worker registration sink requires:

```js
const swPolicy = trustedTypes.createPolicy('jeliya-sw', {
  createScriptURL: (u) => {
    // same-origin, allowlisted worker/SW paths only
    const url = new URL(u, self.origin);
    if (url.origin !== self.origin) throw new TypeError('cross-origin script URL');
    return url.href;
  },
});
navigator.serviceWorker.register(swPolicy.createScriptURL('/sw.js'));
```

The policy's `createScriptURL` is **restrictive** — it accepts only same-origin
paths — so naming `jeliya-sw` on the allowlist does not weaken the protection; it moves
the one legitimate sink use through an audited, same-origin-only factory. The exact
shape (the allowlisted path set, whether the policy is also reused for a same-origin
worker the current shell spawns) is settled in the implementing PR; this record fixes
the **name, the count (one), and the exclusions (`'none'`, `default`).**

## 3. Sinks in scope, and the current shell's actual need

The **current shell is React 18 + Vite** and creates **no Trusted Type policy today**
— `trustedTypes.createPolicy` and `trustedTypes` do not appear in `ui/src`, and
`react-dom` neither creates nor needs one under this CSP (no `innerHTML` /
`dangerouslySetInnerHTML` sinks in the shell). The only TrustedScriptURL sink the
current shell introduces is **service-worker registration**, which arrives with the
same Phase-3 change that serves this header. That is why the served allowlist names
exactly `jeliya-sw` and nothing more.

The relevant TrustedScriptURL sinks, for reference: `ServiceWorkerContainer.register()`,
the `url` argument to the `Worker()` constructor, and `WorkerGlobalScope.importScripts()`.
The first is the current-shell sink. `importScripts()` runs **inside** the worker
context and is governed by the worker's **own** CSP, not the page's `trusted-types`
directive; if `ui/src/sw.ts` uses it, the worker's response headers carry the
constraint. The page-side allowlist is `jeliya-sw`.

## 4. Enforcement tests

The per-PR **"CSP and Trusted Types tests"** gate
([production deployment architecture](production-deployment.md) pull-request checks)
must assert, against the **served** directive:

- `trustedTypes.createPolicy('<name-not-on-allowlist>')` **throws** (policy-creation
  restriction is active) — in particular a policy named `default` throws;
- **service-worker registration succeeds** under the served directive (the `jeliya-sw`
  path is not broken by the restriction);
- the shell creates the `jeliya-sw` policy **exactly once** (a second creation of the
  same name throws unless `'allow-duplicates'` is added, which this record does not add).

## 5. Served at the edge, not only in the document

The directive must be present in the **response header set as served by the edge**
(the CDN/host header configuration), not only in a `<meta>` element, so that the
Phase-3 go/no-go gate item **"external TLS/header/CSP assessment passes"**
([production deployment architecture](production-deployment.md)) covers it. A
`trusted-types` directive in a `<meta http-equiv>` is honored by browsers, but the
external header assessment inspects served headers; keeping the whole CSP (including
`trusted-types`) in the served header set is what makes the gate meaningful.

## 6. Scope and re-examination

The `jeliya-sw` allowlist is **scoped to the current shell** — the React/Vite origin
plus its service worker. It is **not pre-broadened** for the worker-hosted Wasm
component runtime (browser components run in dedicated workers;
[WebAssembly component system](production-deployment.md)), which is a later phase and
does not exist today. When that runtime lands it **re-examines** this allowlist and
either adds its own explicitly-named policy (e.g. a component-loader policy) to the
directive or runs the loader inside a worker with its own CSP — a scoped, reviewed
extension, never a catch-all `default` and never a speculative pre-broadening now.

## 7. Edits applied with this record

- [production deployment architecture](production-deployment.md) baseline CSP block —
  adds **`trusted-types jeliya-sw;`** after `require-trusted-types-for 'script';`
  (AC 1), with an inline note that it names only the shell's one policy and excludes
  `'none'` and `default` (AC 2).
- [production deployment architecture](production-deployment.md) "CSP and Trusted Types
  tests" per-PR gate — asserts an **off-allowlist `createPolicy()` throws** and that
  **service-worker registration succeeds** under the served directive (AC 3).
- [production deployment architecture](production-deployment.md) baseline CSP note —
  records that the directive is served in the **header set** so the Phase-3
  header/CSP assessment gate covers it (AC 4), and that the allowlist is **scoped to
  the current shell** and re-examined for the Wasm worker runtime (AC 5).

## 8. Acceptance-criteria mapping (issue #46)

Each criterion is marked **met** (decided/applied here) or **publication-deferred**
(decided; served/exercised as a Phase-3 build item).

- *The baseline CSP block carries an explicit `trusted-types` directive alongside
  `require-trusted-types-for 'script'`, naming only the policy names the shell actually
  creates* — **met**: §1, edit §7. The shell's one policy is `jeliya-sw` (§2–§3).
- *The directive is not `trusted-types 'none'` while the plan requires the service
  worker, and no policy is named `default` without a recorded review* — **met**: §1
  excludes both; `register()`/`Worker()` are named as the TrustedScriptURL sinks (§3).
- *The "CSP and Trusted Types tests" assert that an off-allowlist `createPolicy()`
  throws and that service-worker registration still succeeds under the served
  directive* — **met (named) / publication-deferred (exercised)**: the assertions are
  fixed (§4, edit §7); they run against the served origin when the SW and served CSP
  land in Phase 3.
- *The directive is present in the header set as served by the edge, so the Phase-3
  "external TLS/header/CSP assessment passes" gate covers it* — **met (required) /
  publication-deferred (served)**: §5 fixes the served-header requirement; the served
  header exists in Phase 3.
- *The allowlist is recorded as scoped to the current shell, re-examined when the
  worker-hosted Wasm runtime lands, rather than pre-broadened for it* — **met**: §6.

## 9. Reopen-set position

This record and its edits touch **documentation only** — a new decision record and a
documentation-only edit to `docs/production-deployment.md` and the [docs index](index.md).
None is in the Phase-1 reopen set
([phase-1 security review scope](phase-1-security-review-scope.md)) — the CSP header
block is design documentation, not `jeliya-core`/`serve.rs`/`PROTOCOL.md`/ADR/crypto
material. No re-pin or delta review is owed. When the served CSP and `ui/src/sw.ts`
are actually implemented (Phase 3), that code change is reviewed on its own terms.

## 10. Citations

- [production deployment architecture](production-deployment.md) — the baseline CSP
  block and its `require-trusted-types-for 'script'` directive, the "CSP and Trusted
  Types tests" per-PR gate, the `ui/src/sw.ts` service worker, the dedicated-worker
  Wasm component runtime, and the Phase-3 header/CSP assessment gate.
- [production deployment architecture review](production-deployment-review.md) §F21 —
  the confirmed observation (verified at **medium**, asserted high; the dissenting
  reviewer recommended low and supplied the corrected fix adopted here: name a policy
  allowlist when the SW/Wasm work lands, never `trusted-types 'none'`, never a bare
  `default`) that this record discharges.
- Issue [#46](https://github.com/kortiene/app.jeliya.ai/issues/46).
