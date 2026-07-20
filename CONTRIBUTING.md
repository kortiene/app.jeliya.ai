# Contributing to Jeliya

Thanks for wanting to help build the gathering place. Setup lives in the
README ("Build from source"); the daemon ⇄ UI contract is
`docs/PROTOCOL.md`; design tokens and rules are `DESIGN.md`; the canonical
documentation wiki starts at `docs/index.md`.

## The honesty rules are contribution requirements

Jeliya's one promise is that the screen never shows a comforting lie.
Contributions are reviewed against that promise first:

1. **No fake state.** No optimistic "delivered" checks, no spinners implying
   progress that isn't happening, no invented presence. Render what the
   signed log proves.
2. **Green is earned.** The emerald accent marks real, verified
   live/healthy state — never decoration, never a fallback
   (see `labelTone` in `ui/src/lib/format.ts`, normative in
   `docs/PROTOCOL.md`).
3. **Failures are failures.** Errors surface their real code
   (`unavailable`, `unauthorized`, `hash_mismatch`) and a useful hint —
   never a silent partial result.
4. **Accessibility floor.** WCAG 2.1 AA: ≥4.5:1 contrast for
   information-bearing text, status never by color alone (dot + label),
   `prefers-reduced-motion` honored, full keyboard operability.

A PR that makes the UI friendlier by making it less truthful will be
declined kindly.

## Practical notes

- **Layering:** only `jeliya-core` may import the `iroh-rooms` SDK. The
  daemon (`jeliyad`) speaks `docs/PROTOCOL.md` to the UI; don't route around
  the contract.
- **Prove it runs.** `node scripts/agent-e2e.mjs` proves the agent flow
  end-to-end with no network and no AI; `scripts/demo.sh` runs the full
  two-daemon demo. Say in the PR what you ran. CI runs six jobs on every PR
  and push to main: `docs-ui`, `ui-e2e`, `rust-runtime`, `msrv`,
  `windows-installer`, and `dependency-security`.
  Together they cover docs, UI, browser-level responsive and accessibility
  regressions, Rust, smoke/E2E/protocol conformance, the 1.91.0 MSRV,
  Windows installer integrity, and Cargo/npm security audits.
  **All six are branch-protection REQUIRED checks on `main`** (issue #20;
  verified against the branch-protection API on 2026-07-20). The required
  contexts are the six job `name:` values in `.github/workflows/ci.yml`, one
  per job, so the set can be diffed against the workflow:
  - `docs-ui` → "docs + TypeScript + release contracts"
  - `ui-e2e` → "UI browser regression (Playwright)"
  - `rust-runtime` → "Rust + smoke + E2E + protocol conformance"
  - `msrv` → "MSRV 1.91.0"
  - `windows-installer` → "Windows installer integrity"
  - `dependency-security` → "dependency security (Cargo + npm)"
  The axe accessibility sweep lives in `ui-e2e`, so a critical or serious
  violation now blocks the merge instead of only failing the run.
  **Rule: a new pull-request gate enters this required-check set in the same
  change that creates it** — an advisory-only job is a gap from the moment it
  exists (amendment A5 requires the accessibility gate to sit alongside the
  security gates, and the same applies to every gate the deployment plan
  adds). Branch protection is a repository setting, so the operator flips it
  when merging the change; a job rename must update the required context in
  the same step, or the stale context blocks every merge.
  The same complete matrix can be dispatched manually without publishing a release.
- **UI regressions are browser-tested.** `cd ui && npm run test:e2e` runs the
  Playwright suite (`ui/e2e/`) against the `VITE_MOCK=1` fixture client — no
  daemon needed — across desktop (1440×900, 920×800) and compact (390×844,
  320×568) viewports. Changes to responsive flows (pane navigation, timeline,
  composer, dialogs) must keep it green and should extend it; keep the suite
  deterministic — web-first assertions only, never arbitrary sleeps.
- **Documentation is a contract.** `docs/PROFILE.md` defines metadata,
  lifecycle, navigation, and linking rules. Every page must remain reachable
  from `docs/index.md`; run `node scripts/check-docs.mjs` after editing the
  wiki. CI runs the same gate.
- **The UI ships inside the binary.** `jeliyad` embeds `ui/dist` via
  `rust-embed` under the `embed-ui` feature, so the build order is not
  optional: `cd ui && npm ci && npm run build` **before**
  `cargo build --release -p jeliyad --features embed-ui`. A plain `cargo build`
  produces a WS-only daemon that serves no UI — that is by design, and the
  daemon says so on `/`.
- **Strings & i18n:** French ships wherever the web client does —
  `docs/i18n.md` records the decisions and engineering rules;
  `docs/glossary-fr.md` the glossary tiers. No hand-rolled pluralizations, no
  sentence-building from concatenated fragments, no wire enums as display
  text. `node scripts/check-ui-i18n.mjs` enforces catalog completeness, French
  typography, and the never-translate boundary — CI runs it on every PR and
  push to main, and the release jobs gate on it.
- **Naming:** the project renamed from Bantaba to Jeliya on 2026-07-05
  (`docs/naming.md`). Don't reintroduce the old name outside that record.
- **Security reports:** privately, please — see `SECURITY.md`.

## License

Dual-licensed MIT OR Apache-2.0. By contributing, you agree your
contribution may be distributed under both.
