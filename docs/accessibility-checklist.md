---
type: "Runbook"
title: "Accessibility release checklist"
description: "The screen-reader and keyboard behaviours automated checks cannot prove, verified by hand before a release."
tags: ["accessibility", "release", "qa", "manual"]
timestamp: "2026-07-19T12:00:00Z"
status: "canonical"
implementation_status: "implemented"
verification_status: "partial"
release_status: "unreleased"
audience: ["contributors", "reviewers", "maintainers"]
---

# Accessibility release checklist

Jeliya ships one client, the React web client in `ui/`, and CI enforces what a
machine can decide about it: no critical or serious axe violations across
every destination and viewport, critical flows that reflow at the 320px /
400%-zoom target in English and French, target sizes that clear their floor,
and a palette that matches the shared token fixture.

None of that proves the app is usable with a screen reader. Automated checks
read the accessibility tree; they cannot hear the order things are announced
in, notice that a live region interrupts mid-sentence, or tell that focus
technically moved somewhere useless. This checklist covers exactly that gap —
the residue, not a re-run of the gates.

Work through it in one desktop browser with a desktop screen reader and one
mobile browser with a mobile screen reader before a release. Record the pass
in the release notes with the browser, reader, and versions used; a checklist
nobody can tell was run is not evidence.

Accessibility here is enforced, not certified. Nothing on this page is a WCAG
conformance claim; see [capability status](capability-status.md) for the
standing position.

## What CI already covers — do not re-verify by hand

| Enforced by | Covers |
|---|---|
| `ui/e2e/a11y-matrix.spec.ts` | No critical/serious axe violations, all destinations x 4 viewports |
| `ui/e2e/a11y.spec.ts` | One `main` and one `h1` per destination, landmark names, skip links that move focus, 44px target floors, distinct names on repeated row actions, reduced motion |
| `ui/e2e/i18n-layout.spec.ts` | Critical flows reflow at 320px (the 400%-zoom equivalent) in English and French |
| `ui/e2e/responsive.spec.ts` | Widths 360/899/900/920/1280, the inspector's float-versus-column behaviour, safe-area insets at 320 and 360 |
| `scripts/check-design-tokens.mjs` | The React palette against the shared fixture |

## Screen reader

- [ ] **Reading order matches visual order** on a room's Activity. Follow the
      timeline top to bottom with the virtual cursor and confirm nothing is
      announced out of sequence, especially around the day dividers and folded
      agent runs.
- [ ] **A new message is announced once.** Send from a second device with the
      timeline focused. Confirm one announcement, not one per intervening
      re-render. This is the failure mode a `liveRegion` over a rebuilding list
      produces, and no automated check can hear it.
- [ ] **A connection transition is announced once.** Stop the daemon, wait for
      the banner, restart it. The record allows exactly one live region for
      this (`docs/room-workbench.md`, decision 3) — confirm you hear one
      transition, not a repeat per retry attempt.
- [ ] **Landmark navigation is useful.** Jump by landmark on each destination
      and confirm the names distinguish the panes ("Room rail", "Files
      inspector") rather than announcing two unnamed complementary regions.
- [ ] **The status vocabulary reads as intended.** On Agent Fleet, confirm each
      agent's liveness and last-posted status are announced as two separate
      facts. A "Stale" agent whose last posted label was "Working" must not
      sound like it is working now.
- [ ] **Error copy is the friendly message, not the raw code.** Trigger a fetch
      failure and confirm the announcement leads with the designed sentence;
      the daemon's own code and hint belong in the collapsed technical
      disclosure.

## Keyboard

- [ ] **Skip links work as the first two tab stops** and land focus, not just
      scroll. Tab once from a fresh load, confirm the link becomes visible,
      activate it, and confirm the NEXT Tab continues from the destination.
- [ ] **The focus ring is visible everywhere it lands**, including over the
      inspector drawer at a medium width and against the tinted primary and
      danger buttons.
- [ ] **No focus trap outside a dialog.** Tab all the way around each
      destination and back. Inside a dialog, confirm the trap holds and Escape
      releases it to the control that opened it.
- [ ] **Destructive actions never take initial focus.** Open Leave room and
      press Enter immediately: it must abandon, not confirm.
- [ ] **The room tab strip behaves as a tablist** — arrows move between tools,
      Home and End jump to the ends, and one Tab enters and one leaves.
- [ ] **Nothing is reachable but invisible.** Watch for a focus ring that
      disappears behind the drawer, the composer, the jump-to-latest pill, or
      the bottom tab bar.

## Browser and platform behaviours

- [ ] **Browser text size raised on its own**, without page zoom: set the
      browser's minimum or default font size to its largest and confirm every
      primary and Cancel action is still reachable, by scrolling if necessary,
      in both English and French. CI covers page-zoom reflow but not
      text-only resizing (see Known gaps).
- [ ] **OS text size at maximum** in a mobile browser: same check on a phone.
- [ ] **Reduced motion honoured** at the OS level, not only through the
      Playwright emulation: the jump-to-latest scroll lands instantly rather
      than animating.
- [ ] **The app is operable with the keyboard alone from first load** —
      including onboarding, which a pointer-only assumption tends to miss
      because it is seen once.

## Known gaps

- **Text-only resizing has no automated coverage.** The Flutter suite carried
  the 100/200/320% text-scale checks; it is gone with the client, and the
  browser equivalent — raising text size without zooming — has no spec. Until
  one exists, the manual item above is the only coverage, and WCAG 1.4.4 is
  unproven.
- **Focus-indicator presence has no automated coverage** either, for the same
  reason. axe does not decide whether a visible focus ring appears, so the
  keyboard item above is the only check.
- `ui-e2e` is not currently in the repository's required status checks, so the
  accessibility gate runs on every pull request but does not yet BLOCK a merge.
  Adding it is a branch-protection change, outside any pull request's diff.
