---
type: "Reference"
title: "Design tokens"
description: "Mapping from every Jeliya design-token concept to its React custom property, with the shared fixture and the gate that enforces it."
tags: ["design", "design-system", "tokens", "accessibility", "web-client"]
timestamp: "2026-07-19T12:00:00Z"
status: "canonical"
implementation_status: "implemented"
verification_status: "partial"
release_status: "unreleased"
audience: ["client-authors", "contributors", "designers", "maintainers"]
---

# Design tokens

Jeliya has one client: the React web client in `ui/`. It renders the design
system as CSS custom properties in
[`ui/src/styles.css`](../ui/src/styles.css). This page is the mapping from
each design-token concept to the custom property that carries it. [The design
system](../DESIGN.md) stays normative for *why* a token exists; this page says
*where* it lives.

The mapping is written down because values drift quietly. The message bubble
once grew an accent gradient in CSS that contradicted the design record, and
it looked local and reasonable at the call site — which is how every one of
these regressions looks. A named concept with a pinned value and a gate behind
it is harder to talk out of.

## Source of truth and the gate

[`assets/design-tokens.json`](../assets/design-tokens.json) is the fixture: the
machine-checkable half of the design system. Colours, alpha companions, radii,
the contrast floors, the shadow vocabulary, and the gradient ceiling are pinned
there as values, not prose.

[`scripts/check-design-tokens.mjs`](../scripts/check-design-tokens.mjs) reads
that file and checks the stylesheet against it. Run it from the repository
root:

```sh
node scripts/check-design-tokens.mjs
```

What the gate actually asserts:

- every pinned base colour is declared in `:root` with the pinned value;
- no `var()` is referenced without being declared — a referenced-but-undeclared
  variable silently disables whatever rule uses it, which is exactly how the
  fetched-path hover state sat dead;
- `box-shadow` values stay inside the fixture's shadow vocabulary;
- no coloured left/right border wider than 1px is used as an accent stripe;
- the progress fill is the only accent gradient, and any tint wash stays under
  the alpha ceiling and single-hue.

What it does **not** assert: the radii, the alpha companions, and the contrast
floors are pinned in the fixture but nothing compares them to the stylesheet.
They are an authoring obligation, not a gate. Rendered contrast is covered
separately and indirectly by the axe sweep in `ui/e2e/a11y-matrix.spec.ts`; see
the [accessibility release checklist](accessibility-checklist.md) for what that
does and does not prove.

Where the stylesheet and the design record disagree, one of them is a bug. Say
which in the pull request; do not edit the fixture to match whichever side you
happened to open first.

## Colour mapping

Fixture keys are the names in `assets/design-tokens.json`.

### Surfaces

| Concept | Fixture key | React |
|---|---|---|
| App ground | `ground` | `--bg` |
| Chrome (sidebar, panels, headers, modal) | `chrome` | `--bg-raise` |
| Card | `card` | `--bg-card` |
| Nested surface | `card-nested` | `--bg-card-2` |
| Input well | `input-well` | `--bg-input` |
| Remote message bubble | `bubble-remote` | `--bg-bubble-remote` |

### Borders

| Concept | Fixture key | React |
|---|---|---|
| Quiet hairline / divider | `border-quiet` | `--border` |
| Strong border, and selected-state edges | `border-strong` | `--border-strong` |
| Control-identifying boundary, 3:1 (WCAG 1.4.11) | `border-interactive` | `--border-interactive` |

### Accent

| Concept | Fixture key | React |
|---|---|---|
| Emerald | `accent` | `--accent` |
| Deep emerald (progress fill partner) | `accent-deep` | `--accent-2` |
| Tint fill, 12% | `alpha.dim.accent` | `--accent-dim` |
| Border line, 40% | `alpha.line.accent` | `--accent-line` |
| Tinted-button hover, 20% | `alpha.accent-hover` | `--accent-hover` |
| Tinted-button pressed, 28% | `alpha.accent-active` | `--accent-active` |
| Brightened emerald for a hovered link | not pinned | `--accent-strong` |

### Ink

| Concept | Fixture key | React |
|---|---|---|
| Primary ink | `ink` | `--text` |
| Secondary ink | `ink-dim` | `--text-dim` |
| Small info-bearing ink, AA-audited | `ink-mute` | `--text-mute` |

### Status hues

Every hue carries exactly two companions: a tint and a 40% line. Any third
alpha is drift — the audit found five distinct alphas where two are specified.

| Concept | Fixture key | React |
|---|---|---|
| Degraded | `amber` | `--amber` |
| Degraded tint, 12% / line, 40% | `alpha.dim.amber`, `alpha.line.amber` | `--amber-dim`, `--amber-line` |
| Failed | `red` | `--red` |
| Failed tint, 10% / line, 40% | `alpha.dim.red`, `alpha.line.red` | `--red-dim`, `--red-line` |
| Waiting | `blue` | `--blue` |
| Waiting tint, 10% / line, 40% | `alpha.dim.blue`, `alpha.line.blue` | `--blue-dim`, `--blue-line` |

Status is never colour alone. The hue is half of a token pair whose other half
is a dot and a text label; see [room attention](room-attention.md) for the
vocabulary and the evidence rule behind each label.

### Scrim and elevation

| Concept | Fixture key | React |
|---|---|---|
| Modal scrim, 72% | `scrim` | composed in the `.modal-backdrop` rule |
| Modal lift | `elevation.modal-lift` | `box-shadow` on the modal |
| Drawer lift, medium shell only | `elevation.drawer-lift` | `box-shadow` on `.right-panel` |
| Status glow, `0 0 6px` | `elevation.status-glow` | `box-shadow` on status dots |

The fixture's `elevation.allowed` list is exhaustive by design: the gate treats
any other `box-shadow` as drift.

## Custom properties with no fixture key

These are not drift. Each is a browser-platform mechanic the fixture has no
opinion about, so it lives in the stylesheet and nowhere else:

- `--accent-strong` — the brightened emerald for a hovered fetched-path link.
  It was referenced before it was declared, so the hover state silently did
  nothing; it is now declared, and the gate fails on any repeat.
- `--z-fleet`, `--z-drawer`, `--z-tabbar`, `--z-modal` — the stacking scale.
- `--vh-full`, `--safe-top`, `--safe-bottom`, `--safe-left`, `--safe-right`,
  `--tabbar-h` — viewport and safe-area mechanics.
- `--font`, `--mono` — the type stacks.

One palette lives outside CSS entirely: the deterministic identity colour and
the file-type tint are `colorForId` and `fileTint` in
[`ui/src/lib/format.ts`](../ui/src/lib/format.ts). Four of its values duplicate
declared tokens as hex literals and carry a comment naming the property they
mirror (`--accent`, `--blue`, `--red`, `--text-dim`); the rest — a violet
shared by both functions, plus three avatar-only hues — have no token at all,
because they appear only inside those two functions. Change a mirrored hex in
the stylesheet and you must change it there too: the gate does not read that
file.

## Radii

Radii are pinned as numbers in the fixture. There are no radius custom
properties: the values appear as literals in the rule that uses them, so the
React column here is the value, not a variable name.

| Fixture key | Value | Used for |
|---|---|---|
| `tail` | 4 | The bubble's sharp tail corner |
| `tight` | 7 | Icon buttons, skeletons, pipe address chips |
| `sm` | 8 | Small buttons |
| `control` | 9 | Buttons, inputs, 34px square tiles |
| `nav` | 10 | Nav items, stat inner cells |
| `tile` | 11 | Room rows, file and pipe tiles, agent-work cards |
| `card-sm` | 12 | Profile and settings cards |
| `card` | 13 | Composer bar, agent and pipe cards, panel forms |
| `stat` | 14 | Member and file rows, bubble corners, stat tiles |
| `card-lg` | 15 | Heroes, fleet cards |
| `surface` | 16 | Modal, onboarding card |
| `pill` | 999 | All pills, chips, and badges |

Because the values are literals rather than variables, a new radius is easy to
introduce by accident. Twelve steps is the whole vocabulary; reach for the
nearest one rather than a thirteenth.

## Spacing is not pinned, and that is deliberate

[The design system](../DESIGN.md) names five spacing steps: 4, 8, 12, 18, 24.
Those five are the design record. Spacing is deliberately absent from the
shared fixture, so it is the one part of the token system with no gate behind
it at all — the stylesheet is free to use an intermediate value, and nothing
will report it.

Treat the five steps as the default and reach for an intermediate only when a
real layout needs it. If a *sixth* step turns out to be genuinely systematic
rather than local, promote it in the design record first, rather than letting
it accumulate in the stylesheet.
