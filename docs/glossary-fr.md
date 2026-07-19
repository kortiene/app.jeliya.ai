---
type: "Glossary"
title: "French localization — glossary & scoping decisions"
description: "Canonical French terminology and localization decisions for Jeliya product surfaces."
tags: ["french", "i18n", "localization", "terminology"]
timestamp: "2026-07-19T12:00:00Z"
status: "canonical"
implementation_status: "implemented"
verification_status: "verified"
release_status: "unreleased"
audience: ["contributors", "reviewers", "translators"]
---

# French localization — glossary & scoping decisions

**Status: agreed before any translation landed.** This file gated the first
French release: translators and reviewers enforce it so terms don't drift
across surfaces. Jeliya targets francophone West Africa first (Mali,
Senegal, Guinea, Côte d'Ivoire); Bambara (bm) is the community aspiration
unlocked now that the French catalog has landed.

This is a contract for translators and reviewers — it is not a live,
end-user-facing glossary. It did its gating work: the web client ships a
complete French catalog in `ui/src/l10n/fr.ts`, typed against
`ui/src/l10n/catalog.ts` so a missing key is a compile error, and checked by
`scripts/check-ui-i18n.mjs` for empty, untranslated, and typographically
invalid values. Mechanics in [`i18n.md`](i18n.md). Still open: the user-facing
discoverability pointer (a `README.fr.md`, or a "Voir aussi" link from the
main README) does not exist yet — until one lands, francophone users have no
way to find this page.

## Tier 1 — communal vocabulary: translate

Everyday nouns rendered as prose. First-pass equivalents (translators may
refine, but consistently):

| English | French |
|---|---|
| room | salon |
| member(s) | membre(s) |
| files | fichiers |
| invite / invitation | inviter / invitation |
| share | partager |
| join | rejoindre |
| create | créer |
| settings | réglages |
| Your Rooms | Vos salons |
| ticket | ticket |
| agent | agent |

## Tier 2 — protocol truth tokens: never translate

These are grep-able wire identifiers rendered in mono/code style. Translate
the sentence and the hint around them; keep the token verbatim:

- `direct` / `relay` connection badges — rendered exactly as reported by the
  daemon (honesty rule).
- Error codes `unavailable`, `unauthorized`, `hash_mismatch`.
- `daemon`, `jeliyad`, endpoint and identity ids.
- `pipe` — the stated audience (technical operators) knows the Unix term;
  « tuyau » may appear in explanatory prose, never as the token.

## Tier 3 — the brand: a told story

*Jeliya* is the Manding word for the art of the jeli (in French, the
**djéli** or griot) — the hereditary keeper of the community's true record.
In the target market the jeli is universally understood, and the concept
maps directly onto what the product does: a tamper-evident log nobody can
quietly rewrite. The name is an asset, not a problem; it just has to be
told. The French onboarding carries one quiet line of dim prose under the
wordmark (no badge, no animation):

> Jeliya — l'art du djéli, gardien de la mémoire vraie.

## Recorded scoping decisions

1. **Daemon/CLI output stays English.** Operators and agents grep logs and
   search error text; translated diagnostics are a support liability. Daemon
   errors already reach the UI as structured `{code, message, hint}`, so the
   UI can translate the message around a frozen code token without the
   daemon ever localizing.
2. **RTL is out of scope for French/Bambara.** Both use LTR Latin
   orthography — add no speculative RTL layout work. (N'Ko, if it ships
   later, is RTL and gets its own groundwork phase.)
3. **Status labels are an English-token contract.** `labelTone()` in
   `ui/src/lib/format.ts` (the reference implementation, normative in
   [`PROTOCOL.md`](PROTOCOL.md)) derives chip/dot tone from known English tokens;
   labels it can't read (any language) render neutral — green is earned,
   never a fallback. The long-term fix is a typed severity field on the
   agent-status protocol event so tone keys off protocol truth, not prose.
4. **Text locale ≠ formatting locale.** Bambara users will run fr-locale
   systems; locale plumbing must let UI strings (bm) and date/number
   formatting (fr) diverge from day one. (The seam today is
   `ui/src/l10n/formats.ts` — every display formatter lives there, reached
   through `useFormats()`.)
5. **Rollout scope.** A language ships **full-catalog** or not at all. The
   workbench shows the room rail, the timeline, and the inspector at once, so
   a partial translation would put two languages in one window;
   `SUPPORTED_LOCALES` in `ui/src/l10n/locale.ts` lists only the languages
   with a complete catalog, and anything outside it falls back.
   `ui/src/l10n/catalog.ts` is the complete inventory — one member per
   user-visible string. [`agent-guide.md`](agent-guide.md) stays English (an
   API contract, not an onboarding surface); a `README.fr.md` quickstart is
   still outstanding.
6. **Bambara feasibility notes.** Standard orthography needs ɛ ɔ ɲ ŋ — the
   sans stack covers them on mainstream platforms; smoke-test the mono stack
   before shipping bm. CLDR bm has a single plural category, which an
   ICU-based catalog handles with no extra work.
7. **Typographie française (settled 2026-07-09, before the first French
   string was written).** `scripts/check-ui-i18n.mjs` enforces the
   non-breaking-space, apostrophe, ellipsis, and guillemet rules
   mechanically; register and casing stay a review obligation.
   - **Espaces insécables** : espace fine insécable U+202F before `;` `!`
     `?` and inside guillemets (« texte ») ; espace insécable U+00A0 before
     `:`. Never a breaking space before high punctuation.
   - **Apostrophe typographique** U+2019 (l’identité), **ellipse** U+2026
     (…) — both already the EN catalog's norm.
   - **Guillemets « »** (with the U+202F inner spaces) wherever EN uses
     curly quotes “ ”.
   - **Sentence case** (« Créer un salon », never Title Case), accents kept
     on capitals (À propos, États). Traditional orthography (no 1990
     rectifications).
   - **Vouvoiement**, calm and concrete — the app's honest register
     (green-is-earned) carries into French; no exclamatory marketing tone.
   - **Octets** for byte units: o, Ko, Mo, Go (decision 4's accepted
     deviation: unit WORDS follow the text locale). Percent renders
     « 42 % » (U+202F before %).
   - **Tier 3 placement**: the onboarding tagline slot (the one dim line
     under the wordmark) carries the brand story in French —
     « Jeliya — l’art du djéli, gardien de la mémoire vraie. »
