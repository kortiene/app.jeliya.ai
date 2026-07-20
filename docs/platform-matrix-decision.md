---
type: "Decision"
title: "Supported browser, desktop OS, and mobile matrix — decision record"
description: "Decides the supported desktop operating systems, browser releases, and mobile position for the first production slice, the pull-request test lane each entry maps to, and the denominator for the pairing-success objective."
tags: ["browsers", "decision", "deployment", "platforms", "support"]
timestamp: "2026-07-20T13:20:00Z"
status: "canonical"
implementation_status: "planned"
verification_status: "unverified"
release_status: "unreleased"
audience: ["contributors", "maintainers", "product", "release-engineers"]
---

# Supported browser, desktop OS, and mobile matrix — decision record

**Status: DECIDED 2026-07-20.** This record settles deferred decision 8 of the
[production deployment decision](production-deployment-decision.md) — the
supported browser, desktop OS, and mobile matrix — for the first production
slice at `app.jeliya.ai`. It decides intent only: nothing in it asserts that
any platform is implemented, verified, certified, or released.
[Platform matrix](platform-matrix.md) remains the status page, and its
implementation, verification, and release columns are not changed by this
record.

## What this record supersedes

- It performs the narrowing the plan assumed: "The first supported production
  matrix is desktop-focused and is narrowed in Phase 0 before package work
  starts" ([Production deployment architecture](production-deployment.md),
  planning assumptions). That assumption is discharged by this record, not
  open.
- It narrows, for the first slice, the matrix the Phase 4 gate implies — "the
  latest two Chrome, Edge, Firefox, and Safari releases plus current iOS
  Safari and Android Chrome pass the supported matrix". That list remains the
  Phase 4 browser-peer target; the first slice commits to its desktop subset
  only, as decided below.
- It supersedes nothing else. It reconciles with
  [Platform matrix](platform-matrix.md), which records the intended matrix in
  a section kept separate from its implementation, verification, and release
  status tables.

## Supported desktop operating systems (first slice)

The signed companion of the Phase 2 deliverable — "signed macOS and Windows
packages and a verified Linux package" — targets the same five build targets
the release workflow already produces:

| Operating system | Minimum version | Architectures | Companion package trust |
|---|---|---|---|
| macOS | 13 (Ventura) | arm64 (`aarch64-apple-darwin`) and x86_64 (`x86_64-apple-darwin`) | Developer ID signed and notarized |
| Windows | Windows 10 22H2, and all Windows 11 releases | x86_64 (`x86_64-pc-windows-msvc`) | Authenticode signed |
| Linux | kernel 5.10 or newer with a Secret Service implementation for production keystore mode; Ubuntu 22.04 LTS is the verified-reference distribution | x86_64 and arm64 (musl static) | verified via checksum sidecar and provenance |

This is the closed, named set behind the Phase 1 gate item "recovery succeeds
from a fresh install on every supported OS": macOS 13 or newer on arm64 and
x86_64, Windows 10 22H2 or newer on x86_64, and the Linux reference
environment above on x86_64 and arm64 — five OS/architecture entries and
nothing else.

The same set is the input to signing procurement in
[Signing and notarization](signing-notarization.md) and to the Phase 2
deliverable "signed macOS and Windows packages and a verified Linux package":
Apple Developer enrollment covers the two macOS entries, Authenticode
issuance covers the Windows entry, and the two Linux entries need
checksum-and-provenance publication rather than a platform signing service.

A Linux system without a Secret Service implementation falls back to the
plan's explicit encrypted-file keystore, and setup copy says so; it is a
stated degradation, not silent unsupport.

## Supported browsers (first slice)

Companion mode supports the latest two stable major releases of each of:

| Browser | On which supported OS | Pull-request test lane |
|---|---|---|
| Chrome | Windows, macOS, Linux | Chromium |
| Edge | Windows, macOS | Chromium |
| Firefox | Windows, macOS, Linux | Firefox |
| Safari | macOS | WebKit |

"Latest two" is evaluated against the vendor's stable channel on the day a
release candidate is cut, which keeps the set closed at every evaluation
instant without hard-coding version numbers that expire between releases.
This is where the first slice narrows the Phase 4 reference list: the four
desktop browser families are kept at the same latest-two depth, and the two
mobile entries (current iOS Safari and Android Chrome) are deferred to the
Phase 4 gate. Releases older than the latest two may work but are outside
the support commitment, and the requirements copy on the
download-and-install page says so.

Every supported entry maps to exactly one of the plan's Chromium, Firefox,
and WebKit pull-request test lanes, as tabulated above, so a green lane set
covers the whole committed matrix and no lane runs against browsers nobody
committed to support. When Phase 4 adds iOS Safari and Android Chrome, they
join the WebKit and Chromium lanes respectively.

## The measured matrix

"The supported OS/browser matrix" in the plan's service objectives means the
cross product of the operating-system entries and the browser entries above,
restricted to the cells where the vendor ships that browser on that
operating system. The objective "Companion pairing | At least 99 percent
success on the supported OS/browser matrix" is measured with exactly those
cells as its denominator — sliceable per cell and reportable in aggregate —
so the target resolves to a concrete population instead of an open phrase.

## Mobile position and amendment A4

Mobile is out of scope for the first slice, paired with the slice's existing
exclusion of "mobile background-availability claims": no mobile operating
system, mobile browser, or installed mobile PWA is in the first-slice
support commitment, and the pairing objective above has no mobile cell.

For the Phase 4 browser peer, amendment A4 of the
[production deployment decision](production-deployment-decision.md) binds
this record's mobile position:

- browser-peer mode on iOS is supported only for home-screen-installed PWAs;
- a non-installed Safari tab is treated as companion mode.

Both statements must appear in product copy, not only in the risk register.
The surfaces that must carry them are: the download-and-install page at
`app.jeliya.ai`, the in-app capability notice the shell shows when it
detects a non-installed WebKit browser, and the pairing flow's explanation
of which mode the user is in. The Phase 4 gate item "product copy makes no
durable background-availability claim" is checked against those three
surfaces.

## Outside the support commitment

- mobile operating systems and browsers, until the Phase 4 gate passes;
- browser releases older than the latest two stable majors;
- Windows on arm64, every 32-bit system, and the BSDs;
- Linux systems that cannot provide the reference environment above, beyond
  the stated encrypted-file fallback;
- any browser or operating system not named in the tables above.

On those platforms the product states that the app may load but is
unsupported and untested there, and points at the supported list on the
download-and-install page. No copy claims a capability on a platform it has
not run on.
