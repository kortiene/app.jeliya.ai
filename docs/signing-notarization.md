---
type: "Runbook"
title: "Signing and notarization (Phase 2)"
description: "Release-security plan and procedure for signing the Jeliya daemon release artifacts."
tags: ["linux", "macos", "release", "security", "signing", "windows"]
timestamp: "2026-07-20T17:50:00Z"
status: "canonical"
implementation_status: "partial"
verification_status: "partial"
release_status: "unreleased"
audience: ["contributors", "maintainers", "release-engineers"]
---

# Signing and notarization (Phase 2)

Release binaries to date are unsigned (`v0.1.0`/`v0.2.0` were
released under the project's former name Bantaba — see `docs/naming.md`).
The `curl | sh` and
Homebrew paths install cleanly because they do not set the macOS quarantine bit,
but browser downloads can still trip Gatekeeper on macOS and SmartScreen on
Windows. This document tracks the work needed to ship signed daemon binaries.

Current status:

- The `v0.5.0` workflow publishes only five unsigned `jeliyad` archives with
  their checksum sidecars. It contains no Developer ID signing, notarization,
  or Authenticode step.

The platform input to this plan is the
[supported platform matrix decision](platform-matrix-decision.md): Apple
Developer enrollment and notarization cover macOS 13 or newer on arm64 and
x86_64, Authenticode issuance covers Windows 11 and serviced Windows 10 22H2
on x86_64, and the two Linux musl targets need checksum-and-provenance
publication rather than a platform signing service.

## Procurement status (Phase 0)

Enrollment is tracked here because it is calendar lead time, not engineering
time: the Phase 2 gate needs signed packages, so both credential chains start
during Phase 0. Nothing in this section claims any artifact is signed or
notarized today, and nothing in `release.yml` signs today.

### Eligibility, confirmed before ordering

- Microsoft's managed code-signing service is now named **Azure Artifact
  Signing** (formerly Trusted Signing). Its public-trust restriction was
  confirmed from the primary documentation on 2026-07-20: "For Public Trust
  certificates, Artifact Signing is currently available to organizations in
  the USA, Canada, the European Union, and the United Kingdom, as well as
  individual developers in the USA and Canada" — see the
  [Artifact Signing FAQ](https://learn.microsoft.com/en-us/azure/artifact-signing/faq).
- The enrolling identity is an individual developer resident in the
  USA/Canada region, so the service is expected to be available. One
  prerequisite stands before the fallback is dropped for good: individual
  public-trust identity validation is sourced from the Azure billing
  account, whose type, name, and address must match the intended
  certificate subject — and the paid subscription does not exist yet, so
  that match is unverified. Until identity validation completes, the
  recorded fallback remains a cloud-signing CA whose keys stay in the CA's
  HSM (SSL.com eSigner, DigiCert KeyLocker, or Certum SimplySign) — never
  a raw `.pfx` file.
- Two constraints of the chosen service, recorded so nobody rediscovers
  them later: it requires a paid Azure subscription (free, trial, and
  sponsored subscriptions are rejected), and it issues no EV certificates —
  SmartScreen reputation accrues from download history instead of from the
  certificate class.

### Recorded decisions

- **Apple: individual enrollment.** The Apple Developer Program membership
  is applied for as an **individual** under the maintainer's legal name
  ($99/year; no D-U-N-S number, entity verification, or org-domain website
  required). The Developer ID and notarization identity therefore carry the
  maintainer's personal legal name; switching to an organizational identity
  later is a new enrollment and a new decision. Notarization uses the
  `xcrun notarytool` app-specific-password route recorded above, not an App
  Store Connect API key. The Team ID is recorded here once issued.
- **Windows: Azure Artifact Signing.** Of the three routes recorded below —
  Azure Artifact Signing / cloud HSM, a CA-backed remote signing service,
  or a password-protected `.pfx` secret — the first is chosen. Reasons:
  signing keys are generated and kept in the service's FIPS 140-2 Level 3
  HSMs and are never handed to the project, which satisfies "keep Apple and
  Windows signing material in platform-approved secret/HSM services" with
  no certificate file to custody at all; CI authenticates with a scoped
  Microsoft Entra identity instead of a stored certificate; and the ongoing
  cost is small. The `.pfx` mode is rejected outright; its procedure is no
  longer documented and its secrets must never be created.

### Custody, rotation, and incident response

- The release authority holds every signing credential: the Apple Developer
  account, the notarization app-specific password, and the Azure
  subscription with its Artifact Signing account. All credential values
  live in GitHub Actions repository or environment secrets; none are
  committed to the repository.
- Rotation: the app-specific password is revocable and re-issuable from the
  Apple account at any time; Artifact Signing certificates are short-lived
  and rotate automatically inside the service. That rotation stops if the
  Artifact Signing identity validation lapses, so the release authority
  also owns identity-validation renewal, starts it at Microsoft's first
  reminder sixty days before expiry, and records it in the dated log — an
  expired validation halts release signing even though certificates
  otherwise rotate on their own.
- Incident response: on suspected compromise the release authority cuts
  off the ability to produce new signatures first, then revokes what was
  issued — for the Apple chain, revoking the Developer ID certificate
  through the Apple Developer account and the notarization app-specific
  password (the password alone does not stop code signing with a stolen
  key); for the Windows chain, disabling the scoped Microsoft Entra
  principal or removing its Artifact Signing Certificate Profile Signer
  role assignment so no further signatures can be requested, then revoking
  issued certificates through the service. Signing fails closed: no
  unsigned artifact ships from a signing-enabled job.
- Degraded mode while the sole credential holder is unavailable: no
  promotions and no signing-enabled releases; rollback to already-published
  artifacts only. A named deputy does not exist yet; naming one belongs to
  the production ownership record (Phase 0), alongside DNS, CDN, and relay
  ownership.

### Dated log

| Date (UTC) | Track | State |
|---|---|---|
| 2026-07-20 | Windows | Eligibility confirmed from the Artifact Signing FAQ; Artifact Signing route chosen and recorded; the paid Azure subscription and Artifact Signing account are not yet created |
| 2026-07-20 | Apple | Individual-enrollment decision recorded; enrollment not yet submitted |

Code-signing procurement is **deferred until after the full system is deployed
and tested end-to-end** (decided 2026-07-21, per the
[Code-signing deferral decision](signing-deferral-decision.md), which
supersedes the earlier Phase 0 / Phase 1 timing). Phases 1–5 build, deploy, and
test with unsigned companion artifacts; [#25](https://github.com/kortiene/app.jeliya.ai/issues/25)
(enrollment + issuance) runs in the Release hardening (signing) milestone once
the post-deploy signing gate nears. That post-deploy gate — "supported
installers verify signatures and reject tampering" — is the trust boundary at
which signed, notarized installers become mandatory.

## Goals

- Keep the daemon local-only and reproducible while adding platform trust
  signatures to release artifacts.
- Preserve the manual, exact-version promotion workflow and its private
  artifact staging, two clean CI runs, and sole write-enabled final job.
- Never commit private signing material. All credentials live in GitHub Actions
  repository or environment secrets.

## macOS Developer ID + notarization

Required Apple assets:

- Apple Developer Program membership.
- Developer ID Application certificate exported as a password-protected `.p12`.
- Apple ID app-specific password for notarization (`xcrun notarytool` — the
  workflow uses this route, not an App Store Connect API key).
- Team ID and certificate password as GitHub secrets.

A future reviewed workflow may use the following credentials:

| Secret | Purpose |
| --- | --- |
| `MACOS_CERT_P12` | Base64-encoded Developer ID Application `.p12`. |
| `MACOS_CERT_PASSWORD` | Password for the `.p12`. |
| `MACOS_SIGN_IDENTITY` | Full codesign identity string (`Developer ID Application: …`). |
| `NOTARY_APPLE_ID` | Apple ID that owns the app-specific password. |
| `NOTARY_TEAM_ID` | Developer Team ID. |
| `NOTARY_PASSWORD` | App-specific password for that Apple ID. |

Required future controls:

1. Import the certificate into a throwaway keychain with logs that never expose
   credential values.
2. Sign the daemon binary with hardened runtime enabled.
3. Verify the signature locally before notarization.
4. Submit with `notarytool`, wait for success, and re-verify.
5. Generate the checksum only over the final signed and notarized bytes.
6. Fail closed if any selected signing or notarization step fails. Never fall
   back to an ad-hoc or unsigned artifact in a signing-enabled release.

### Not implemented: signing the bare `jeliyad` archives

The five per-target daemon archives from the `build` matrix are unsigned. A
future signing change requires a separate platform review. Outline:

1. Import the Developer ID certificate into a temporary keychain on the macOS
   build jobs.
2. Build `jeliyad` with `embed-ui` as today.
3. `codesign --timestamp --options runtime --sign "$MACOS_SIGN_IDENTITY" jeliyad`.
4. Package the signed binary into the `.tar.gz` asset.
5. Submit the archive or a zipped staging bundle with `xcrun notarytool submit --wait`.
6. Keep `.sha256` sidecars over the final signed/notarized asset bytes.

Notes:

- Notarization is most valuable for browser-downloaded macOS artifacts. Homebrew
  and `curl | sh` are less affected, but signed artifacts still improve trust.
- A bare CLI daemon archive has no app bundle to staple a notarization ticket
  to; Gatekeeper checks the ticket online.

## Windows Authenticode signing

Not implemented — nothing in `release.yml` signs `jeliyad.exe` today, and no
signing identity or configuration exists yet. This section is the plan.

Required Windows assets:

- A publicly trusted code-signing capability. EV was once preferred here for
  SmartScreen; the chosen Artifact Signing route issues no EV certificates,
  and SmartScreen reputation accrues from download history — see
  [Procurement status](#procurement-status-phase-0).
- Signing key available to GitHub Actions via one of:
  - Azure Artifact Signing (formerly Trusted Signing) / cloud HSM — the
    chosen route (see [Procurement status](#procurement-status-phase-0)),
  - a CA-backed remote signing service,
  - or a password-protected `.pfx` secret (least preferred operationally;
    rejected by the recorded decision).

Workflow outline for the chosen Artifact Signing route:

1. Authenticate the Windows release job to Azure with the scoped Microsoft
   Entra identity holding the Artifact Signing Certificate Profile Signer
   role — workload identity federation (OIDC) preferred, so no certificate
   or client secret is stored in CI at all.
2. Build `jeliyad.exe` with `embed-ui` as today.
3. Sign with SignTool through the Artifact Signing dlib and metadata file
   (endpoint, account name, and certificate-profile name), or with the
   Artifact Signing GitHub Action; the certificate itself is never
   downloaded — the service returns only signed bytes.
4. Verify with `signtool verify /pa /v jeliyad.exe`.
5. Zip the signed executable and generate `.sha256` from final bytes.

The `.pfx` certificate-import flow this section previously outlined is the
rejected route and is deliberately no longer documented as a procedure; its
secrets (`WINDOWS_CERTIFICATE_PFX_BASE64`, `WINDOWS_CERTIFICATE_PASSWORD`)
must not be created.

## Acceptance checklist

- macOS `spctl --assess` / `codesign --verify --deep --strict` passes for signed artifacts.
- Windows `signtool verify /pa /v` passes for `jeliyad.exe`.
- Release artifacts remain named exactly as installers expect.
- Installer smoke tests still pass for macOS/Linux and PowerShell.
- Signing failures fail closed: no unsigned artifact is uploaded from a signing-enabled job.
