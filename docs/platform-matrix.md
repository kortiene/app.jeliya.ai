---
type: "Status Report"
title: "Platform matrix"
description: "Implementation, verification, packaging, and release status for every Jeliya runtime and target platform."
tags: ["packaging", "platforms", "release", "verification"]
timestamp: "2026-07-20T13:20:00Z"
status: "canonical"
implementation_status: "partial"
verification_status: "partial"
release_status: "partial"
audience: ["contributors", "maintainers", "operators", "release-engineers"]
---

# Platform matrix

The latest public release is `v0.5.0` (2026-07-14, daemon-only prerelease
with certified network evidence). The current `v0.6.0` source candidate repins
`iroh-rooms` to untagged `a5d98b70...`; local exact-revision and loopback
qualification passes, and signed direct (`098c4979`) and relay (`8bda01e6`)
runs certify the current `922f620...` + `a5d98b70...` pair from a linux arm64
operator. The retained 2026-07-16 runs certify only the prior `55024a4...` +
`71fbb500...` snapshot. A source build or passing test is not a release.

## Daemon and embedded web UI

| Target | Implementation | `v0.5.0` evidence | Latest public artifact | Preview status |
|---|---|---|---|---|
| macOS arm64 (`aarch64-apple-darwin`) | implemented | archive built and verified by the release workflow; no platform-specific network run | `v0.5.0` archive and sidecar | released; platform network run still absent |
| macOS x86_64 (`x86_64-apple-darwin`) | implemented | certifying signed schema 2 direct and relay runs pass (operator role); installer behavior passes | `v0.5.0` archive and sidecar | certified for `v0.5.0` and the prior `v0.6.0` snapshot; current candidate pending |
| Linux arm64 musl (`aarch64-unknown-linux-musl`) | implemented | archive built and verified by the release workflow; no platform-specific network run | `v0.5.0` archive and sidecar | released; platform network run still absent |
| Linux x86_64 musl (`x86_64-unknown-linux-musl`) | implemented | certifying signed schema 2 direct and relay runs pass on Ubuntu x86_64 under UID `65534`; installer behavior passes | `v0.5.0` archive and sidecar | certified for `v0.5.0`, the prior `v0.6.0` snapshot, and the current candidate (remote role in runs `098c4979`/`8bda01e6`) |
| Windows x86_64 MSVC (`x86_64-pc-windows-msvc`) | implemented | hosted behavioral installer/checksum/tamper, simulated reparse, and native daemon smoke jobs pass on `main` | `v0.5.0` archive and sidecar | released; no platform network run |

The certifying [direct](evidence/v0.6.0/direct.json) (run `098c4979`) and
[relay](evidence/v0.6.0/relay.json) (run `8bda01e6`) schema 2 manifests both
bind the current candidate `922f620…` + Iroh Rooms pin `a5d98b70…`, exercised
from a linux arm64 operator (AS11426) over `demo1`/`demo2` (AS11426 + AS24940);
the remote role ran the `x86_64-unknown-linux-musl` daemon, and the relay run's
verifier source-built and self-attested on all three hosts. macOS-specific
network certification rests on the retained prior-snapshot run and has not been
repeated at the current candidate. The `v0.5.0` manifests
([direct](evidence/v0.5.0/direct.json), [relay](evidence/v0.5.0/relay.json))
bind the released pair `c5f740e…` + `d0ceb0b…` and do not transfer to another
pin. The earlier unsigned
[preview manifest](evidence/v0.5.0/preview-direct-schema2.json) at `0f6769a…`
with pre-remediation pin `3cb9bfd…` remains historical.

The older schema 1
[direct](evidence/v0.5.0/historical-schema1-direct.json) and
[relay](evidence/v0.5.0/historical-schema1-relay.json) manifests use Jeliya
`fe870c7…` and local upstream `3702e8c…`. They remain historical
local-remediation evidence only. See
[Verification evidence](verification-evidence.md).

## Source-only tools

| Surface | Implementation | Verification evidence | Release status | `v0.5.0` decision |
|---|---|---|---|---|
| Agent runner and fleet launcher | JavaScript scripts exist | agent E2E pass; fleet stability 5/5; Linux orphan/zombie cleanup verified remotely | source only | no separate artifact |

Jeliya is daemon-only. The repository contains no desktop or mobile
application for any platform, so there is no native application surface to
implement, verify, or publish.

## Network claims by runtime

| Runtime | Local protocol | Cross-network direct | Forced relay | Reconnect/resync |
|---|---|---|---|---|
| `jeliyad` on macOS x86_64 and Linux x86_64 | implemented | signed direct pass at the current `922f620…` + `a5d98b70…` (Linux, run `098c4979`) and at prior `55024a4…` + `71fbb500…` and released `c5f740e…` + `d0ceb0b…`; macOS-specific current-pin network run not yet done | signed relay pass with self-attestation at the current pair (Linux, run `8bda01e6`) and at the prior pairs; macOS-specific current-pin run not yet done | local current-pin loopback passes; signed current-pin reconnect/resync certified (Linux, runs `098c4979`/`8bda01e6`) |
| Other daemon targets | implemented | no candidate evidence | no candidate evidence | no candidate evidence |

The certifying runs qualify their recorded revision pairs exactly; they do not
transfer to the current candidate, whose pin differs.

## Packaging trust status

`v0.5.0` contains five daemon archives and a SHA-256 sidecar for each. Its
Unix installers pass behavioral fail-closed tests for sidecar verification
before extraction, and the hosted Windows job exercises the PowerShell
installer, tamper rejection, a simulated reparse-point payload, and native
daemon startup.

The release workflow pins third-party actions, verifies downloaded Zig,
keeps build jobs read-only, validates and seals the complete set without
executing it, and runs smoke execution in a separate read-only job. The sole
writer verifies the sealed receipt without executing candidate bytes and
exposes its token only to the final publishing step. It executed exactly this
way to publish `v0.5.0`'s five-target set.
See [Release versus main](release-vs-main.md).

## Intended support matrix (decision, not status)

The [supported platform matrix decision](platform-matrix-decision.md) fixes
the first-slice support commitment for the companion-backed production slice:
the five daemon build targets above as the supported desktop operating
systems (macOS 13 or newer on arm64 and x86_64, Windows 11 plus serviced
Windows 10 22H2 on x86_64, and Linux x86_64/arm64 musl with a stated
reference environment),
the latest two stable releases of Chrome, Edge, Firefox, and Safari in
companion mode, and no mobile support in the first slice. This section
records intent only: nothing in it changes the implementation, verification,
or release status in the tables above, and no capability is available on a
platform it has not run on.
