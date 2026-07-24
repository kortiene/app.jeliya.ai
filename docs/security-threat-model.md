---
type: "Architecture"
title: "Security and threat model"
description: "Trust boundaries, assets, threats, controls, and residual risks for the v0.6.0 Jeliya candidate, plus the proposed and unbuilt hosted web-origin, companion, and relay boundaries."
tags: ["authorization", "deployment", "privacy", "security", "threat-model"]
timestamp: "2026-07-20T00:30:00Z"
status: "canonical"
implementation_status: "partial"
verification_status: "partial"
release_status: "unreleased"
audience: ["contributors", "maintainers", "operators", "security-reviewers"]
---

# Security and threat model

Jeliya is a local daemon that stores identity keys, room state, files, and
agent events while communicating with untrusted network peers. The `v0.6.0` target is a trustworthy technical preview, not a claim of
complete security. The current dependency pin carries the room-scoped
synchronization remediation, provisional-peer gate, store retry/degradation
controls, and relay-only verification seam. Exact-revision local qualification
passes. Signed direct and forced-relay evidence still binds the prior dependency
pin and must be repeated before the current source candidate is network-
qualified.

## Candidate boundary

Security conclusions must name the source being evaluated:

| Surface | Revision | Security meaning |
|---|---|---|
| Current public Jeliya dependency | Iroh Rooms `a5d98b70d717f35d3ce60953a88e12e646f2e871` (untagged upstream `main`) | first merge carrying the fixes for `kortiene/iroh-room#121` and `kortiene/iroh-room#119` plus the `kortiene/iroh-room#126` connection-generation follow-ups; local fanout, isolation, and store-degradation qualification passes |
| Current source candidate | Jeliya `922f620b30ee95c82426a7d4404b1f73a70c0958` | exact dependency pin in `Cargo.toml` and `Cargo.lock`; workspace and 67-assertion loopback suites pass; network-qualified at `922f620…` + `a5d98b70…` (signed direct `098c4979` and forced-relay `8bda01e6`) |
| Last network-qualified snapshot | Jeliya `55024a46b3e112796ba2acf1dc408dab26dbba2e` plus Iroh Rooms `71fbb5007bef4ce83631c94762ec68c2beef3d79` | signed direct and forced-relay schema 2 evidence remains valid for this exact prior pair only |
| Superseded `v0.5.0` dependency | Iroh Rooms `d0ceb0b320f1ff3a576b63d8b24aa1bf76a2d3bb` | carried the isolation remediation and relay-only seam; certified for the published `v0.5.0` at Jeliya `c5f740e67d043a1153cf285691e3bc5b2b9a7203`. Still fetchable by commit SHA, but no longer named by tag `v0.1.0-rc.2`, which was re-created upstream and now resolves elsewhere; the `v0.5.0` evidence binds the SHA, not the tag |
| Historical local-remediation verification | Jeliya `fe870c7c5b63f2bf52b031dd1bc8e27e83183be5` plus local Iroh Rooms `3702e8cbcd5ac1808791124dd6bc44068be5f822` | schema 1 direct and forced-relay checks passed, but this older unpublished pair does not qualify a release |

The retained certifying direct and forced-relay runs bind published Jeliya
commit `55024a4…` and published Iroh Rooms pin `71fbb500…`: they
establish direct and relay network operation and public-RPC non-disclosure. They
do not establish room-scoped synchronization isolation — both manifests set
`synchronization_isolation_claimed: false`; that control rests on the upstream
suite at that revision. They do not transfer to `922f620…` + `a5d98b70…`.
Fresh source-built direct and relay runs and signatures are security
requirements, not release administration.

## Assets

- identity private keys and persisted engine state;
- room membership, event history, files, pipes, and agent activity;
- invite tickets and per-start daemon bearer tokens;
- local files and workspaces available to an explicitly enabled agent runner;
- release artifacts, checksums, CI credentials, and evidence-signing material;
- verification evidence, which must be attributable without containing
  secrets.

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Required control |
|---|---|---|---|
| Browser or script client to loopback daemon | local authorized client holding the per-start token | other local processes, hostile web origins, DNS rebinding | loopback bind, host validation, bearer token, origin restrictions, bounded inputs |
| Engine to P2P room network | local identity and accepted room membership | peers, relays, malformed events, malicious room members | signatures, room validation, room-scoped synchronization, authorization before state access |
| Shared event store to public RPC | rooms the local identity has accepted | foreign or invite-only rooms that exist in storage | centralized accepted-room guard before fold, materialization, or return; aggregate filtering |
| Agent runner to host | operator-approved sender, worker, workspace, and room | room messages, generated tasks, subprocess output | explicit opt-in, sender allowlist, least-privilege process, isolated state/workspace, no ambient secret logging |
| Operator environment to certifying source build | exact public commit, pinned lockfiles, explicitly allowed network and CA settings, independently verified complete Zig archive | checkout-local Git attributes/configuration, ambient build controls or credentials, path substitution, Python `ziglang`, unbound build tools | isolated bare Git archive; run-owned HOME/Cargo/npm/Git/temp; controlled path; exact Node/npm/Cargo/cargo-zigbuild/Zig bindings; verified Zig installation root and library directory |
| CI build to public release | reviewed immutable source and complete verified artifacts | third-party actions/tools, compromised downloads, partial jobs, candidate binary attempting to alter release inputs | immutable action pins, verified tool downloads, execution-free validation and sealing, isolated read-only smoke, receipt verification without candidate execution, token only in final step |
| Retained evidence to release decision | exact sanitized manifest signed by the approved evidence key | edited, fabricated, stale, or secret-bearing evidence | pinned public SPKI, detached Ed25519 signature, exact source/dependency checks, ancestry restriction |

## Primary threats and current status

| Threat | Impact | Control | Evidence and remaining risk |
|---|---|---|---|
| Foreign-room data returned through a public RPC | cross-room confidentiality breach | one accepted-room preflight guard before any room-derived read or fold; `agents.fleet` and other aggregates enumerate/filter accepted rooms | local current-tree regressions pass; signed network denial evidence binds the prior `55024a4…` + `71fbb500…` snapshot and must be repeated at the current pin |
| Foreign-room events served or admitted during synchronization | remote extraction or local-store contamination | room-scope `get`, `contains`, `WantEvents`, missing-parent traversal, and administrative tips; reject foreign envelopes and parents | exact-revision malicious `WantEvents`, foreign-parent, and administrative-tip oracles pass at `a5d98b70…`. This control is local upstream qualification, not a network-manifest claim |
| Uninvited dialer pulls room history or live fanout during an open join window | pre-join history disclosure | serve the membership closure only after a verified invite capability proof; defer handshake/fanout until proof or membership promotion; generation-guard connection teardown | `uninvited_provisional_dialer_receives_no_live_fanout` and Jeliya's loopback join suite pass at the current pin; fresh direct/relay integration evidence pending |
| Store hole from a swallowed insert error | local store/fold divergence and unhealed history | retain the accepted event, retry bounded inserts on ticks, defer feed/fanout until persistence, and record durable critical `store_degraded` on exhaustion or overflow | five deterministic recovery/degradation tests pass at `a5d98b70…`; real disk failure remains possible and requires an operator response |
| Invite possession treated as accepted membership | pre-join data exposure | accepted-room index is authoritative; invite-only/never-joined rooms fail closed; joined-then-left archive behavior is explicit | negative never-joined cases and positive archive behavior pass locally |
| Agent identity or state committed from a checkout | public secret disclosure and identity reuse | platform data directory outside the checkout, per-directory deny-all `.gitignore`, repository ignore rules, tracked-secret gate | six secret-storage tests plus repository validation pass locally |
| Reachable vulnerable dependency | code execution, compromise, or denial of service | automated cargo/npm audits; high/critical findings block; explicit owned/expiring exception only when unavoidable | zero cargo/npm vulnerabilities; three maintenance warnings and one yanked version expire 2026-09-30 |
| Compromised action or downloaded build tool | release supply-chain compromise | third-party Actions pinned to immutable revisions; Zig distributions verified before execution; certifying network builds use the official complete Zig archive and exact tool bindings; least-privilege jobs | workflow and local contract tests pass; only the complete Zig archive is independently verified by schema 2, while other recorded tool digests are execution identities; the hosted double run executed for the published `v0.5.0` and executes again for `v0.6.0` on dispatch |
| Partial, mismatched, or post-validation-modified release | incomplete, stale, mislabeled, or candidate-mutated binaries | validate and seal all five private archives in a no-execution job; smoke the immutable artifact separately; verify the receipt without execution before tag/release creation; expose the write token only to the final step | workflow and receipt negative tests pass locally, and the path executed end to end for the published `v0.5.0` five-archive set; it has not yet run for `v0.6.0` |
| Installer extracts modified bytes | local code execution | fetch the matching published checksum, validate filename/format, verify SHA-256, then extract | Unix behavior passes; Windows checksum, tamper, and simulated-reparse behavior passed on public `main` run `29688515781` at `a24f223…`; current-candidate rerun pending |
| Forged or edited verification record | false release confidence | retained exact manifest, canonical public key, detached Ed25519 signature, source/publication/ancestry checks | retained signatures verify for the prior snapshot; the current-pin direct (`098c4979`) and forced-relay (`8bda01e6`) signatures verify for `922f620…` + `a5d98b70…`, and the release evidence gate is READY |
| Secrets copied into logs or evidence | credential or identity disclosure | transient logs confined to run-owned data directories, no address retention, and digest-only retained summaries | retained runs report completed cleanup. Manifests keep only line/byte counts and stream SHA-256 digests and contain no tickets, tokens, seeds, private keys, excerpts, or IP addresses |

## Authorization invariant

A caller-supplied room, invite, event, file, pipe, or agent identifier is
untrusted. Identifier possession is not authorization. Before a public RPC
touches room-derived state, the engine must establish that the local identity
accepted membership in that room. Filtering only after materialization is too
late because names, counts, timing, or errors may already disclose foreign
state.

The accepted-room index is therefore the first guard. A snapshot-level check
is a second defense, not a substitute. Aggregate surfaces must begin with
accepted rooms rather than enumerate the shared store and remove foreign rows
afterward. A rejected request must not mutate room-open state or create a
side-channel through partial work.

Room departure currently preserves access to the local archive for an identity
that previously joined. An invite that has not been accepted must not grant the
same access. Negative never-joined cases and the joined-then-left positive case
pin this security-sensitive product decision.

## Synchronization invariant

RPC guards prevent disclosure from the local API, but they do not make a
foreign event safe to store or serve. Every synchronization session and event
lookup must remain scoped to its room. Known event IDs, causal parents,
administrative tips, and missing-event requests must never become cross-room
read primitives.

The pinned upstream revision enforces that invariant and passes malicious
`WantEvents`, foreign-parent, and administrative-tip tests. The public Jeliya
lockfile resolves that exact code. Fresh signed network evidence remains
mandatory for current-candidate integration qualification.

## Secret-storage boundaries

The agent runner defaults to the OS platform data directory rather than the
repository. Explicit state directories receive a deny-all Git marker, and
unsafe existing markers fail closed. Repository-level ignore and tracked-file
validation provide independent defense against accidental commits. Operators
must still avoid placing production credentials in the agent environment or
workspace.

## Agent boundary

The runner is a deliberate local code-execution surface. The daemon and browser
do not enable it automatically. The operator selects a worker, room, trigger,
allowed senders, data directory, and workspace. The sender allowlist limits who
can trigger work; it does not sandbox an allowed sender's task or make
model-generated commands safe. Run agents with the least-privileged OS account,
isolated state, a minimal environment, and no production credentials unless the
task explicitly requires them.

## Network evidence boundary

The retained schema 2 three-peer direct run demonstrates direct connectivity
across the observed operator/demo topology at Jeliya `55024a4…`. It also
exercised messages, files, pipes, reconnect, and the public-RPC isolation
boundary against the published, remediated public pin `71fbb500…`, which carries
the room-scoped event-lookup isolation. This is the last network-qualified
snapshot, not the current `a5d98b70...` dependency candidate.

Both certifying manifests set
`functional_evidence.foreign_room_non_disclosure.synchronization_isolation_claimed`
to `false`. The network runs therefore certify the **public-RPC** boundary —
room-scoped RPC denial, local-file HTTP denial, and aggregate foreign-room/agent
filtering — and do **not** certify room-scoped synchronization isolation.
`WantEvents`, foreign-parent, and administrative-tip traversal are covered by
the upstream test suite at the pinned revision, which is local qualification,
not network evidence.

The retained certifying forced-relay run passed. Its relay-only source build compiles
against the published seam, self-attests, and forces every role onto relay; its
path assertions hold for the prior revision pair. A fresh current-pin run is
required.

Older schema 1 direct and relay runs passed with the unpublished local
remediation and seam. They are historical functional evidence only and cannot
be projected onto the current implementation or made certifying
retroactively. See
[`verification-evidence.md`](verification-evidence.md#historical-schema-1-local-remediation-evidence)
for the exact revisions, environments, assertions, hashes, cleanup, and
limitations.

## Release boundary

Build jobs must remain read-only. A manual promotion binds an exact version and
public default-branch commit, then requires two independent complete CI runs.
An execution-free read-only job validates the five daemon archives, embedded
UI, filenames, checksums, versions, commit, changelog, signed network evidence,
and source ancestry, then seals exact bytes and provenance in a receipt. A
separate read-only job executes the immutable smoke artifact. The sole writer
fetches the public verification source without credentials and verifies the
receipt without executing candidate bytes; its GitHub token exists only in the
final publishing step.

The finalizer rejects an existing tag or release, keeps the release draft until
uploaded bytes compare exactly, and attempts scoped cleanup of only its own
draft and unchanged run-owned tag on failure. GitHub does not provide a single
transaction across a Git ref and release assets, so any interrupted cleanup
requires operator inspection before retry. Signed or notarized daemon archives
are outside `v0.5.0` unless their platform gates are separately satisfied.

No release action may proceed while the evidence public key is absent, the
network manifests are unsigned, the source/dependency revisions are
unpublished, the two hosted CI passes are missing, or the complete artifact set
has not been verified.

## Proposed hosted boundaries: web origin, companion, and relays

Everything from here to the end of this section describes an **adopted but
entirely unbuilt** architecture. [Production deployment architecture —
decision record](production-deployment-decision.md) adopts the design in
[Production deployment architecture](production-deployment.md) subject to six
binding amendments, and states explicitly that it "does not authorize a
production deployment, and it does not advance any implementation,
verification, or release status".

No part of this exists in the candidate tree. `crates/` contains only
`jeliya-core` and `jeliyad`. There is no web origin, no CDN, no service worker,
no header emission, no companion control protocol, no pairing, no browser
control key, no relay, and no relay-auth credential service. `app.jeliya.ai`
had no resolvable A, AAAA, or CNAME record at the time of the decision record.
Every control listed below is **proposed**: none is implemented, none is
verified, and none is released. Nothing here may be cited as a deployed
protection, and no phase gate below has been attempted.

### The existing loopback boundary is unchanged

The preview boundary described earlier in this document stands exactly as
written. `jeliyad` binds `127.0.0.1` only, exposes no flag for a non-loopback
address, and must never be publicly exposed; the decision record rules out a
public listener, a reverse proxy, a proxied `/ws`, and a remotely reused daemon
token. The proposed companion control protocol is a **separate future surface**
over Iroh with its own authentication and its own scope model. It does not
relax, replace, or inherit the loopback controls, and no hosted origin may ever
receive a daemon bearer token.

Two honest limits of the existing loopback surface carry into any companion
design that co-resides with `jeliyad` on one data directory. First, the
`Origin` and `Sec-Fetch-Site` checks on `/api/session` are browser-shaped
checks: as the code comment in [`serve.rs`](../crates/jeliyad/src/serve.rs)
states, "neither header is a boundary against a non-browser local process,
which can forge both", and that route performs no token comparison at all — the
constant-time bearer comparison guards `/ws` and `/api/files/*`. Second, a
hostile same-user local process and shared multi-user operation are out of
scope. A companion sharing that data directory inherits both exclusions, and
the weaker of the two surfaces bounds the pair.

### Proposed trust boundaries

These extend, and do not replace, the trust-boundary table above. The names
TB1, TB2, and TB3 are the ones used by the architecture document; the "required
control" column states the **proposed** control, none of which exists.

| Boundary | Trusted side | Untrusted side | Required control |
|---|---|---|---|
| TB1, web supply chain: static PWA supply plane to browser session | reviewed source, the promoted build artifact, and its provenance | DNS, CA issuance, CDN account, deployment credentials, frontend dependencies, an installed service worker, and any deliberately malicious first-party build | proposed: build-once and promote-the-digest with SBOM and signed provenance, strict CSP with a Trusted Types policy allowlist, `Clear-Site-Data` and a web-shell kill switch, a client-verifiable binding between the served document and the reviewed source, DNSSEC and CAA |
| TB2, relay metadata: room peers to dedicated relays and the relay-auth credential service | the peer's own end-to-end-encrypted session and local key material | every relay operator, hosting provider, credential requester, and network observer | proposed: relays that never join rooms and store no history, short-lived endpoint-bound credentials so no project secret enters a bundle, a stated minting admission rule, numeric abuse and egress ceilings, sensitive-log handling with bounded retention, and a stated way for a peer to authenticate the relay it dials |
| TB3, native authority: paired browser control client to signed local companion | the companion's native key custody and its own scope enforcement | every paired browser control client and anything driving one, including a compromised origin or CDN | proposed: mutually authenticated end-to-end-encrypted Iroh control protocol with human-confirmed short authentication string, a non-extractable browser control key with a bounded maximum lifetime, an enumerated scope model that names every reachable method, companion-side authorization as the only authority, and no public listener |

### Proposed threats — TB1, the web supply chain

| Threat | Impact | Control | Evidence and remaining risk |
|---|---|---|---|
| Origin, CDN account, or deployment-credential compromise serves hostile first-party code | full read of everything the session renders plus every action inside the granted control scope | proposed: build-once and promote-the-exact-digest with SBOM and signed provenance, manual promotion approval, and an exercised malicious-frontend runbook | nothing exists. The architecture states plainly that CSP "cannot make a deliberately malicious first-party build trustworthy", and the architecture's planning assumptions accept that a hosted first-party origin can observe the content it renders. This is an accepted planning assumption, not a solved problem |
| A confused deputy on `room.join`: a hostile origin mints an identity-bound ticket into a room it controls and has the paired companion redeem it | a signed `member.joined` authored by the victim's device key in an attacker-chosen room, and disclosure of the victim's endpoint to attacker peers | proposed by **amendment A1**: an explicit redemption scope with human confirmation of the room being joined | `requires_room_access_preflight` in [`engine.rs`](../crates/jeliya-core/src/engine.rs) deliberately exempts `room.join` because its authorization object is the key-bound ticket, so there is no existing guard to inherit. Identity binding stops ticket theft, not attacker-chosen rooms. A1 blocks the Phase 1 gate and is open |
| The browser control key's extractability is unspecified, so one origin compromise becomes permanent and off-origin | an exfiltrated control key drives the companion from attacker infrastructure until explicit revocation, surviving rollback, CSP, and service-worker update | proposed by **amendment A1**: a non-extractable browser control key and a bounded maximum lifetime expressed as a duration | the proposal mandates non-extractability only for the browser identity key, which does not exist in the first slice, while the control key is the only key that does. A1 blocks the Phase 1 gate and is open |
| A hostile service worker keeps serving its own cached shell after the CDN pointer is rolled back | rollback restores clean bytes without stopping hostile execution; an installed PWA that is not navigated may not re-check for up to 24 hours | proposed by **amendment A2**: `Clear-Site-Data` in the production header set and a signed kill switch covering the web shell, not only component metadata | no service worker exists in the preview tree and no header emission exists at all. `Clear-Site-Data` appears nowhere in the architecture document's header set. A hostile worker also controls its own fetch handler, so for navigations it may answer from cache and never see a rolled-back origin's headers; the header is necessary but its delivery to an already-hostile client is not guaranteed. A2 blocks the Phase 3 gate and is open |
| The rollback objective measures byte availability, not hostile-code termination | the Phase 3 gate can pass, and a runbook can report containment, while every installed client still executes the attacker's cached shell | proposed by **amendment A2**: restate the rollback objective in terms of hostile-code termination | the stated 15-minute objective and the gate assertion are both satisfiable with hostile code still running. A2 blocks the Phase 3 gate and is open |
| The CSP and the other security headers are emitted by the same CDN that serves the bytes | the adversary in the threat above also controls header emission, so the header set is not an independent control against origin or CDN compromise | proposed: none stated. The architecture lists the headers but does not name an out-of-band emission or attestation path | unaddressed in the architecture document. The header set constrains injected third-party code, not the party that configures the edge |
| `connect-src` is read as an exfiltration control | against a hostile first-party build the permitted origins include the attacker's own, so the directive bounds injection only | proposed: the baseline policy with `default-src 'none'` and `connect-src` limited to self, relay-auth, and relay hosts | the distinction matters: the same policy is a real control against injected third-party script and no control at all against the first party that authored the bundle |
| Trusted Types is required without constraining which policies may be created | injected code creates its own conforming policy and satisfies the requirement, so the enforcement reads stronger than it is | proposed: add an explicit `trusted-types` policy allowlist alongside `require-trusted-types-for 'script'` | the architecture document specifies `require-trusted-types-for 'script'` with no `trusted-types` directive. Adoption is cheap today because the preview UI uses no `innerHTML`, `dangerouslySetInnerHTML`, `eval`, or `new Function`; that is an observation about current code, not an enforced gate |
| No client-verifiable binding ties the served document to the reviewed source | anyone holding CDN or deployment credentials can upload bytes that never came from CI, undetectably from the browser | proposed: a signed manifest or equivalent document-level binding that a client can check | Subresource Integrity is **not** the fix and this document does not propose it: the adversary who rewrites the bundle rewrites the `integrity` attribute in the `no-cache` `index.html` in the same operation, and SRI never covers the top-level document. The repository's review record already rejected re-proposing SRI here. No document-level mechanism is specified anywhere |
| Targeted, per-victim hostile delivery leaves no artifact | one user, IP range, or geography receives a hostile document while auditors, smoke tests, and every other user receive clean bytes | proposed: none stated beyond the general promotion and smoke-test path | `index.html` is served `no-cache`, so every navigation refetches it from the edge and an edge rule can discriminate. The proposed production smoke tests would pass throughout |
| Rollback used as a downgrade primitive | an attacker with pointer control pins the population to a signed, provenance-attested but known-vulnerable N-1, which reads as containment in the runbook rather than as an attack | proposed: none stated. No monotonic version floor accompanies the requirement to keep N and N-1 available | unaddressed in the architecture document |
| DNS or certificate-issuance compromise, or takeover of an unclaimed name | the attacker serves the origin outright; every origin-side control is downstream of the name | proposed: DNSSEC, restrictive CAA, TLS 1.2/1.3 with managed renewal, HSTS, HTTPS redirect, and separate development, staging, and production origins | `app.jeliya.ai` had no resolvable A, AAAA, or CNAME record at the time of the decision record. Confirming DNS, CDN, relay, and signing ownership is an open Phase 0 item |
| Per-branch preview deployments become live near-production origins | branch builds serve near-production code without the production header set, HSTS, or the DNS and CAA controls, and any pairing or relay-auth flow that does not pin the exact production origin would accept them | proposed: none stated. The architecture requires separate development, staging, and production origins but says nothing about disabling provider preview deployments | unaddressed in the architecture document |
| Frontend dependency compromise modifies the emitted bundle before the digest, SBOM, and provenance are computed | provenance faithfully attests hostile bytes and the promotion path deploys them without rebuilding | proposed: extend `--ignore-scripts`, or an equivalently vetted install, from the advisory job to the job that produces the shipped bundle | the shipped bytes come from the build in [`release.yml`](../.github/workflows/release.yml), which runs `npm ci` with dependency lifecycle scripts enabled; the pull-request build in [`ci.yml`](../.github/workflows/ci.yml) has the same exposure but publishes no artifact. Only the separate advisory job uses `npm ci --ignore-scripts`. A hosted web artifact would also be a new pipeline: the existing execution-free validate-and-seal path covers the five daemon archives and the embedded UI, not a CDN upload |
| An already-installed service worker reads the invite ticket from the `/join` navigation request | the ticket is captured before any page script runs, defeating the in-memory bootstrap and `history.replaceState()` ordering entirely | proposed: none stated. Nothing in the architecture constrains service-worker scope on the join route | the request URL seen by a fetch handler retains its fragment, unlike a response URL, and the navigation request is not fragment-stripped. The proposed pull-request gate asserts only that fragments never enter HTTP requests, logs, or crash evidence — a service-worker fetch handler is none of those, so the gate as worded would pass |
| A hostile or careless origin reads the invite fragment from the URL and exfiltrates it | total disclosure of the invitation and its room relationship; identity binding limits redemption to the named invitee but not disclosure | proposed: fragment-only invitations, an in-memory bootstrap calling `history.replaceState()` before React startup, service-worker registration, error reporting, or telemetry, `Referrer-Policy: no-referrer`, no third-party requests on the join route, and structural ticket and token redaction across browser, companion, relay-auth, support, and test tooling | every step listed is code that does not exist. Browser extensions, screenshots, copied links, and OS clipboard managers remain disclosure paths outside the origin's control |
| CSP violation reports carry room-derived or invite-derived strings | a leak channel out of the origin through `document-uri`, query values, and script samples | proposed: scrub reports of `document-uri`, query values, and code samples | the defect today is the inverse of a leak: the baseline policy specifies no `report-to`, `report-uri`, or `Reporting-Endpoints` directive at all, so the scrubbing requirement has no channel to apply to and no reporting exists to detect an injection |
| Browser-peer mode later forces `'wasm-unsafe-eval'` into the same origin's script policy | Wasm compilation from arbitrary bytes permanently removes part of the policy's injection resistance | proposed: none. The baseline `script-src` already anticipates the directive | a Phase 4 concern baked into the Phase 3 header set |
| Reusing the current frontend on a hosted origin carries its same-origin daemon assumption | the shipped client derives its WebSocket URL from `window.location.host` and fetches the per-start daemon token from `/api/session` on that same origin; served from a hosted origin unchanged it treats that origin as the daemon | proposed: replace the same-origin transport assumption with explicit transport interfaces and capability negotiation before any bundle is served from a hosted origin | the component table prohibits giving a browser a daemon token outright. Any path that made a daemon token reachable from a hosted origin would collapse the loopback boundary the preview depends on |

### Proposed threats — TB3, the companion boundary

| Threat | Impact | Control | Evidence and remaining risk |
|---|---|---|---|
| Identity binding mistaken for room authorization | a reader who believes the ticket is identity-bound closes the wrong hole and leaves the `room.join` confused deputy open | proposed by **amendment A1**: an explicit redemption scope with human confirmation of the room being joined | [`supervisor.rs`](../crates/jeliya-core/src/supervisor.rs) rejects a ticket whose invitee key is not the local identity and rejects an expired ticket, then takes the room id straight from the attacker-supplied ticket with no further authorization. That is the correct behavior for its own boundary and is not a defect in the preview; it is the reason A1 exists |
| Authorship laundering on a browser-driven join | a cryptographically genuine, root-and-device-signed membership event attributable to the victim, which revocation cannot recall | proposed by **amendment A1**, plus the general scope model | the joined event is built with the identity and device keys and published after local validation. Signatures make it non-repudiable; nothing recalls it |
| Browser-supplied dial hints as an outbound-probe and deanonymization primitive | the companion emits traffic to attacker-chosen socket addresses, disclosing its endpoint and network position. The peer *identity* cannot be substituted: the join-time dial set iterates the ticket's discovery devices and matches caller hints by endpoint id, and the transport authenticates the remote by that id. Containment stops there. The caller's whole `peers` list is persisted verbatim on a successful join, unfiltered by the ticket, and every persisted hint becomes the dial set of each later room spawn — so an attacker-chosen address is a recurring outbound dial target, not a one-shot probe. A hint may also overwrite the stored address of a legitimate peer id, and because one hint carries a comma-separated address list, an id that *does* match the ticket can smuggle an attacker socket alongside a reachable one: the join succeeds over the reachable address and both are persisted | proposed: an enumerated scope model that either forbids caller-supplied peer hints from a browser controller or requires approval for them | `room.join` matches caller hints against the ticket only when building the ephemeral join dial set (`supervisor.rs:1443-1459`); the raw list is then persisted by `remember_room_with_peer_hints` (`supervisor.rs:1602`), and `merge_peer_hints` (`localstate.rs:140-147`) stores every entry verbatim with no ticket cross-check — `parse_peers` validates syntax only. `stored_hints` feeds them to the room-session dial set on every spawn (`supervisor.rs:749-752`, `:842`). `room.open` is a second injection point with no ticket to bind against at all: it accepts caller `peers`, authorizes with an accepted-room membership check only, and persists them (`supervisor.rs:1016-1027`) — and it is exactly the "selected-room read" the architecture places inside the proposed default browser scope. The join-time allowlist binds inbound admission to the inviter identity; it does not constrain outbound dial addresses, so it is a control against third parties, not against the controller |
| Scope escalation through any gap between the scope list and the method table | a hostile controller reaches native files, pipes, the agent runner, invite minting, or identity reset | proposed: default scopes limited to selected-room reads and idempotent chat sends, with invite creation, file access, pipes, identity operations, and agents behind separate approval, and a Phase 2 gate demonstrating a malicious controller cannot invoke files, pipes, agents, or identity reset | `room.join` is the already-identified instance. The scope model does not exist, and the underlying RPC surface includes identity creation, daemon shutdown, room history, files, pipes, and agent projections |
| Control-key enrollment is itself unenumerated | a compromised origin that can initiate or complete an additional pairing enrolls a second control key it owns; revoking the first leaves the attacker's authority intact while the user believes the incident is closed | proposed: name enrollment explicitly in the scope model and require out-of-band human confirmation for it | pairing and grant enrollment appear in neither the default-scope list nor the separate-approval list. This is a second instance of the A1 gap class, and it is not covered by A1's text |
| Destructive membership actions are unnamed by either scope list | `room.leave` and `room.close` are room-scoped but appear in neither list; eviction from every accepted room is not recoverable without a fresh invite | proposed: name every room-scoped method in one list or the other before the pairing protocol is specified | both methods are in `requires_room_access_preflight`, which answers accepted-room membership, not whether a browser controller may invoke them |
| Selected-room reads where the origin does the selecting | a controller with the read scope walks every accepted room one at a time and drains the history the companion can serve, without triggering a separate-approval prompt | proposed: bind reads to user intent rather than to accepted membership | the engine's preflight answers "has this identity accepted this room", not "did the human ask for this room now". The default scope reads as narrow but is bounded only by total accepted membership |
| Abuse entirely inside the default grant | a compromised origin authors arbitrary messages attributable to the user in every joined room while never leaving its scope | proposed: rate limiting on control keys | idempotency on `client_msg_id` collapses retries of one intent; it bounds duplication, not content or volume. Amendment **A6** restates the limit that applies here: signatures prevent forgery but not copying, and revocation cannot recall material already received |
| Revocation bypass through the offline send queue | the companion signs and publishes queued sends under the root identity after the tab is closed and potentially after the control key is revoked | proposed: none stated. The architecture specifies deferred signing without saying what authorization is checked at signing time | queued sends carry a stable `client_msg_id` and are signed by the companion after reconnection, which defers signing past the point where the authorization may have been withdrawn |
| Expired or revoked control key honored on a live session | revocation does not stop the attack in progress; the user is told the key is revoked while the attacker's session continues | proposed: expiry, immediate revocation, and Phase 1 gate tests requiring expired-key and revoked-key cases to fail closed | checks naturally sit at pairing and at request admission; a long-lived session, an in-flight request, or a cached decision can outlive revocation. No implementation exists to inspect |
| Availability denial as revocation denial | a hostile controller that stops or wedges the companion prevents the very control-key revocation the incident runbook depends on | proposed: none stated. The Phase 2 gate tests only that a malicious controller cannot invoke files, pipes, agents, or identity reset | daemon shutdown is on the RPC surface and shutdown or denial-of-service is not among the gate assertions |
| Dormant grant invisibility | a stolen control key used once a month is indistinguishable from an idle device | proposed: the companion records public key, granted scopes, expiry, creation time, and last use | the metadata is specified; no grant enumeration, review interface, or notification-on-use is specified, so nothing surfaces it to the human who must decide to revoke |
| Pairing replay | an attacker completes a second pairing against an offer the user believes was already consumed, obtaining an authorized control key | proposed: an ephemeral public key, endpoint, and nonce in the offer rather than a reusable bearer secret, a Noise XX-equivalent authenticated transcript, and a Phase 1 gate requiring the replay case to fail closed | the pairing transcript is one of the eight decisions the record explicitly defers to its own future record. Single-use and session-binding properties are not yet specified |
| Wrong short-authentication-string acceptance | a machine-in-the-middle between the browser tab and the companion is detected only by a human comparison; a hurried confirmation pairs an attacker's control key with full default scope | proposed: both sides display the string and require user confirmation, with a Phase 1 gate requiring the wrong-string case to fail closed | this is a human control and degrades exactly where users are hurried. No protocol property recovers from a confirmation given without comparing |
| Induced storage eviction as a path to a phished pairing ceremony | repeated re-pair prompts train the user to confirm, and a hostile or lookalike origin then receives a fresh authorized control key | proposed: none beyond the short-authentication-string comparison itself | the architecture treats cache or pairing-key eviction as a routine re-pair and resync event rather than identity loss. WebKit's seven-day eviction of script-writable storage, cited by the decision record for **amendment A4**, makes involuntary re-pairing ordinary on Safari and iOS |
| Downgrade through version and capability negotiation | the origin selects the weakest control-protocol behavior an older companion accepts, turning every later hardening amendment into an attacker-controlled opt-out | proposed: control-protocol version and capability negotiation with a companion-enforced minimum-safe version floor | negotiation is a Phase 1 deliverable and minimum-safe enforcement is a single line in the architecture document. Neither exists |
| Version skew between an auto-updating origin and a manually updated companion | enabling minimum-safe enforcement hard-fails an unknown fraction of users into a companion that will not talk to the shell, and a stranded user cannot apply the control-key revocation an incident requires | proposed by **amendment A3**: a stated auto-update channel or an explicit decision that there is none, an in-browser upgrade prompt, a grace window before enforcement hard-fails, and a companion-version bucket in the allowed metrics | the repository already records this failure shape: mixed pre- and post-repin fleets cannot complete joins, so joiners and admins must upgrade together. Companion version is not in the allowed telemetry, so the stranded fraction is unmeasurable before enforcement. A3 blocks the Phase 2 gate and is open |
| Unsigned or tampered companion install | a user following a pairing prompt installs a hostile companion that pairs normally and exports the root seed | proposed: signed macOS and Windows packages, a verified Linux package, and installers that verify signatures and reject tampering | bare daemon binaries are unsigned today and macOS notarization and Windows Authenticode are inactive. Every scope control above assumes the process holding the keys is the one the project built |
| Root and device seeds are plaintext at rest | any local read of the data directory yields the root identity outright, defeating every pairing, scope, and revocation control on this boundary | proposed: OS-keystore wrapping through macOS Keychain, Windows DPAPI/CNG, or Linux Secret Service, with any encrypted-file fallback explicit and its password-hardening parameters versioned | [`identity.rs`](../crates/jeliya-core/src/identity.rs) stores both seeds in a single secret file protected by filesystem permissions. Removing plaintext root storage is a Phase 1 gate item, not a current property. Secret key material carries no debug or serialization derive, so a stray format call cannot leak a seed — that control is real today and is unrelated to at-rest protection |
| The companion becomes a second publicly reachable authority surface | a single-user, high-authority local API with identity creation, shutdown, files, pipes, and agents ends up behind public ingress with no tenant, account, quota, or audit model | proposed: the companion exposes no public HTTP or WebSocket listener, never gives a browser a daemon token, never accepts an unpaired controller, with a Phase 2 gate asserting no non-loopback TCP or HTTP control listener | this is a prohibition and a gate assertion, not an implemented mechanism. A reverse proxy in front of `jeliyad` would invalidate the host and origin assumptions rather than supply the missing security model |
| Two high-authority surfaces over one identity | the weaker surface sets the effective bound: a local attacker holding the `jeliyad` token gets the full RPC surface regardless of the companion's scope model, and a companion compromise bypasses every loopback control | proposed: none stated. The architecture does not say whether a companion and `jeliyad` may share a data directory | the loopback threat model explicitly excludes hostile same-user processes and shared multi-user operation, and a co-resident companion inherits that exclusion |
| Pairing and control traffic cross the relay boundary | a relay operator or the relay-auth service learns which companion endpoint pairs with which browser session, when re-pairs happen, and the volume of control traffic; re-pair frequency is itself an incident signal | proposed: the TB2 controls below, which bound retention and abuse but not observation | the control protocol runs over Iroh and therefore over the relays. TB3 does not contain this; TB2 does not remove it |

### Proposed threats — TB2, relays and relay-auth

| Threat | Impact | Control | Evidence and remaining risk |
|---|---|---|---|
| Relay substitution through origin-served environment config | a compromised origin or CDN repoints every browser peer at an attacker-operated relay without touching any relay provider, credential, or account | proposed: none stated. The architecture makes `app.jeliya.ai` responsible for serving public environment config and does not say how the relay list is authenticated | the CSP `connect-src` allow-list is served by the same origin and is no defence against the party that configures it. This composes TB1 into TB2 and is the sharpest path across this boundary |
| No stated relay authentication in the peer direction | DNS hijack, a mis-issued certificate, or a route hijack of a relay hostname yields the same metadata vantage as a compromised relay | proposed: none stated. The design specifies how a peer authenticates to the relay through an endpoint-bound credential and never how the relay authenticates to the peer | no relay-URL pinning, relay public-key pinning, or signed relay list is specified. DNSSEC and CAA are proposed for the web origin only |
| Structural relay metadata exposure in browser mode | source IP, endpoint id, peer-routing relationships, timing, and byte volumes are disclosed on every browser session; relay observation is the only mode, not a degraded fallback | proposed: relays that never join rooms, store no history, and do not retain endpoint relationships indefinitely | browser sandboxes have no UDP hole-punching path, so browser traffic always uses a relay. The prohibitions are operator policy, not properties a peer can verify. Native peers are not exempt in general: relays also assist NAT traversal, and a direct path relocates the disclosure rather than removing it, because a hole-punched path discloses the peer's public IP to every room peer |
| Traffic analysis and social-graph reconstruction without decrypting anything | who talks to whom, session cadence, transfer sizes, and the linkage of a stable endpoint key to a sequence of IP addresses over time | proposed: the retention and prohibited-responsibility rules above, plus bounded log retention | endpoint ids are stable long-lived public keys and no credential- or endpoint-rotation policy is specified. Room content stays end to end encrypted throughout; the loss is entirely metadata, and it is sensitive |
| Relay compromise | wholesale metadata loss plus a selective drop, delay, and reorder primitive against named endpoints, which for a browser peer is a complete cutoff | proposed: an exercised incident runbook for relay project-secret and token-service compromise with relay-token rotation | content confidentiality holds because the relay still cannot decrypt. The prohibitions on joining rooms, storing history, and retaining endpoint relationships are exactly what a compromised relay stops honouring |
| A project-wide relay API secret reaching the browser bundle | every visitor obtains unbounded relay capacity billed to the project, and the leak survives a frontend rollback | proposed: short-lived endpoint-bound credentials minted by the relay-auth service so no project secret enters static assets, and an explicit rule that no build variable, bundle, manifest, or public config contains one | content-hashed assets are served immutable, N-1 is deliberately kept available, and per **amendment A2** a stale or hostile service worker keeps serving its cached shell. Recovery requires provider-side rotation, not a pointer flip |
| Relay-auth service compromise is equivalent to project-secret compromise | unlimited endpoint-scoped token minting plus a second metadata vantage that observes every minting request, its source IP, and its endpoint key | proposed: the same runbook and rotation path | the credential service, not the client, would hold the real project credential. Recovery requires provider-side rotation and re-issuance to every legitimate peer; during that window either the attacker retains minting capability or legitimate browser peers cannot connect |
| Relay-auth as a liveness oracle in the honest design | every peer must mint a credential to come online, so the service holds a first-party presence log for the whole user base | proposed: none stated. The telemetry deny-list governs first-party metrics and does not reach the credential service's own request records | this is a property of the design working correctly, not only of its compromise |
| Credential minting as an abuse and cost channel | any freely generated keypair converts into paid relay capacity, with the egress cost term unbounded and the cost-ceiling gate unfalsifiable because no numeric ceiling is defined | proposed: per-IP and per-endpoint handshake, connection, byte, and rate limits, plus no arbitrary relay egress and no generic TCP proxying | the minting admission rule is now decided in the [relay-auth admission rule record](relay-auth-admission-rule-decision.md) (#49): DH-key-confirmation proof of possession of a companion-countersigned, non-extractable control key; per-control-key and bucketed global mint quotas with a two-plane egress cutoff (mint-shed plus relay-side aggregate-egress termination) at the [published ceilings](relay-load-and-cost-ceilings-decision.md) (#45); a 25% reserve for established keys; and a proof-of-work anchor deferred behind a named trigger. The accepted residual is that a Sybil attacker running many free self-pairings can still pressure availability (not cost) until the anchor triggers |
| Cost-driven denial of service | the economic attack and the availability attack are the same attack: an adversary chooses between exhausting the egress budget and shedding capacity, which is itself the browser-mode outage | proposed: the abuse limits above | no numeric ceiling, load profile, or automatic-cutoff threshold exists, so neither outcome is bounded by anything but the provider bill |
| Targeted quota exhaustion against a named victim | an attacker who knows a victim's endpoint id deliberately consumes that endpoint's relay-side limits, producing a victim-specific denial of service that for a browser peer is a total cutoff | proposed: none. Per-endpoint limits are specified purely as a defence | endpoint ids are public and travel inside invite tickets. The abuse-control surface is also an attack surface and the architecture does not treat it as one |
| Relay unavailability as denial of service | an outage of the relays or of the credential service removes connectivity for every browser peer, which has no direct path to fall back to | proposed: two dedicated relays across two regions, a regional-failover objective of at most two minutes, and a 99.9 percent monthly availability objective for relay-auth plus at least one relay | the architecture states these are launch objectives to measure during beta and explicitly not guarantees. Native peers are less exposed but not unaffected, because relays also assist NAT traversal and native companions use the same short-lived credential policy |
| Environment-config and CSP drift across a regional failover | a failover to a relay host absent from the deployed policy is either an outage or forces a permissive `connect-src` that defeats the exfiltration control | proposed: none. The failover objective and the static immutable header set are specified separately and never composed | unaddressed in the architecture document |
| Short-lived relay credential theft and replay after issuance | a hostile service worker or injected script reads and exfiltrates a live credential, which the policy already permits it to use against the relay hosts | proposed: short-lived endpoint-bound credentials | what "endpoint-bound" binds to — a replayable signature or a channel binding — is unspecified, as is where the browser stores the credential. Combined with **amendment A2**, a hostile worker surviving a pointer flip holds a valid credential for its full lifetime |
| Provider-side access logs outside the first-party telemetry allow-list | a per-user IP-and-timing record exists at the CDN and relay providers even with a perfectly disciplined first-party pipeline | proposed: raw security access logs retained no more than 72 hours with restricted access and documented incident exceptions, and a telemetry deny-list forbidding peer IPs, private addresses, identity, device, and endpoint ids including shortened values, and any stable cross-session identifier | the architecture states that CDN and relay providers necessarily observe source IPs and that access logs must be treated as sensitive. Retention is a policy stated in an engineering document; log aggregation, support escalation, an incident exception, or legal compulsion turns those logs into a deanonymization dataset |
| Jurisdictional and residency consequences of the two-region footprint | user transport metadata is processed in a region the user did not choose and cannot see, and runtime failover moves that processing across jurisdictions invisibly | proposed by **amendment A6**: a named abuse contact and triage owner, a stated retention and lawful-basis position for relay and log data, and an explicit statement of what the architecture can and cannot do about content already distributed | no controller or processor determination, data-processing agreement, transfer mechanism, or impact assessment is planned for the providers that observe source IPs. A6 blocks the Phase 3 gate, which is the first production launch gate, and is open |
| Environment bleed between staging, test, and production relay projects | a staging or CI credential able to mint production relay capacity, and CI traffic mixed into production relay metadata | proposed: separate development, staging, and production origins, relay projects, trust roots, credentials, and browser storage, with dedicated staging relays and a dedicated test relay for companion integration | the cost model prices two relays, creating budgetary pressure to reuse one production relay project across environments — a separation collapse for a financial reason rather than a security decision |
| A relay operator who is also an invited peer | once any identity is an authorized member it receives room content legitimately, converting a metadata-only position into content access for everything shared afterwards | proposed: none available at this boundary. Room content is out of scope for a relay acting as a relay, and this threat is precisely the case where that scoping stops applying | "relays never join rooms" is an operator policy plus a consequence of invite-gated membership; it is not a property enforced against an operator who additionally runs an ordinary invited identity. **Amendment A6** restates the governing limit: signatures prevent forgery but not copying, and revocation cannot recall material already received |
| Endpoint and relay metadata reaching the web origin with no relay compromise at all | a compromised origin reads the victim's endpoint id, dialable IP addresses, and relay URL directly, and combined with an attacker-operated peer links a room identity to a home IP address | proposed: the scope model must decide explicitly whether a status-shaped surface is inside the browser's default scope and must redact dialable addresses and the relay URL if it is | `daemon.status` already returns the endpoint id, the dialable socket addresses, and the relay URL, and it is deliberately absent from `requires_room_access_preflight`. Today it is guarded only by the loopback bind and the per-start bearer token. **Amendment A1** requires bounding companion authority to what the browser may name; this surface is an open instance of that question, not a settled control |
| Retained forced-relay evidence read as qualification for this architecture | a relay boundary ships on evidence that never examined it | proposed: fresh signed direct and forced-relay evidence bound to the current candidate commit and `a5d98b70…`, plus a Phase 0 spike proving a browser reaches a native endpoint through an authenticated relay | the retained relay run certifies the prior revision pair over native daemons through a compile-time relay-only test seam against the general relay path. It says nothing about dedicated relays, nothing about a credential service, and nothing about browser relay connections, and it does not transfer to the current source candidate |

### Proposed residual risks on the hosted boundaries

These are in addition to, and do not replace, the residual risks recorded
below for the preview.

- None of these boundaries exists. Every control in this section is a design
  commitment with no implementation, no verification, and no release.
- A first-party origin can read everything it renders and act within every
  scope it is granted. The architecture proposal records this as a planning
  assumption, and the decision record adopts that architecture without
  amending it. CSP and Trusted Types constrain injected third-party
  code; they do not constrain a deliberately malicious first-party build.
- Bytes already served cannot be recalled. A hostile bundle that executed once
  may have exfiltrated what it rendered; rollback, revocation, and key rotation
  bound future use only.
- Until `Clear-Site-Data` and a web-shell kill switch exist, the time to
  terminate hostile code is unbounded by the rollback objective and can reach
  the 24-hour service-worker staleness cap for an installed PWA that is not
  navigated.
- A compromise of CDN or deployment credentials is not detectable from the
  browser, and a targeted per-victim delivery leaves no artifact for an
  auditor or a smoke test to find.
- Even a non-extractable control key does not stop a compromised origin: a
  malicious same-origin script can invoke a usable key and may observe active
  memory. Non-extractability bounds persistence after rollback, not abuse
  during compromise. This is the browser instance of the existing
  endpoint-compromise residual risk.
- Short-authentication-string comparison is a human control, and no protocol
  property recovers from a confirmation given without comparing.
- Relay metadata exposure is structural for browser mode and no proposed
  control removes it. Short-lived credentials, quotas, and retention limits
  reduce abuse and retention; they do not stop a relay from observing IP,
  endpoint, timing, and volume. Running a native companion changes who observes
  what rather than eliminating observation, because a direct path discloses the
  peer's public IP to every room peer instead of to one relay operator.
- Abuse control and anonymity are in direct tension: per-IP and per-network
  quotas, the only defences that bite against freely generated keypairs,
  require processing the IP data this boundary tries to minimize.
- Whether the origin and CDN compromise case and the maximum authority granted
  to a web controller are adequately bounded is still among the architecture's
  highest-risk unknowns, and eight decisions bearing on these boundaries —
  including provider selection, the companion control protocol and pairing
  transcript, multi-device and revocation semantics, and the browser signing
  strategy — are deferred to their own records. Threats depending on them
  cannot be closed here.
- All six amendments **A1**-**A6** are open and binding, and each blocks the
  phase gate the decision record names for it — including **A4** on the Phase 4
  gate and **A5** on the Phase 2 gate. **A4** and **A5** bound browser-peer
  storage support and accessibility and localization scope; they are not
  restated as threats on this page because neither is a confidentiality or
  integrity boundary threat, not because they carry less weight.

## Residual risks after the release blockers are cleared

- An authorized room member can copy data already shared with that member;
  removal cannot recall it.
- Relay operators can observe transport metadata even though the room content
  is protected by the underlying protocol.
- Endpoint compromise defeats application-level key protection while an
  identity is in use.
- Windows installer reparse-point behavior has not been exercised in the local
  evidence window.
- Comprehensive accessibility conformance and release-artifact
  signing/notarization are not preview security guarantees.

See [`known-gaps-roadmap.md`](known-gaps-roadmap.md) for ownership and release
blocking status, the
[`dependency-risk exception register`](verification-evidence.md#dependency-risk-exception-register)
for current maintenance warnings, and [`SECURITY.md`](../SECURITY.md) for
private reporting.
