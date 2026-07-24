//! The daemon side of the companion control plane (D5b): everything that turns
//! the transport-agnostic `jeliya-companion` runtime into a live, paired
//! surface on this daemon.
//!
//! Four pieces, all behind the opt-in `--companion-control` flag:
//!
//! * **Key provenance** — the companion's two transport secrets (the Ed25519
//!   iroh-endpoint seed and the X25519 Noise static that is its pairing
//!   identity) are derived from the profile device seed with versioned BLAKE3
//!   `derive_key` contexts, exactly like `SecretKeys::room_device`
//!   (issue #91). `identity.secret` stays the only secret-bearing file, so the
//!   companion's *pairing identity* reproduces from it: the derived static and
//!   endpoint id are stable across a recovery-bundle restore (the browser's
//!   pinned fingerprint keeps verifying). The paired-key *records*
//!   (`control_keys.json`) are device-local state and are **not** in the D1
//!   bundle (ADR #3: identity authority only), so after a restore into a fresh
//!   data dir every browser must re-pair. The derivation lives here — not in
//!   `jeliya-core/src/identity.rs` — deliberately: identity.rs is in the
//!   Phase-1 "reopens review" set, and this glue must not reopen the pin.
//! * **Engine-backed dispatch** — maps the three authorized v1 wire methods
//!   onto the existing public [`Engine::dispatch`] arms, so every companion
//!   call crosses the same room-access preflight the WS protocol crosses and
//!   `engine.rs`/`serve.rs` stay untouched. Engine failures cross the wire as
//!   their stable error *code* only, never the free-text message (which can
//!   embed the daemon's absolute data-dir path).
//! * **Terminal pairing policy** — ADR #2 requires the pairing confirmation on
//!   a surface the browser origin cannot render or forge. Until the native UI
//!   exists, that surface is the daemon's own terminal: the operator types the
//!   code *the browser displays*, and the companion compares. Non-interactive
//!   and `--supervised` runs refuse pairing (fail closed). Attacker-influenced
//!   strings (remote-chosen room names) are sanitized before they touch the
//!   terminal so they cannot rewrite the confirmation surface with escape
//!   sequences.
//! * **Persistence** — paired control keys snapshot to `control_keys.json`
//!   through a single writer task (atomic replacement, `0600`, the
//!   `localstate.rs` discipline) so grants survive a daemon restart; a corrupt
//!   file refuses companion startup rather than silently discarding — or
//!   silently masking tampering with — recorded grants.

use std::io::IsTerminal;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncBufReadExt;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};
use zeroize::Zeroizing;

use jeliya_companion::companion_fingerprint;
use jeliya_companion::{
    BoxFuture, ControlDispatch, ControlEndpoint, ControlPolicy, PairingDecision, RelayConfig,
    OFFER_TTL_MS,
};
use jeliya_control::{
    load_records, ControlGateway, ControlKey, ControlKeyRecord, Scope, DEFAULT_LIFETIME,
};
use jeliya_core::engine::Engine;
use jeliya_core::identity::SecretKeys;
use jeliya_protocol::MethodCall;
use serde_json::json;

/// BLAKE3 `derive_key` context for the companion's Ed25519 iroh-endpoint seed,
/// version 1. Immutable once shipped: a scheme change requires a NEW v2
/// context plus legacy dispatch keyed on which derived endpoint existing
/// pairings actually dialed — the same discipline as
/// `ROOM_DEVICE_KDF_CONTEXT_V1` in jeliya-core, including its pinned-vector
/// tripwire (`companion_kdf_v1_vectors_are_pinned`) that fails CI if the
/// context string or the hash ever moves.
const COMPANION_IROH_KDF_CONTEXT_V1: &str =
    "jeliya.ai app.jeliya.ai 2026-07-23 companion iroh endpoint seed v1";

/// BLAKE3 `derive_key` context for the companion's X25519 Noise static secret
/// (its long-lived pairing identity; the QR fingerprint pins its public key),
/// version 1. Immutable; see [`COMPANION_IROH_KDF_CONTEXT_V1`].
const COMPANION_NOISE_KDF_CONTEXT_V1: &str =
    "jeliya.ai app.jeliya.ai 2026-07-23 companion noise static v1";

/// Where paired control keys persist, under the daemon data dir.
const CONTROL_KEYS_FILE: &str = "control_keys.json";

/// How often the single writer task re-checks the gateway against disk. The
/// wire spec persists `last_used_ms` "at most once per minute otherwise", so a
/// pure last-used bump reaches disk on this cadence; structural changes — the
/// only ones that matter for authorization — are flushed immediately out of
/// band (a pairing install signals a flush the moment it lands).
const PERSIST_TICK: Duration = Duration::from_secs(60);

/// The pairing prompt waits at most this long for the operator to type the
/// code, comfortably inside the runtime's 120 s pairing deadline so the
/// companion, not a dangling prompt, is what times out.
const PAIRING_PROMPT_TIMEOUT: Duration = Duration::from_secs(110);

/// How long the bind may take (it waits for the endpoint to advertise reachable
/// paths) before an explicit `--companion-control` request fails loudly rather
/// than hanging daemon start.
const BIND_TIMEOUT: Duration = Duration::from_secs(30);

/// Derive one companion transport secret from the profile device seed under a
/// versioned context. Deterministic on purpose: the companion identity
/// reproduces from `identity.secret` alone, and the two contexts
/// domain-separate the two secrets from each other and from every room-device
/// key.
fn derive_companion_secret(keys: &SecretKeys, context: &str) -> Zeroizing<[u8; 32]> {
    // Wrap the extracted device seed immediately, as identity/recovery do: on a
    // password-protected profile this is decrypted long-term key material, and
    // it must not linger on the stack after derivation.
    let device_seed = Zeroizing::new(keys.device.to_seed());
    Zeroizing::new(blake3::derive_key(context, device_seed.as_slice()))
}

/// Replace anything that could steer a terminal — control characters, escape
/// sequences, newlines, carriage returns — with the Unicode replacement
/// character, and cap the length. Remote peers choose room names (a joined
/// room's name is the creator's signed `room.created` field), and those names
/// are printed onto the ADR #2 pairing-confirmation surface; an unsanitized
/// name could carry `\x1b[…` sequences that rewrite the scope/lifetime the
/// operator is asked to approve.
fn sanitize_for_terminal(s: &str) -> String {
    const MAX: usize = 80;
    let mut out: String = s
        .chars()
        .map(|c| if steers_display(c) { '\u{fffd}' } else { c })
        .take(MAX)
        .collect();
    if s.chars().count() > MAX {
        out.push('…');
    }
    out
}

/// Whether a character can move the cursor, hide text, or reorder what is
/// around it.
///
/// `char::is_control` covers only the C0/C1 controls (general category `Cc`),
/// which leaves two families that steer a rendered line just as effectively:
///
/// * **`Cf`, format characters** — the bidirectional overrides and isolates
///   that reverse the visual order of everything after them, the zero-width
///   joiners, the interlinear-annotation marks, and the tag characters that
///   carry an invisible ASCII payload.
/// * **`Zl`/`Zp`, line and paragraph separators** — line breaks that are not
///   `\n`, so a renderer can split a row the sanitizer thought was one line.
///
/// The `Cf` set is enumerated **in full** rather than approximated by the few
/// blocks that are most often abused, because a denylist covering the obvious
/// ones is precisely the kind that gets walked around. The ranges below are
/// exactly `Cf ∪ Zl ∪ Zp` as of **Unicode 15.0**, cross-checked against the
/// Unicode character database in both directions — nothing in those categories
/// is missed, and nothing outside them is caught (so legitimate international
/// room names survive intact). Re-run that check when adopting a newer Unicode
/// revision: this is still a denylist, which is why the surfaces printing
/// untrusted strings also bound their length and line count rather than
/// trusting this function alone.
fn steers_display(c: char) -> bool {
    c.is_control()
        || matches!(c,
            // Zl / Zp — line breaks that are not '\n'.
            '\u{2028}' | '\u{2029}'
            // Cf — format characters.
            | '\u{00ad}'                // SOFT HYPHEN
            | '\u{0600}'..='\u{0605}'   // Arabic number signs
            | '\u{061c}'                // ARABIC LETTER MARK
            | '\u{06dd}'                // ARABIC END OF AYAH
            | '\u{070f}'                // SYRIAC ABBREVIATION MARK
            | '\u{0890}'..='\u{0891}'   // Arabic pound/piastre marks above
            | '\u{08e2}'                // ARABIC DISPUTED END OF AYAH
            | '\u{180e}'                // MONGOLIAN VOWEL SEPARATOR
            | '\u{200b}'..='\u{200f}'   // zero-width space/joiners, LRM/RLM
            | '\u{202a}'..='\u{202e}'   // bidi embeddings and overrides
            | '\u{2060}'..='\u{2064}'   // word joiner, invisible operators
            | '\u{2066}'..='\u{206f}'   // bidi isolates, deprecated formats
            | '\u{feff}'                // ZWNBSP / BOM
            | '\u{fff9}'..='\u{fffb}'   // interlinear annotation
            | '\u{110bd}' | '\u{110cd}' // Kaithi number signs
            | '\u{13430}'..='\u{1343f}' // Egyptian hieroglyph formats
            | '\u{1bca0}'..='\u{1bca3}' // shorthand format controls
            | '\u{1d173}'..='\u{1d17a}' // musical symbol formats
            | '\u{e0001}'               // LANGUAGE TAG
            | '\u{e0020}'..='\u{e007f}' // TAG characters (invisible ASCII)
        )
}

/// Executes an authorized companion call against the engine's public dispatch
/// table — the same `room.timeline` / `room.members` / `message.send` arms,
/// and therefore the same room-access preflight, the WS protocol uses. This
/// seam never widens scope: the gateway authorized exactly this call before the
/// runtime hands it over, and the mapping below adds no method, no room, and no
/// parameter the wire call did not carry.
struct EngineDispatch {
    engine: Arc<Engine>,
}

impl ControlDispatch for EngineDispatch {
    fn dispatch(&self, call: MethodCall) -> BoxFuture<'_, Result<Vec<u8>, String>> {
        Box::pin(async move {
            let (method, params) = match call {
                // The cursor (`after`) form routes to the engine's
                // `timeline_after`, which materializes the whole settled tail
                // (`room_tail(u32::MAX)`) before paging — unbounded work a
                // paired browser could amplify with tiny cursor requests. The
                // engine path is in the Phase-1 reopen set, so rather than
                // change it here we withhold the cursor form over the companion:
                // clients use the bounded newest-`limit` snapshot (`after` =
                // None, capped by the wire's MAX_TIMELINE_LIMIT). Lift this once
                // the engine gains a bounded cursor query.
                MethodCall::RoomTimeline { after: Some(_), .. } => {
                    return Err("unsupported".to_owned())
                }
                MethodCall::RoomTimeline {
                    room_id,
                    limit,
                    after: None,
                } => (
                    "room.timeline",
                    json!({ "room_id": room_id, "limit": limit }),
                ),
                MethodCall::RoomMembers { room_id } => {
                    ("room.members", json!({ "room_id": room_id }))
                }
                MethodCall::MessageSend {
                    room_id,
                    body,
                    client_msg_id,
                } => (
                    "message.send",
                    json!({ "room_id": room_id, "body": body, "client_msg_id": client_msg_id }),
                ),
            };
            let value = self.engine.dispatch(method, params).await.map_err(|err| {
                // Only the stable machine code crosses the wire. The free-text
                // CoreError message can embed the daemon's absolute data-dir
                // path (e.g. a failed state.json write), which a paired browser
                // must never learn.
                err.kind.code().to_owned()
            })?;
            serde_json::to_vec(&value).map_err(|_| "internal".to_owned())
        })
    }
}

/// Why a pairing confirmation cannot be presented, if it cannot. Pure so the
/// fail-closed matrix is unit-testable without a terminal.
fn pairing_refusal(supervised: bool, stdin_tty: bool, stdout_tty: bool) -> Option<&'static str> {
    if supervised {
        // The parent app owns all UX in sidecar mode; a prompt would race its
        // stdin-EOF parent-death watch, and there is no human at this terminal.
        return Some("--supervised runs cannot confirm a pairing; the parent app owns pairing UX");
    }
    if !stdin_tty || !stdout_tty {
        return Some("pairing needs an interactive terminal for the SAS confirmation");
    }
    None
}

/// Whether the code the operator typed confirms the ceremony's SAS. Exact
/// match after trimming surrounding whitespace: the SAS is transcript-derived
/// and unique per ceremony, so a stale line from an abandoned earlier prompt
/// can never confirm a later ceremony.
fn typed_code_confirms(typed: &str, sas: &str) -> bool {
    let typed = typed.trim();
    !typed.is_empty() && typed == sas
}

/// The terminal pairing policy: the companion-local trusted surface until the
/// native UI exists. The prompt deliberately does NOT print the companion's own
/// SAS — the only place the code exists for the operator is the browser's
/// display, so typing it here proves the operator actually read the browser
/// side, and the companion performs the comparison itself. A middle party would
/// show the browser a different transcript's code, which cannot match.
///
/// Lines come from a single long-lived stdin reader (`lines`), not a
/// per-ceremony blocking read: a ceremony that the runtime tears down (deadline
/// or revocation) leaves no orphaned reader parked on the process stdin lock
/// that could swallow the next ceremony's typed code. Each confirmation drains
/// any line buffered before it started (a stale code from an abandoned prompt)
/// and then waits for a fresh one.
struct TtyPolicy {
    engine: Arc<Engine>,
    supervised: bool,
    /// The stdin line stream, present only when interactive pairing is enabled.
    /// Its absence is itself a fail-closed refusal.
    lines: Option<Arc<Mutex<mpsc::Receiver<String>>>>,
}

impl TtyPolicy {
    /// The rooms the grant would cover: only the rooms this identity has
    /// **currently open**, enumerated at confirmation time. Closed and archived
    /// (left/removed) rooms that `room.list` also returns are deliberately
    /// excluded — the wire spec binds the readable set to the rooms explicitly
    /// opened through the companion, so a pairing must not silently grant every
    /// room the profile has ever touched. Rooms opened after pairing are NOT
    /// covered until a future re-pair or a native grant-management UI. Names are
    /// sanitized for display; the *ids* (never remote-chosen) are what binds.
    async fn current_rooms(&self) -> Vec<(String, String)> {
        let listed = match self.engine.dispatch("room.list", json!({})).await {
            Ok(value) => value,
            Err(err) => {
                warn!("companion pairing: room.list failed: {}", err.kind.code());
                return Vec::new();
            }
        };
        listed["rooms"]
            .as_array()
            .map(|rooms| {
                rooms
                    .iter()
                    .filter(|room| room["open"] == json!(true))
                    .filter_map(|room| {
                        let id = room["room_id"].as_str()?.to_owned();
                        let name = room["name"].as_str().unwrap_or("unnamed").to_owned();
                        Some((id, name))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl ControlPolicy for TtyPolicy {
    fn confirm_pairing(&self, sas: &str) -> BoxFuture<'_, PairingDecision> {
        let sas = sas.to_owned();
        Box::pin(async move {
            if let Some(reason) = pairing_refusal(
                self.supervised,
                std::io::stdin().is_terminal(),
                std::io::stdout().is_terminal(),
            ) {
                warn!("companion pairing refused: {reason}");
                return PairingDecision::Reject;
            }
            let Some(lines) = self.lines.clone() else {
                warn!("companion pairing refused: no stdin reader");
                return PairingDecision::Reject;
            };

            let rooms = self.current_rooms().await;
            println!("\n── Companion pairing request ─────────────────────────");
            if rooms.is_empty() {
                println!("   NOTE: no rooms are open; the grant would authorize");
                println!("   nothing. Open the rooms to share first, then re-pair.");
            } else {
                println!("   If approved, the browser may read and send in these");
                println!("   currently-open rooms:");
                for (id, name) in &rooms {
                    println!(
                        "     - {}  ({})",
                        sanitize_for_terminal(name),
                        sanitize_for_terminal(id)
                    );
                }
            }
            println!("   Key lifetime: 30 days. Scope: read + send only.");
            println!("   Type the pairing code EXACTLY as the browser shows");
            println!("   it to approve, or press Enter / wait to reject:");
            print!("   code> ");
            let _ = std::io::stdout().flush();

            let typed = {
                let mut rx = lines.lock().await;
                // Discard any line typed before this prompt opened (a stale
                // code from a prior, abandoned ceremony): it cannot confirm
                // this transcript anyway, and draining it keeps it from being
                // mistaken for this ceremony's answer.
                while rx.try_recv().is_ok() {}
                // On timeout (Err) or a closed channel (Ok(None)) there is no
                // line — either way the ceremony is rejected below.
                tokio::time::timeout(PAIRING_PROMPT_TIMEOUT, rx.recv())
                    .await
                    .unwrap_or_default()
            };

            match typed {
                Some(line) if typed_code_confirms(&line, &sas) => {
                    let rooms: std::collections::BTreeSet<String> =
                        rooms.into_iter().map(|(id, _)| id).collect();
                    println!(
                        "   Approved: control key installed for {} room(s).",
                        rooms.len()
                    );
                    info!("companion pairing approved for {} room(s)", rooms.len());
                    PairingDecision::Approve {
                        scopes: [Scope::RoomRead, Scope::MessageSend].into_iter().collect(),
                        rooms,
                        lifetime: DEFAULT_LIFETIME,
                    }
                }
                _ => {
                    println!("   Rejected: the code did not match (or the prompt timed out).");
                    warn!("companion pairing rejected at the terminal");
                    PairingDecision::Reject
                }
            }
        })
    }
}

/// Path of the persisted control-key store under the data dir.
pub(crate) fn control_keys_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CONTROL_KEYS_FILE)
}

/// Persist a gateway snapshot as a durable atomic replacement (`0600`), the
/// exact discipline `state.json` uses in jeliya-core's `localstate.rs`.
fn persist_snapshot(path: &Path, snapshot: &str) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    atomicwrites::AtomicFile::new(path, atomicwrites::AllowOverwrite)
        .write_with_options(|file| file.write_all(snapshot.as_bytes()), options)
        .map_err(|err| format!("could not durably replace {}: {err}", path.display()))
}

/// The per-key authority projection of a gateway snapshot, keyed by the control
/// key's bytes, with `last_used_ms` deliberately excluded — two records with the
/// same projected value grant exactly the same authority. An unparseable
/// snapshot yields an empty map (so a corrupt read can never be mistaken for a
/// grant install; see [`install_since`]).
fn structural_records(snapshot: &str) -> std::collections::BTreeMap<[u8; 32], String> {
    let records = load_records(snapshot).unwrap_or_default();
    records
        .iter()
        .map(|record| {
            let mut scopes: Vec<u16> = record.scopes().map(Scope::registry_id).collect();
            scopes.sort_unstable();
            let mut rooms: Vec<&str> = record.rooms().collect();
            rooms.sort_unstable();
            let value = format!(
                "{}|{}|{}|{scopes:?}|{rooms:?}",
                record.created_at_ms(),
                record.expires_at_ms(),
                if record.is_revoked() { "r" } else { "-" },
            );
            (record.key().0, value)
        })
        .collect()
}

/// Whether a grant was **installed or re-installed** between `baseline` and
/// `current` — a key present in `current` that is new, or whose authority
/// projection changed (a re-pair that refreshes expiry or widens rooms reuses
/// the same key, so mere key-presence is not enough). A key that only
/// *disappeared* (an expiry eviction the Persister performs on its own timer)
/// is explicitly NOT a success: the pairing loop must never mistake background
/// housekeeping for a completed ceremony. A bare `last_used_ms` bump leaves the
/// projection unchanged and so is also ignored.
fn install_since(
    baseline: &std::collections::BTreeMap<[u8; 32], String>,
    current: &std::collections::BTreeMap<[u8; 32], String>,
) -> bool {
    current
        .iter()
        .any(|(key, value)| baseline.get(key) != Some(value))
}

/// A single-writer persistence task: the ONLY code that writes
/// `control_keys.json`, so two callers can never race an atomic replace and
/// commit a stale snapshot over a fresh one. It writes on a slow timer (for
/// lazy `last_used_ms`), on demand (a flush the moment a pairing installs), and
/// once more on shutdown.
struct Persister {
    tx: mpsc::Sender<PersistMsg>,
    task: JoinHandle<()>,
}

enum PersistMsg {
    /// Write now if the store changed; ack `Ok(())` once the current state is
    /// durable on disk, or `Err` with why the write failed.
    Flush(oneshot::Sender<Result<(), String>>),
    /// Evict expired keys, write a final snapshot, ack, and exit.
    Shutdown(oneshot::Sender<()>),
}

impl Persister {
    fn start(gateway: Arc<Mutex<ControlGateway>>, keys_path: PathBuf) -> Self {
        let (tx, mut rx) = mpsc::channel::<PersistMsg>(8);
        let task = tokio::spawn(async move {
            let mut last_written = gateway.lock().await.snapshot_json();
            let mut tick = tokio::time::interval(PERSIST_TICK);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the immediate first tick; baseline already matches disk.
            tick.tick().await;

            // Write the snapshot if it differs from what is on disk. Returns
            // whether the current state is durable: `Ok(())` on a successful
            // write OR when there was nothing to write (last_written already
            // reflects a prior successful write); `Err` when the write failed,
            // in which case `last_written` is NOT advanced so the next tick or
            // flush retries.
            let write_if_changed = |last: &mut String, gw_snapshot: String| -> Result<(), String> {
                if gw_snapshot == *last {
                    return Ok(());
                }
                persist_snapshot(&keys_path, &gw_snapshot).inspect(|()| *last = gw_snapshot)
            };

            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let snapshot = {
                            let mut gw = gateway.lock().await;
                            gw.evict_expired();
                            gw.snapshot_json()
                        };
                        if let Err(err) = write_if_changed(&mut last_written, snapshot) {
                            error!("control-key persistence failed: {err}");
                        }
                    }
                    msg = rx.recv() => match msg {
                        Some(PersistMsg::Flush(ack)) => {
                            let snapshot = gateway.lock().await.snapshot_json();
                            let result = write_if_changed(&mut last_written, snapshot);
                            if let Err(err) = &result {
                                error!("control-key persistence failed: {err}");
                            }
                            let _ = ack.send(result);
                        }
                        Some(PersistMsg::Shutdown(ack)) => {
                            let snapshot = {
                                let mut gw = gateway.lock().await;
                                gw.evict_expired();
                                gw.snapshot_json()
                            };
                            if let Err(err) = write_if_changed(&mut last_written, snapshot) {
                                error!("final control-key persistence failed: {err}");
                            }
                            let _ = ack.send(());
                            return;
                        }
                        None => return,
                    }
                }
            }
        });
        Self { tx, task }
    }
}

/// Flush now and wait until the current state is durable, returning whether it
/// is. Used on a successful pairing so the loop only announces success once the
/// grant has actually reached disk. `Err` if the write failed or the writer is
/// gone — in either case the just-installed key is not durable.
async fn flush_now(tx: &mpsc::Sender<PersistMsg>) -> Result<(), String> {
    let (ack_tx, ack_rx) = oneshot::channel();
    if tx.send(PersistMsg::Flush(ack_tx)).await.is_err() {
        return Err("persistence task is gone".to_owned());
    }
    ack_rx
        .await
        .map_err(|_| "persistence task dropped the flush".to_owned())?
}

/// Options `main` resolves from flags before spawning the companion.
pub(crate) struct CompanionOptions {
    pub(crate) data_dir: PathBuf,
    pub(crate) engine: Arc<Engine>,
    /// `--companion-pair`: keep a pairing offer open and confirm on this
    /// terminal until one pairing succeeds.
    pub(crate) pair: bool,
    /// `--supervised`: never prompt; every pairing is refused.
    pub(crate) supervised: bool,
}

/// The running companion control plane: the bound endpoint plus its writer,
/// stdin, and (optional) pairing tasks. Shut down explicitly so the final key
/// snapshot always reaches disk after live sessions stop.
pub(crate) struct Companion {
    endpoint: Arc<ControlEndpoint>,
    gateway: Arc<Mutex<ControlGateway>>,
    persister: Persister,
    stdin_task: Option<JoinHandle<()>>,
    pair_task: Option<JoinHandle<()>>,
    pair: bool,
    endpoint_id: String,
    fingerprint_hex: String,
}

/// Bind the companion control endpoint (direct connectivity only — the
/// production relay posture is issue #49's decision, not this flag's) and start
/// its writer + stdin tasks. Prints nothing to stdout: the supervision contract
/// requires the `ready` JSON line to be first, and `main` starts the pairing
/// loop (which does print) only after that line. Fails rather than degrades: no
/// identity, a non-interactive terminal under `--companion-pair`, an
/// unreadable/corrupt key store, or a bind failure refuse companion startup
/// with the reason.
pub(crate) async fn spawn(opts: CompanionOptions) -> Result<Companion, String> {
    // Fail fast on a pairing request that can never confirm (piped/redirected
    // stdio), instead of accepting it and rejecting every ceremony deep inside
    // confirm_pairing with only a log line.
    if opts.pair
        && pairing_refusal(
            opts.supervised,
            std::io::stdin().is_terminal(),
            std::io::stdout().is_terminal(),
        )
        .is_some()
    {
        return Err(
            "--companion-pair needs an interactive terminal (stdin and stdout must be a TTY, \
             and it cannot combine with --supervised)"
                .to_owned(),
        );
    }

    // Identity first: without a device seed there is no companion identity to
    // derive. (Create the identity by opening the app once, then restart with
    // --companion-control.)
    let keys = SecretKeys::load(&opts.data_dir)
        .map_err(|err| format!("companion control needs the device identity: {err}"))?;
    let iroh_secret = derive_companion_secret(&keys, COMPANION_IROH_KDF_CONTEXT_V1);
    let noise_secret = derive_companion_secret(&keys, COMPANION_NOISE_KDF_CONTEXT_V1);
    drop(keys);

    let keys_path = control_keys_path(&opts.data_dir);
    let mut gateway = ControlGateway::new();
    match std::fs::read_to_string(&keys_path) {
        Ok(persisted) => {
            let loaded = gateway.load_persisted(&persisted).map_err(|err| {
                format!(
                    "corrupt {}: {err:?} — remove the file (all pairings are \
                     forgotten and every browser must re-pair) or restore it, \
                     then restart",
                    keys_path.display()
                )
            })?;
            info!("companion control: loaded {loaded} persisted control key(s)");
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("could not read {}: {err}", keys_path.display())),
    }
    let gateway = Arc::new(Mutex::new(gateway));

    // The stdin line reader (single, long-lived) exists only for interactive
    // pairing; without it the policy fails closed.
    let (lines, stdin_task) = if opts.pair {
        let (tx, rx) = mpsc::channel::<String>(8);
        let task = tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(tokio::io::stdin()).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                if tx.send(line).await.is_err() {
                    break;
                }
            }
        });
        (Some(Arc::new(Mutex::new(rx))), Some(task))
    } else {
        (None, None)
    };

    let dispatch = Arc::new(EngineDispatch {
        engine: opts.engine.clone(),
    });
    let policy = Arc::new(TtyPolicy {
        engine: opts.engine,
        supervised: opts.supervised,
        lines,
    });

    // Bind under a timeout: `bind` waits until the endpoint has advertised
    // reachable paths, and a network where that never happens must fail the
    // explicit --companion-control request loudly, not hang the daemon start.
    let endpoint = tokio::time::timeout(
        BIND_TIMEOUT,
        ControlEndpoint::bind(
            *iroh_secret,
            *noise_secret,
            RelayConfig::Direct,
            gateway.clone(),
            dispatch,
            policy,
        ),
    )
    .await
    .map_err(|_elapsed| "the companion control endpoint did not come online within 30s".to_owned())?
    .map_err(|err| format!("could not bind the companion control endpoint: {err}"))?;
    let endpoint = Arc::new(endpoint);

    let (endpoint_id, _) = endpoint.addr_strings();
    let fingerprint_hex = hex::encode(endpoint.fingerprint());
    info!(
        "companion control endpoint bound (direct-only): id {endpoint_id}, static fingerprint {fingerprint_hex}"
    );

    let persister = Persister::start(gateway.clone(), keys_path);

    Ok(Companion {
        endpoint,
        gateway,
        persister,
        stdin_task,
        pair_task: None,
        pair: opts.pair,
        endpoint_id,
        fingerprint_hex,
    })
}

impl Companion {
    /// A one-line human status for the operator, printed by `main` AFTER the
    /// ready line (so stdout's first line stays the machine-readable one).
    pub(crate) fn status_line(&self) -> String {
        format!(
            "companion control bound (direct-only): id {}  fingerprint {}",
            self.endpoint_id, self.fingerprint_hex
        )
    }

    /// Start the pairing-offer loop (only under `--companion-pair`). Separated
    /// from `spawn` because this loop prints the offer surface to stdout, which
    /// must not precede the ready line.
    pub(crate) fn start_pairing(&mut self) {
        if !self.pair || self.pair_task.is_some() {
            return;
        }
        let endpoint = self.endpoint.clone();
        let gateway = self.gateway.clone();
        let persist_tx = self.persister.tx.clone();
        self.pair_task = Some(tokio::spawn(async move {
            pair_loop(&endpoint, &gateway, &persist_tx).await;
        }));
    }

    /// Stop the background tasks, close the endpoint, then write the final
    /// snapshot. Ordering matters: draining the endpoint before the last write
    /// is what gives a pairing that completed just before shutdown (browser
    /// already told `installed=true`) the best chance to reach disk — the
    /// endpoint close awaits in-flight connections, so a key installed during
    /// teardown is captured by the snapshot taken after it returns.
    pub(crate) async fn shutdown(self) {
        if let Some(pair) = self.pair_task {
            pair.abort();
            let _ = pair.await;
        }
        if let Some(stdin) = self.stdin_task {
            stdin.abort();
            let _ = stdin.await;
        }
        // Close (drain) the endpoint before the final snapshot so an install
        // racing teardown lands before the snapshot rather than after it.
        match Arc::try_unwrap(self.endpoint) {
            Ok(endpoint) => endpoint.shutdown().await,
            // A clone still outstanding (shouldn't happen once the tasks above
            // are joined) still closes when the last Arc drops.
            Err(_still_shared) => {}
        }
        // Final durable write, after sessions have stopped.
        let (ack_tx, ack_rx) = oneshot::channel();
        if self
            .persister
            .tx
            .send(PersistMsg::Shutdown(ack_tx))
            .await
            .is_ok()
        {
            let _ = ack_rx.await;
        }
        let _ = self.persister.task.await;
    }
}

/// Keep exactly one pairing offer open — reopening only when the current offer
/// has outlived its 120 s TTL unclaimed — until one pairing installs or widens
/// a grant, then stop offering. Success is detected by a grant *install* against
/// the baseline (a new or changed key present in the store), NOT by any
/// structural change: a background expiry eviction removes a key and must never
/// be mistaken for a completed ceremony, and a re-pair that reuses an existing
/// key still registers because its authority projection changes. On success the
/// grant is flushed durably before the loop declares completion.
async fn pair_loop(
    endpoint: &ControlEndpoint,
    gateway: &Arc<Mutex<ControlGateway>>,
    persist_tx: &mpsc::Sender<PersistMsg>,
) {
    let baseline = structural_records(&gateway.lock().await.snapshot_json());

    loop {
        let Some(offer) = endpoint.open_offer().await else {
            // A ceremony is claimed on the previous offer; do not interrupt it.
            // (The registry's TTL frees a wedged slot; we re-check shortly.)
            tokio::time::sleep(Duration::from_secs(1)).await;
            if install_detected(gateway, &baseline).await {
                announce_success(persist_tx).await;
                return;
            }
            continue;
        };
        print_offer(endpoint, &offer, false);
        let opened = tokio::time::Instant::now();

        // Poll until this offer resolves: either a pairing installs a grant
        // (success) or the offer's TTL elapses unclaimed (reopen).
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if install_detected(gateway, &baseline).await {
                announce_success(persist_tx).await;
                return;
            }
            if opened.elapsed() >= Duration::from_millis(OFFER_TTL_MS) {
                // The TTL has passed; break to the outer loop to mint a fresh
                // offer. open_offer() returns None if a ceremony is meanwhile in
                // progress, so we never cut one off.
                break;
            }
        }
    }
}

/// Whether a grant has been installed or re-installed against `baseline`.
async fn install_detected(
    gateway: &Arc<Mutex<ControlGateway>>,
    baseline: &std::collections::BTreeMap<[u8; 32], String>,
) -> bool {
    let current = structural_records(&gateway.lock().await.snapshot_json());
    install_since(baseline, &current)
}

/// Flush the new grant durably, then tell the operator — truthfully. The
/// browser was already told `installed=true` by the runtime, so if persistence
/// failed we cannot un-say that; we surface the durability failure loudly
/// instead of the reassuring "complete" line, so the operator knows the grant
/// will not survive a restart and can fix the data dir and re-pair.
async fn announce_success(persist_tx: &mpsc::Sender<PersistMsg>) {
    match flush_now(persist_tx).await {
        Ok(()) => {
            println!("   Pairing complete: the browser now holds a control key.");
            info!("companion pairing complete; offer loop stopped");
        }
        Err(err) => {
            println!(
                "   WARNING: pairing was accepted but the key could NOT be saved\n\
                             ({err}). It will be LOST on the next restart — fix the\n\
                             data dir and re-pair the browser."
            );
            error!("companion pairing installed but not persisted: {err}");
        }
    }
}

/// Print a pairing offer's surface (endpoint id, reachable addresses, static
/// fingerprint, rendezvous nonce) for the operator to enter in the browser.
fn print_offer(endpoint: &ControlEndpoint, offer: &jeliya_companion::Offer, _reopened: bool) {
    let (endpoint_id, addrs) = endpoint.addr_strings();
    println!("\n── Companion pairing offer (expires in 120s) ─────────");
    println!("   endpoint id : {endpoint_id}");
    for addr in &addrs {
        println!("   address     : {addr}");
    }
    println!("   fingerprint : {}", hex::encode(endpoint.fingerprint()));
    println!("   offer nonce : {}", hex::encode(offer.nonce));
    println!("   Enter these in the browser's pairing screen.");
}

// ---- Administrative pairing commands ---------------------------------------
//
// `--companion-reset-pairings` forgets *every* browser at once, which is the
// wrong instrument for the common case: one browser is lost or compromised and
// must be cut off without re-pairing the others. These two commands are the
// per-pairing instrument — and the visibility it needs, since a control key is
// otherwise only ever seen as 32 opaque bytes inside `control_keys.json`.
//
// Both operate on the persisted store with the data dir exclusively held (see
// `main`), never on a live gateway. That is deliberate: `control_keys.json` has
// exactly one writer by construction, and an administrative process editing it
// underneath a running daemon would break that invariant and could commit a
// stale snapshot over a fresh one. So the operator stops the daemon, revokes,
// and starts it again — and the stop is itself the teardown of any session the
// revoked key was holding, which is why no live-revocation path is needed here.
// (`ControlEndpoint::revoke` remains the seam for the native grant-management
// UI, which will run *inside* the daemon and so can tear down in place.)

/// The shortest `--companion-revoke` prefix that may match. A revocation is
/// destructive and unattended, so a fat-fingered one-character argument must
/// not silently resolve to "the only key there is" — the operator states enough
/// of the id to mean it. Ambiguity beyond this is reported, never guessed.
const MIN_PAIRING_ID_PREFIX: usize = 4;

/// The operator-facing short id for a paired browser control key: the first 8
/// bytes of SHA-256 over its Noise static public, hex. Deliberately the same
/// construction and display width as the companion's own fingerprint (which the
/// pairing offer already prints), so the two ids in the pairing UX read alike.
/// It is a display handle, not an authorization input: nothing is ever admitted
/// by this id — the gateway matches full 32-byte keys.
fn pairing_id(key: &ControlKey) -> String {
    hex::encode(companion_fingerprint(&key.0))
}

/// Refuse a directory that is not a Jeliya profile.
///
/// `main` creates the data dir before it gets here, so a mistyped or defaulted
/// `--data-dir` would otherwise be *manufactured* and then truthfully reported
/// as holding no pairings — an operator auditing after a lost laptop would read
/// "No browser control keys are paired", exit 0, and conclude they were safe
/// while the real profile's grant stayed live somewhere else. An empty store in
/// a real profile is still fine; a store in a directory that has never held an
/// identity is not an answer to the question being asked.
fn require_profile_dir(data_dir: &Path) -> Result<(), String> {
    if data_dir.join(jeliya_core::identity::SECRET_FILE).exists() {
        return Ok(());
    }
    Err(format!(
        "{} holds no Jeliya identity, so it has no pairings to show — check \
         --data-dir (a companion pairing lives in the profile whose identity \
         it was made against)",
        data_dir.display()
    ))
}

/// Read and parse the persisted store. A missing file is an empty list (no
/// browser has ever paired); a corrupt one refuses, with the same actionable
/// message `spawn` gives, rather than being silently read as "no pairings" —
/// which would let tampering present as a clean slate.
fn load_store(data_dir: &Path) -> Result<(PathBuf, Vec<ControlKeyRecord>), String> {
    let path = control_keys_path(data_dir);
    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let records = load_records(&contents).map_err(|err| {
                format!(
                    "corrupt {}: {err:?} — remove the file (all pairings are \
                     forgotten and every browser must re-pair) or restore it",
                    path.display()
                )
            })?;
            // Collapse duplicate entries for one key exactly the way the daemon
            // does when it loads the same file: `ControlGateway::install` is a
            // map insert, so the LAST entry for a key is the one that actually
            // authorizes. Without this, a store carrying a key twice (a hand
            // edit, a merged backup) would list two rows under one id — possibly
            // with contradictory status, only one of which the daemon enforces —
            // and make *every* prefix ambiguous, including the full id, leaving
            // that pairing impossible to revoke through this command.
            let mut by_key: std::collections::BTreeMap<ControlKey, ControlKeyRecord> =
                std::collections::BTreeMap::new();
            for record in records {
                by_key.insert(record.key(), record);
            }
            Ok((path, by_key.into_values().collect()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok((path, Vec::new())),
        Err(err) => Err(format!("could not read {}: {err}", path.display())),
    }
}

/// Render an epoch-millisecond stamp relative to now — "in 29d", "5m ago" —
/// because what the operator decides on is how long a grant has left and how
/// recently it was used, not an absolute timestamp.
fn humanize(stamp_ms: u64, now_ms: u64) -> String {
    let (delta_ms, past) = if stamp_ms >= now_ms {
        (stamp_ms - now_ms, false)
    } else {
        (now_ms - stamp_ms, true)
    };
    let secs = delta_ms / 1_000;
    let magnitude = if secs < 60 {
        format!("{secs}s")
    } else if secs < 3_600 {
        format!("{}m", secs / 60)
    } else if secs < 86_400 {
        format!("{}h", secs / 3_600)
    } else {
        format!("{}d", secs / 86_400)
    };
    if past {
        format!("{magnitude} ago")
    } else {
        format!("in {magnitude}")
    }
}

fn scope_name(scope: Scope) -> &'static str {
    match scope {
        Scope::RoomRead => "room.read",
        Scope::MessageSend => "message.send",
    }
}

/// One record as the operator sees it. Room ids are locally generated, but they
/// are sanitized anyway: this prints to a terminal, and the cost of not having
/// to re-audit that assumption later is one function call.
fn describe(record: &ControlKeyRecord, now_ms: u64) -> String {
    let status = if record.is_revoked() {
        "REVOKED"
    } else if record.expires_at_ms() <= now_ms {
        "expired"
    } else {
        "active "
    };
    let scopes: Vec<&str> = record.scopes().map(scope_name).collect();

    // Each room id is sanitized, and the *number* shown is capped too: one
    // record with thousands of rooms would otherwise push the rest of the
    // listing out of the operator's scrollback, so they would choose what to
    // revoke from a picture missing the pairing they were looking for.
    const MAX_ROOMS_SHOWN: usize = 8;
    let total_rooms = record.rooms().count();
    let mut rooms: Vec<String> = record
        .rooms()
        .take(MAX_ROOMS_SHOWN)
        .map(sanitize_for_terminal)
        .collect();
    if total_rooms > MAX_ROOMS_SHOWN {
        rooms.push(format!("(+{} more)", total_rooms - MAX_ROOMS_SHOWN));
    }

    // A record's `last_used_ms` starts equal to `created_at_ms`, so rendering
    // it as an age would show a never-connected browser as though it had used
    // its grant — the wrong direction for an operator deciding what is dormant.
    let last_used = if record.last_used_ms() <= record.created_at_ms() {
        "never".to_owned()
    } else {
        humanize(record.last_used_ms(), now_ms)
    };

    format!(
        "  {}  {status}  expires {}\n      paired {}, last used {}\n      scopes: {}\n      rooms : {}",
        pairing_id(&record.key()),
        humanize(record.expires_at_ms(), now_ms),
        humanize(record.created_at_ms(), now_ms),
        last_used,
        if scopes.is_empty() { "(none)".to_owned() } else { scopes.join(", ") },
        if rooms.is_empty() { "(none)".to_owned() } else { rooms.join(", ") },
    )
}

/// `--companion-list-pairings`: show every paired browser control key, so the
/// operator can tell them apart well enough to revoke one.
pub(crate) fn list_pairings(data_dir: &Path) -> Result<(), String> {
    require_profile_dir(data_dir)?;
    let (path, records) = load_store(data_dir)?;
    if records.is_empty() {
        println!("No browser control keys are paired ({}).", path.display());
        return Ok(());
    }
    // The same clock the gateway enforces expiry against.
    let now_ms = ControlGateway::new().now_ms();
    println!(
        "{} paired browser control key(s) in {}:\n",
        records.len(),
        path.display()
    );
    for record in &records {
        println!("{}\n", describe(record, now_ms));
    }
    println!("Revoke one with:  jeliyad --companion-revoke <id>");
    Ok(())
}

/// Which records a `--companion-revoke` argument selects. Pure so the matching
/// rules — minimum length, hex-only, case-insensitive, never-guess-on-ambiguity
/// — are testable without a store on disk.
fn select_by_prefix<'a>(
    records: &'a [ControlKeyRecord],
    prefix: &str,
) -> Result<&'a ControlKeyRecord, String> {
    let prefix = prefix.trim().to_ascii_lowercase();
    if prefix.len() < MIN_PAIRING_ID_PREFIX {
        return Err(format!(
            "the pairing id needs at least {MIN_PAIRING_ID_PREFIX} characters \
             (list them with --companion-list-pairings)"
        ));
    }
    if !prefix.chars().all(|c| c.is_ascii_hexdigit()) {
        // Sanitized, and only here: this branch fires precisely because the
        // argument is NOT hex, so it is the one message that can echo arbitrary
        // operator-supplied bytes. An id pasted from a hostile page could
        // otherwise carry a carriage return and an SGR sequence that overwrite
        // this refusal with a forged "Revoked." line — the operator would
        // believe a compromised browser had been cut off while it kept access.
        // (The two messages below run after this check, so their `prefix` is
        // known to be hex.)
        return Err(format!(
            "'{}' is not a pairing id — ids are hex \
             (list them with --companion-list-pairings)",
            sanitize_for_terminal(&prefix)
        ));
    }
    let matched: Vec<&ControlKeyRecord> = records
        .iter()
        .filter(|record| pairing_id(&record.key()).starts_with(&prefix))
        .collect();
    match matched.as_slice() {
        [record] => Ok(record),
        [] => Err(format!(
            "no paired control key starts with '{prefix}' \
             (list them with --companion-list-pairings)"
        )),
        several => Err(format!(
            "'{prefix}' matches {} paired control keys ({}) — give more of the id",
            several.len(),
            several
                .iter()
                .map(|record| pairing_id(&record.key()))
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

/// `--companion-revoke <id>`: revoke exactly one paired browser control key.
///
/// The record is retained as revoked rather than deleted — the gateway's own
/// semantics, and the safer ones: a deleted record leaves no evidence the key
/// ever existed, while a retained revoked record fails every future admission
/// closed and stays visible in the listing until it expires on its own.
pub(crate) fn revoke_pairing(data_dir: &Path, prefix: &str) -> Result<(), String> {
    require_profile_dir(data_dir)?;
    let (path, records) = load_store(data_dir)?;
    if records.is_empty() {
        return Err(format!(
            "no browser control keys are paired ({})",
            path.display()
        ));
    }
    let now_ms = ControlGateway::new().now_ms();
    let target = select_by_prefix(&records, prefix)?;
    let id = pairing_id(&target.key());
    let key = target.key();

    if target.is_revoked() {
        println!("Pairing {id} was already revoked; nothing to do.");
        return Ok(());
    }
    println!("Revoking this pairing:\n\n{}\n", describe(target, now_ms));

    // Rewrite through a gateway rather than editing the JSON: the store then
    // goes back to disk having passed exactly the validation and expiry
    // clamping the daemon applies when it loads it.
    let contents = std::fs::read_to_string(&path)
        .map_err(|err| format!("could not read {}: {err}", path.display()))?;
    let mut gateway = ControlGateway::new();
    gateway
        .load_persisted(&contents)
        .map_err(|err| format!("corrupt {}: {err:?}", path.display()))?;
    gateway.revoke(&key);
    persist_snapshot(&path, &gateway.snapshot_json())?;
    fsync_dir(data_dir);

    // Read back rather than trusting the write: a revocation the operator
    // believes happened but did not is exactly the failure that matters here.
    let (_, reloaded) = load_store(data_dir)?;
    if !reloaded
        .iter()
        .any(|record| record.key() == key && record.is_revoked())
    {
        return Err(format!(
            "pairing {id} did NOT persist as revoked in {} — the browser may still \
             have access; check the file and retry",
            path.display()
        ));
    }

    info!("companion pairing {id} revoked");
    // "keeps its access", not "is untouched": the rewrite passes every record
    // through the same load the daemon performs, so a hand-edited store's
    // out-of-range expiry is clamped and its scope/room lists are normalized.
    // That changes bytes without changing authority — it makes durable exactly
    // what the daemon was already enforcing — but it is not literally untouched.
    println!(
        "Revoked. That browser must pair again to regain access; every other \
         pairing keeps its access unchanged."
    );
    Ok(())
}

/// Forget all persisted pairings (`--companion-reset-pairings`): remove the key
/// store before the gateway ever loads it. Runs at startup, before any session
/// exists, so no live-session teardown is needed. The parent directory is
/// fsynced so the removal is as durable as every write in this module — a
/// "forgotten" pairing must not resurrect after a power loss.
pub(crate) fn reset_pairings(data_dir: &Path) -> Result<(), String> {
    let path = control_keys_path(data_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => {
            fsync_dir(data_dir);
            info!(
                "companion control: removed {} (all pairings forgotten)",
                path.display()
            );
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("could not remove {}: {err}", path.display())),
    }
}

/// Best-effort fsync of a directory so a just-committed unlink (or rename)
/// reaches the journal. A failure is logged, not fatal: the durability gap it
/// leaves is the same one every non-atomic tool lives with, and the caller has
/// already succeeded logically.
fn fsync_dir(dir: &Path) {
    match std::fs::File::open(dir) {
        Ok(handle) => {
            if let Err(err) = handle.sync_all() {
                warn!("could not fsync {}: {err}", dir.display());
            }
        }
        Err(err) => warn!("could not open {} to fsync: {err}", dir.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use serde_json::Value;
    use tempfile::TempDir;
    use tokio::sync::Notify;

    use jeliya_companion::{serve_connection, DuplexChannel, FrameChannel, PairingOffers};
    use jeliya_control::{Clock, Initiator, KeyPair, ManualClock, RejectReason};
    use jeliya_core::engine::EngineConfig;
    use jeliya_protocol::{method, Msg, SessionKind};

    const NOW: u64 = 1_000;
    const BROWSER_SECRET: [u8; 32] = [5u8; 32];

    fn test_engine(dir: &TempDir) -> Arc<Engine> {
        let (shutdown_tx, _shutdown_rx) = mpsc::channel(4);
        Engine::new(
            dir.path().to_path_buf(),
            true,
            EngineConfig {
                port: 0,
                version: "test".to_owned(),
                shutdown_tx,
            },
        )
        .expect("engine over a temp dir")
    }

    #[test]
    fn companion_kdf_v1_vectors_are_pinned() {
        // The immutability tripwire the module doc promises: a fixed seed maps
        // to a fixed derived secret. Editing either context string or the hash
        // moves these and fails CI — so a companion rekey (which silently
        // bricks every existing browser pairing) can never land unnoticed.
        let seed = [0x22u8; 32];
        assert_eq!(
            hex::encode(blake3::derive_key(COMPANION_IROH_KDF_CONTEXT_V1, &seed)),
            "8c2c208f57568eb1db44990e406d7f01be33f99f419db2e0654ce367012a9d9d"
        );
        assert_eq!(
            hex::encode(blake3::derive_key(COMPANION_NOISE_KDF_CONTEXT_V1, &seed)),
            "dfc657519cbb613a52606b6d9219dd44578701c81cfce8c95a58077002b5fc4b"
        );
    }

    #[test]
    fn companion_secrets_are_deterministic_and_domain_separated() {
        let dir = TempDir::new().expect("tempdir");
        jeliya_core::identity::create(dir.path()).expect("identity");
        let keys = SecretKeys::load(dir.path()).expect("secret keys");

        let iroh_a = derive_companion_secret(&keys, COMPANION_IROH_KDF_CONTEXT_V1);
        let iroh_b = derive_companion_secret(&keys, COMPANION_IROH_KDF_CONTEXT_V1);
        let noise = derive_companion_secret(&keys, COMPANION_NOISE_KDF_CONTEXT_V1);

        // Reproducible from identity.secret alone …
        assert_eq!(*iroh_a, *iroh_b);
        // The wrapper's ikm layout is exactly derive_key(context, device_seed):
        assert_eq!(
            *iroh_a,
            blake3::derive_key(
                COMPANION_IROH_KDF_CONTEXT_V1,
                keys.device.to_seed().as_slice()
            )
        );
        // … while the two contexts separate the secrets from each other, from
        // the raw device seed, and from every room-device signing key.
        assert_ne!(*iroh_a, *noise);
        let device_seed = keys.device.to_seed();
        assert_ne!(*iroh_a, *device_seed);
        assert_ne!(*noise, *device_seed);
        let room_seed = keys.room_device(&[0u8; 32]).to_seed();
        assert_ne!(*iroh_a, *room_seed);
        assert_ne!(*noise, *room_seed);
    }

    #[test]
    fn pairing_refusal_fails_closed_off_terminal_and_supervised() {
        assert!(pairing_refusal(true, true, true).is_some());
        assert!(pairing_refusal(false, false, true).is_some());
        assert!(pairing_refusal(false, true, false).is_some());
        assert!(pairing_refusal(false, true, true).is_none());
    }

    #[test]
    fn typed_code_must_match_the_sas_exactly() {
        assert!(typed_code_confirms("04821-60110\n", "04821-60110"));
        assert!(typed_code_confirms("  04821-60110  ", "04821-60110"));
        assert!(!typed_code_confirms("", "04821-60110"));
        assert!(!typed_code_confirms("\n", "04821-60110"));
        assert!(!typed_code_confirms("04821-60111", "04821-60110"));
        assert!(!typed_code_confirms("0482160110", "04821-60110"));
        assert!(!typed_code_confirms("y", "04821-60110"));
    }

    #[test]
    fn sanitize_strips_terminal_escapes_and_caps_length() {
        // A room name carrying cursor-up + erase-line cannot rewrite the prompt.
        let hostile = "safe\n\x1b[3A\x1b[2K   Scope: read only";
        let clean = sanitize_for_terminal(hostile);
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\n'));
        assert!(clean.contains('\u{fffd}'));
        // Length is bounded.
        let long = "a".repeat(500);
        let capped = sanitize_for_terminal(&long);
        assert!(capped.chars().count() <= 81);
    }

    // ---- Administrative pairing commands -------------------------------

    const HOUR_MS: u64 = 60 * 60 * 1_000;
    const DAY_MS: u64 = 24 * HOUR_MS;

    /// One record in the version-1 on-disk shape. These tests build stores as
    /// the real JSON rather than through constructors (which are `pub(crate)`
    /// to jeliya-control anyway), so they exercise the actual file format the
    /// daemon reads and writes.
    fn record_json(
        key: [u8; 32],
        created_ms: u64,
        expires_ms: u64,
        revoked: bool,
        rooms: &[&str],
    ) -> Value {
        json!({
            "key_hex": hex::encode(key),
            "scopes": [Scope::RoomRead.registry_id(), Scope::MessageSend.registry_id()],
            "rooms": rooms,
            "created_at_ms": created_ms,
            "expires_at_ms": expires_ms,
            "last_used_ms": created_ms,
            "revoked": revoked,
        })
    }

    /// A temp dir that looks like a real Jeliya profile to the admin commands.
    /// `require_profile_dir` only checks that an identity file exists, so a
    /// placeholder is exactly equivalent to a real one here and skips the
    /// keypair generation these tests do not exercise.
    fn profile_dir() -> TempDir {
        let dir = TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join(jeliya_core::identity::SECRET_FILE), b"x")
            .expect("placeholder identity");
        dir
    }

    fn write_store(dir: &TempDir, records: Vec<Value>) -> PathBuf {
        let path = control_keys_path(dir.path());
        std::fs::write(&path, json!({ "version": 1, "keys": records }).to_string())
            .expect("seed the store");
        path
    }

    fn id_of(key: [u8; 32]) -> String {
        pairing_id(&ControlKey::from_bytes(key))
    }

    /// A distinct test key per `n`, so a search can range over far more than
    /// the 256 all-one-byte keys.
    fn key_n(n: u32) -> [u8; 32] {
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(&n.to_le_bytes());
        key
    }

    /// Two distinct keys whose ids share a leading `len`-character prefix.
    /// Found by search rather than hard-coded, so the test keeps working if the
    /// id construction ever legitimately changes.
    fn colliding_pair(len: usize) -> ([u8; 32], [u8; 32]) {
        // Birthday bound for a `len`-hex-digit (4*len bit) space, with generous
        // headroom, so raising MIN_PAIRING_ID_PREFIX does not turn this into a
        // confusing "no collision found" failure that blames the test.
        let bound = (1u64 << (2 * len as u64)) * 32;
        let mut seen: std::collections::HashMap<String, [u8; 32]> =
            std::collections::HashMap::new();
        for n in 0..bound.min(u64::from(u32::MAX)) as u32 {
            let key = key_n(n);
            if let Some(first) = seen.insert(id_of(key)[..len].to_owned(), key) {
                return (first, key);
            }
        }
        panic!("no {len}-character id collision found within {bound} keys");
    }

    /// A store with two live pairings, timestamped against the real clock the
    /// commands read.
    fn two_pairings(dir: &TempDir) -> (u64, PathBuf) {
        let now = ControlGateway::new().now_ms();
        let path = write_store(
            dir,
            vec![
                record_json(
                    [0xa1; 32],
                    now - HOUR_MS,
                    now + 30 * DAY_MS,
                    false,
                    &["room-a"],
                ),
                record_json(
                    [0xb2; 32],
                    now - 2 * HOUR_MS,
                    now + 20 * DAY_MS,
                    false,
                    &["room-b"],
                ),
            ],
        );
        (now, path)
    }

    #[test]
    fn pairing_id_is_a_stable_hex_handle() {
        let id = id_of([0x11; 32]);
        assert_eq!(id.len(), 16, "8 bytes of SHA-256, hex");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        // Pinned against an independently computed SHA-256 of 32 bytes of 0x11
        // (not against whatever this code happens to produce): the operator
        // writes this id down and pastes it back into --companion-revoke, so
        // the construction must not drift silently.
        assert_eq!(id, "02d449a31fbb267c");
        assert_eq!(id, id_of([0x11; 32]), "deterministic");
        assert_ne!(id, id_of([0x12; 32]), "distinct keys, distinct ids");
    }

    #[test]
    fn humanize_reads_forward_and_backward() {
        let now = 10 * DAY_MS;
        assert_eq!(humanize(now, now), "in 0s");
        assert_eq!(humanize(now + 90_000, now), "in 1m");
        assert_eq!(humanize(now + 30 * DAY_MS, now), "in 30d");
        assert_eq!(humanize(now - 5 * HOUR_MS, now), "5h ago");
        assert_eq!(humanize(now - 2 * DAY_MS, now), "2d ago");

        // Each unit boundary, so a rounding change cannot silently reshape how
        // long an operator thinks a grant has left.
        assert_eq!(humanize(now - 59_000, now), "59s ago");
        assert_eq!(humanize(now - 60_000, now), "1m ago");
        assert_eq!(humanize(now - (3_600_000 - 1), now), "59m ago");
        assert_eq!(humanize(now - 3_600_000, now), "1h ago");
        assert_eq!(humanize(now - (DAY_MS - 1), now), "23h ago");
        assert_eq!(humanize(now - DAY_MS, now), "1d ago");
    }

    #[test]
    fn select_by_prefix_never_guesses() {
        let dir = profile_dir();
        let (_now, _path) = two_pairings(&dir);
        let (_, records) = load_store(dir.path()).expect("store loads");
        let a = id_of([0xa1; 32]);

        // A full id, and any sufficiently long unique prefix, select it.
        assert_eq!(
            select_by_prefix(&records, &a).expect("full id").key(),
            ControlKey::from_bytes([0xa1; 32])
        );
        assert_eq!(
            select_by_prefix(&records, &a[..8])
                .expect("unique prefix")
                .key(),
            ControlKey::from_bytes([0xa1; 32])
        );
        // Ids are hex; the operator's case must not matter.
        assert!(select_by_prefix(&records, &a.to_uppercase()).is_ok());
        assert!(select_by_prefix(&records, &format!("  {a}  ")).is_ok());

        // The length boundary, both sides: one character below the minimum is
        // refused even though it matches exactly one key, and exactly the
        // minimum is accepted. (The two seeded ids differ in their first
        // character, so a 4-character prefix really is unique here.)
        let err = select_by_prefix(&records, &a[..MIN_PAIRING_ID_PREFIX - 1])
            .expect_err("one short of the minimum");
        assert!(err.contains("at least"), "actionable, got: {err}");
        assert_eq!(
            select_by_prefix(&records, &a[..MIN_PAIRING_ID_PREFIX])
                .expect("exactly the minimum is enough")
                .key(),
            ControlKey::from_bytes([0xa1; 32])
        );
        // An empty argument must never resolve to "the only key there is".
        assert!(select_by_prefix(&records, "").is_err());
        // Not an id at all.
        assert!(select_by_prefix(&records, "zzzz").is_err());
        // No match, and ambiguity, are both refusals rather than guesses.
        assert!(select_by_prefix(&records, "0123456789abcdef").is_err());
        let ambiguous = select_by_prefix(&[], "abcd");
        assert!(ambiguous.is_err(), "an empty store matches nothing");
    }

    #[test]
    fn an_ambiguous_prefix_refuses_and_names_the_candidates() {
        // The property that matters: when a prefix that IS long enough still
        // matches more than one pairing, the command must refuse and show the
        // operator both ids — never silently revoke whichever came first.
        let (first, second) = colliding_pair(MIN_PAIRING_ID_PREFIX);
        let dir = profile_dir();
        let now = ControlGateway::new().now_ms();
        write_store(
            &dir,
            vec![
                record_json(first, now - HOUR_MS, now + DAY_MS, false, &["room-a"]),
                record_json(second, now - HOUR_MS, now + DAY_MS, false, &["room-b"]),
            ],
        );
        let (_, records) = load_store(dir.path()).expect("store loads");

        let shared = &id_of(first)[..MIN_PAIRING_ID_PREFIX];
        let err = select_by_prefix(&records, shared).expect_err("ambiguous prefix refuses");
        assert!(
            err.contains(&id_of(first)) && err.contains(&id_of(second)),
            "both candidates are named so the operator can disambiguate: {err}"
        );

        // …and the full ids still each select exactly one.
        assert_eq!(
            select_by_prefix(&records, &id_of(first))
                .expect("first")
                .key(),
            ControlKey::from_bytes(first)
        );
        assert_eq!(
            select_by_prefix(&records, &id_of(second))
                .expect("second")
                .key(),
            ControlKey::from_bytes(second)
        );

        // And revoking through the ambiguous prefix leaves the store alone.
        let before = std::fs::read_to_string(control_keys_path(dir.path())).expect("read");
        assert!(revoke_pairing(dir.path(), shared).is_err());
        let after = std::fs::read_to_string(control_keys_path(dir.path())).expect("read");
        assert_eq!(before, after, "an ambiguous revoke must change nothing");
    }

    #[test]
    fn list_pairings_on_an_empty_store_is_not_an_error() {
        let dir = profile_dir();
        // No file at all: nobody has ever paired.
        list_pairings(dir.path()).expect("an empty store lists cleanly");
        // An explicitly empty store is the same.
        write_store(&dir, vec![]);
        list_pairings(dir.path()).expect("an empty store lists cleanly");
        // But there is nothing to revoke.
        assert!(revoke_pairing(dir.path(), "abcd").is_err());
    }

    #[test]
    fn a_corrupt_store_refuses_instead_of_reading_as_empty() {
        // The failure that matters: a tampered or truncated store must not
        // present as "no pairings" — which would tell the operator there is
        // nothing to revoke while the daemon itself refuses to start on it.
        let dir = profile_dir();
        std::fs::write(control_keys_path(dir.path()), "{not json").expect("seed");
        let err = list_pairings(dir.path()).expect_err("corrupt store refuses");
        assert!(err.contains("corrupt"), "actionable, got: {err}");
        assert!(revoke_pairing(dir.path(), "abcd").is_err());
    }

    #[test]
    fn revoke_marks_exactly_one_key_and_leaves_the_rest_intact() {
        let dir = profile_dir();
        let (_now, path) = two_pairings(&dir);
        let (_, before) = load_store(dir.path()).expect("store loads");
        let untouched = before
            .iter()
            .find(|r| r.key() == ControlKey::from_bytes([0xb2; 32]))
            .expect("the second pairing");
        let (b_created, b_expires, b_rooms) = (
            untouched.created_at_ms(),
            untouched.expires_at_ms(),
            untouched.rooms().map(str::to_owned).collect::<Vec<_>>(),
        );

        revoke_pairing(dir.path(), &id_of([0xa1; 32])).expect("revokes the first pairing");

        let (_, after) = load_store(dir.path()).expect("store reloads");
        assert_eq!(after.len(), 2, "the record is retained, not deleted");
        let revoked = after
            .iter()
            .find(|r| r.key() == ControlKey::from_bytes([0xa1; 32]))
            .expect("the revoked record survives as a record");
        assert!(revoked.is_revoked());
        // The other pairing keeps its access and every field: rewriting the
        // store through a gateway must not quietly lose or reshape a grant.
        let other = after
            .iter()
            .find(|r| r.key() == ControlKey::from_bytes([0xb2; 32]))
            .expect("the second pairing survives");
        assert!(!other.is_revoked(), "revocation is per key, not per store");
        assert_eq!(other.created_at_ms(), b_created);
        assert_eq!(other.expires_at_ms(), b_expires);
        assert_eq!(
            other.rooms().map(str::to_owned).collect::<Vec<_>>(),
            b_rooms
        );
        assert_eq!(other.scopes().count(), 2);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the rewritten store stays owner-only");
        }
    }

    #[test]
    fn revoking_an_already_revoked_pairing_succeeds_without_churn() {
        let dir = profile_dir();
        two_pairings(&dir);
        revoke_pairing(dir.path(), &id_of([0xa1; 32])).expect("first revoke");
        let after_first = std::fs::read_to_string(control_keys_path(dir.path())).expect("read");
        revoke_pairing(dir.path(), &id_of([0xa1; 32])).expect("second revoke still succeeds");
        let after_second = std::fs::read_to_string(control_keys_path(dir.path())).expect("read");
        assert_eq!(after_first, after_second, "no churn");
        // And it is still revoked afterwards — a second call must not undo it.
        let (_, records) = load_store(dir.path()).expect("store loads");
        assert!(records
            .iter()
            .any(|r| r.key() == ControlKey::from_bytes([0xa1; 32]) && r.is_revoked()));
    }

    #[test]
    fn a_revoked_key_is_actually_denied_admission_after_reload() {
        // The listing says "REVOKED" and the message says the browser must pair
        // again. This asserts the property those claims rest on, through the
        // gateway the daemon really admits with — not just the stored flag.
        let dir = profile_dir();
        two_pairings(&dir);
        revoke_pairing(dir.path(), &id_of([0xa1; 32])).expect("revoke");

        let contents = std::fs::read_to_string(control_keys_path(dir.path())).expect("read");
        let mut gateway = ControlGateway::new();
        gateway.load_persisted(&contents).expect("daemon reload");
        assert!(matches!(
            gateway.admit_session(&ControlKey::from_bytes([0xa1; 32])),
            Err(RejectReason::Revoked)
        ));
        // …and the untouched pairing is still admitted.
        assert!(gateway
            .admit_session(&ControlKey::from_bytes([0xb2; 32]))
            .is_ok());
    }

    #[test]
    fn revoking_one_key_preserves_expired_and_clamped_records() {
        // The rewrite passes the whole store through a fresh gateway. Two ways
        // that could quietly go wrong: an `evict_expired()` slipped in before
        // the snapshot would silently delete every expired record (and with it
        // the evidence of a grant that existed), and a clamped expiry could
        // drift on each rewrite. Neither is allowed.
        let dir = profile_dir();
        let now = ControlGateway::new().now_ms();
        write_store(
            &dir,
            vec![
                record_json([0xa1; 32], now - HOUR_MS, now + DAY_MS, false, &["room-a"]),
                // Long expired, not yet evicted.
                record_json(
                    [0xb2; 32],
                    now - 90 * DAY_MS,
                    now - 30 * DAY_MS,
                    false,
                    &["room-b"],
                ),
                // A hand-edited near-infinite expiry, clamped on every load.
                record_json([0xc3; 32], now - HOUR_MS, u64::MAX, false, &["room-c"]),
            ],
        );
        let (_, before) = load_store(dir.path()).expect("store loads");
        let expiry_of = |records: &[ControlKeyRecord], key: [u8; 32]| {
            records
                .iter()
                .find(|r| r.key() == ControlKey::from_bytes(key))
                .map(ControlKeyRecord::expires_at_ms)
        };
        let clamped_before = expiry_of(&before, [0xc3; 32]).expect("clamped record");

        revoke_pairing(dir.path(), &id_of([0xa1; 32])).expect("revoke");

        let (_, after) = load_store(dir.path()).expect("store reloads");
        assert_eq!(after.len(), 3, "no record is dropped by a revoke");
        assert!(
            expiry_of(&after, [0xb2; 32]).is_some(),
            "an expired record survives a revoke; eviction is the daemon's job"
        );
        assert_eq!(
            expiry_of(&after, [0xc3; 32]),
            Some(clamped_before),
            "the clamp is stable — it does not drift on each rewrite"
        );
    }

    #[test]
    fn a_key_recorded_twice_collapses_to_what_the_daemon_enforces() {
        // A store that somehow carries one key twice (a hand edit, a merged
        // backup) must not make that pairing unrevokable: both rows render the
        // same id, so every prefix — including the full id — would be
        // "ambiguous" with no more id to give. The daemon's own load is
        // last-wins, so the listing shows that same last record and the revoke
        // targets it.
        let dir = profile_dir();
        let now = ControlGateway::new().now_ms();
        write_store(
            &dir,
            vec![
                record_json([0xf6; 32], now - 2 * HOUR_MS, now + DAY_MS, true, &["old"]),
                record_json([0xf6; 32], now - HOUR_MS, now + 5 * DAY_MS, false, &["new"]),
            ],
        );
        let (_, records) = load_store(dir.path()).expect("store loads");
        assert_eq!(records.len(), 1, "one key, one row");
        assert!(
            !records[0].is_revoked(),
            "the listing shows the LAST record — the one the daemon admits"
        );
        assert_eq!(records[0].rooms().collect::<Vec<_>>(), vec!["new"]);

        // And it can actually be revoked.
        revoke_pairing(dir.path(), &id_of([0xf6; 32])).expect("the duplicate is revokable");
        let contents = std::fs::read_to_string(control_keys_path(dir.path())).expect("read");
        let mut gateway = ControlGateway::new();
        gateway.load_persisted(&contents).expect("daemon reload");
        assert!(matches!(
            gateway.admit_session(&ControlKey::from_bytes([0xf6; 32])),
            Err(RejectReason::Revoked)
        ));
    }

    #[test]
    fn a_directory_that_is_not_a_profile_is_refused_not_reported_empty() {
        // The fail-open that matters: a mistyped or defaulted --data-dir is
        // created by `main` before these commands run, so answering "no
        // pairings, exit 0" would tell an operator auditing after a lost device
        // that they are safe while the real profile's grant stays live.
        let dir = TempDir::new().expect("tempdir");
        let err = list_pairings(dir.path()).expect_err("not a profile");
        assert!(err.contains("--data-dir"), "points at the cause: {err}");
        assert!(revoke_pairing(dir.path(), "abcd").is_err());

        // With an identity present, an empty store is a legitimate answer.
        std::fs::write(dir.path().join(jeliya_core::identity::SECRET_FILE), b"x")
            .expect("identity");
        list_pairings(dir.path()).expect("a real profile with no pairings lists cleanly");
    }

    #[test]
    fn revoke_refuses_an_unknown_id_without_touching_the_store() {
        let dir = profile_dir();
        two_pairings(&dir);
        let before = std::fs::read_to_string(control_keys_path(dir.path())).expect("read");
        assert!(revoke_pairing(dir.path(), "0123456789abcdef").is_err());
        assert!(revoke_pairing(dir.path(), "ab").is_err());
        let after = std::fs::read_to_string(control_keys_path(dir.path())).expect("read");
        assert_eq!(before, after, "a refused revoke changes nothing");
    }

    #[test]
    fn describe_sanitizes_what_it_prints() {
        // Room ids are locally generated, but the listing is a terminal
        // surface: a store carrying an escape sequence must not be able to
        // rewrite the status the operator is reading before revoking.
        let dir = profile_dir();
        let now = ControlGateway::new().now_ms();
        write_store(
            &dir,
            vec![record_json(
                [0xc3; 32],
                now - HOUR_MS,
                now + DAY_MS,
                false,
                &["room\n\x1b[2Kactive"],
            )],
        );
        let (_, records) = load_store(dir.path()).expect("store loads");
        let line = describe(&records[0], now);

        assert!(
            !line.contains('\x1b'),
            "no escape sequences reach the terminal"
        );
        // The record's own layout is exactly four lines; a room id carrying a
        // newline must not be able to add a fifth that reads like a real row.
        assert_eq!(
            line.lines().count(),
            4,
            "the hostile room id cannot add a line: {line:?}"
        );
        // The status is read positionally, so the word "active" appearing
        // inside the hostile room id cannot stand in for the real status field
        // — which is the whole point of the spoofing attempt.
        assert!(
            line.starts_with(&format!("  {}  active ", id_of([0xc3; 32]))),
            "id then status, in fixed positions: {line:?}"
        );
    }

    #[test]
    fn sanitize_neutralizes_bidi_and_zero_width_characters() {
        // `char::is_control` is Cc-only, so these Unicode `Cf` characters pass
        // it while still reordering or hiding the text around them. A room name
        // is remote-chosen (the creator's signed `room.created` field) and is
        // printed on the pairing-confirmation surface, so an override there
        // could visually rewrite the scope the operator is approving.
        // One representative from every range `steers_display` enumerates, so
        // dropping a range from that list fails here rather than in the field.
        for hostile in [
            '\u{00ad}',  // SOFT HYPHEN
            '\u{0600}',  // ARABIC NUMBER SIGN
            '\u{061c}',  // ARABIC LETTER MARK
            '\u{06dd}',  // ARABIC END OF AYAH
            '\u{070f}',  // SYRIAC ABBREVIATION MARK
            '\u{0890}',  // ARABIC POUND MARK ABOVE
            '\u{08e2}',  // ARABIC DISPUTED END OF AYAH
            '\u{180e}',  // MONGOLIAN VOWEL SEPARATOR
            '\u{200b}',  // ZERO WIDTH SPACE
            '\u{200f}',  // RIGHT-TO-LEFT MARK
            '\u{2028}',  // LINE SEPARATOR (Zl, not Cc)
            '\u{2029}',  // PARAGRAPH SEPARATOR (Zp, not Cc)
            '\u{202e}',  // RIGHT-TO-LEFT OVERRIDE
            '\u{2060}',  // WORD JOINER
            '\u{2066}',  // LEFT-TO-RIGHT ISOLATE
            '\u{206f}',  // NOMINAL DIGIT SHAPES (deprecated format)
            '\u{feff}',  // ZWNBSP / BOM
            '\u{fff9}',  // INTERLINEAR ANNOTATION ANCHOR
            '\u{110bd}', // KAITHI NUMBER SIGN
            '\u{13430}', // Egyptian hieroglyph format control
            '\u{1bca0}', // SHORTHAND FORMAT LETTER OVERLAP
            '\u{1d173}', // MUSICAL SYMBOL BEGIN BEAM
            '\u{e0001}', // LANGUAGE TAG
            '\u{e0041}', // TAG LATIN CAPITAL LETTER A — invisible ASCII
        ] {
            assert!(
                steers_display(hostile),
                "U+{:04X} must be classified as display-steering",
                hostile as u32
            );
            let clean = sanitize_for_terminal(&format!("room{hostile}name"));
            assert!(
                clean.contains('\u{fffd}') && !clean.chars().any(steers_display),
                "U+{:04X} must be neutralized, got {clean:?}",
                hostile as u32
            );
        }

        // The whole-string cases the listing and the pairing prompt actually
        // face.
        for hostile in [
            "\u{202e}desrever",
            "\u{2066}isolated\u{2069}",
            "line\u{2028}separated",
            "tagged\u{e0020}\u{e0073}\u{e0065}\u{e0063}\u{e0072}\u{e0065}\u{e0074}",
        ] {
            let clean = sanitize_for_terminal(hostile);
            assert!(
                clean.contains('\u{fffd}'),
                "{hostile:?} must be neutralized, got {clean:?}"
            );
            assert!(!clean.chars().any(steers_display));
        }

        // Legitimate international text is untouched — this must not become an
        // ASCII-only filter that mangles the room names it is meant to display.
        // Bambara, French, Arabic, Chinese, and an emoji with a skin-tone
        // modifier (a Sk modifier, not a format character).
        for benign in [
            "Salon café — Kɔrɔ",
            "غرفة العائلة",
            "家族の部屋",
            "team 👋🏽 standup",
        ] {
            assert_eq!(
                sanitize_for_terminal(benign),
                benign,
                "{benign:?} is legitimate"
            );
        }
    }

    #[test]
    fn describe_caps_the_number_of_rooms_it_prints() {
        // One record must not be able to flood the listing and push the pairing
        // the operator is hunting for out of their scrollback.
        let dir = profile_dir();
        let now = ControlGateway::new().now_ms();
        let many: Vec<String> = (0..50).map(|i| format!("room-{i:03}")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        write_store(
            &dir,
            vec![record_json(
                [0xd4; 32],
                now - HOUR_MS,
                now + DAY_MS,
                false,
                &many,
            )],
        );
        let (_, records) = load_store(dir.path()).expect("store loads");
        let line = describe(&records[0], now);
        assert_eq!(line.lines().count(), 4, "still one record, four lines");
        assert!(
            line.contains("(+42 more)"),
            "the remainder is named: {line}"
        );
        assert!(line.len() < 600, "bounded output, got {} bytes", line.len());
    }

    #[test]
    fn a_never_used_grant_does_not_read_as_used() {
        // `last_used_ms` starts equal to `created_at_ms`, so rendering it as an
        // age would show a browser that never connected as having exercised its
        // grant — the wrong direction for deciding what is dormant.
        let dir = profile_dir();
        let now = ControlGateway::new().now_ms();
        write_store(
            &dir,
            vec![record_json(
                [0xe5; 32],
                now - 5 * DAY_MS,
                now + DAY_MS,
                false,
                &["r"],
            )],
        );
        let (_, records) = load_store(dir.path()).expect("store loads");
        let line = describe(&records[0], now);
        assert!(
            line.contains("paired 5d ago, last used never"),
            "got: {line}"
        );
    }

    #[test]
    fn describe_distinguishes_active_expired_and_revoked() {
        let now = 100 * DAY_MS;
        let dir = profile_dir();
        write_store(
            &dir,
            vec![
                record_json([0x01; 32], now - DAY_MS, now + DAY_MS, false, &["r"]),
                record_json([0x02; 32], now - 10 * DAY_MS, now - DAY_MS, false, &["r"]),
                record_json([0x03; 32], now - DAY_MS, now + DAY_MS, true, &["r"]),
            ],
        );
        let (_, records) = load_store(dir.path()).expect("store loads");
        let rendered: Vec<String> = records.iter().map(|r| describe(r, now)).collect();
        let find = |key: [u8; 32]| {
            rendered
                .iter()
                .find(|line| line.contains(&id_of(key)))
                .expect("rendered")
        };
        assert!(find([0x01; 32]).contains("active"));
        assert!(find([0x02; 32]).contains("expired"));
        assert!(find([0x03; 32]).contains("REVOKED"));
    }

    #[test]
    fn reset_pairings_is_idempotent() {
        let dir = TempDir::new().expect("tempdir");
        reset_pairings(dir.path()).expect("no file is fine");
        std::fs::write(control_keys_path(dir.path()), "{}").expect("seed file");
        reset_pairings(dir.path()).expect("removes the file");
        assert!(!control_keys_path(dir.path()).exists());
    }

    #[tokio::test]
    async fn spawn_refuses_without_an_identity() {
        let dir = TempDir::new().expect("tempdir");
        let engine = test_engine(&dir);
        let err = spawn(CompanionOptions {
            data_dir: dir.path().to_path_buf(),
            engine,
            pair: false,
            supervised: false,
        })
        .await
        .err()
        .expect("no identity, no companion");
        assert!(err.contains("identity"), "actionable message, got: {err}");
    }

    #[tokio::test]
    async fn engine_dispatch_maps_the_three_wire_methods_and_hides_paths() {
        let dir = TempDir::new().expect("tempdir");
        let engine = test_engine(&dir);
        engine
            .dispatch("identity.create", json!({}))
            .await
            .expect("identity.create");
        let created = engine
            .dispatch("room.create", json!({ "name": "control" }))
            .await
            .expect("room.create");
        let room_id = created["room_id"].as_str().expect("room_id").to_owned();
        engine
            .dispatch("room.open", json!({ "room_id": room_id }))
            .await
            .expect("room.open");

        let dispatch = EngineDispatch {
            engine: engine.clone(),
        };

        let sent = dispatch
            .dispatch(MethodCall::MessageSend {
                room_id: room_id.clone(),
                body: "hello from the wire".to_owned(),
                client_msg_id: "c1".to_owned(),
            })
            .await
            .expect("scoped send");
        let sent: Value = serde_json::from_slice(&sent).expect("result is JSON");
        assert!(sent["event_id"].is_string());

        let timeline = dispatch
            .dispatch(MethodCall::RoomTimeline {
                room_id: room_id.clone(),
                limit: Some(10),
                after: None,
            })
            .await
            .expect("timeline");
        let timeline: Value = serde_json::from_slice(&timeline).expect("result is JSON");
        assert!(timeline["events"]
            .as_array()
            .expect("events")
            .iter()
            .any(|event| event["body"] == json!("hello from the wire")));

        let members = dispatch
            .dispatch(MethodCall::RoomMembers {
                room_id: room_id.clone(),
            })
            .await
            .expect("members");
        let members: Value = serde_json::from_slice(&members).expect("result is JSON");
        assert!(!members["members"].as_array().expect("members").is_empty());

        // An unknown room surfaces only the stable error code — never a path or
        // the free-text message.
        let denied = dispatch
            .dispatch(MethodCall::RoomMembers {
                room_id: "not-a-room".to_owned(),
            })
            .await
            .expect_err("unknown room denied");
        assert!(!denied.contains('/'), "no filesystem path leaks: {denied}");
        assert!(!denied.contains(' '), "code only, got: {denied}");

        // The unbounded cursor form is withheld at the companion boundary — it
        // never reaches the engine's whole-tail materialization.
        let cursor = dispatch
            .dispatch(MethodCall::RoomTimeline {
                room_id: room_id.clone(),
                limit: Some(10),
                after: Some("some-event-id".to_owned()),
            })
            .await
            .expect_err("cursor form withheld");
        assert_eq!(cursor, "unsupported");
    }

    #[tokio::test]
    async fn pairing_grant_covers_only_open_rooms() {
        let dir = TempDir::new().expect("tempdir");
        let engine = test_engine(&dir);
        engine
            .dispatch("identity.create", json!({}))
            .await
            .expect("identity.create");
        let open = engine
            .dispatch("room.create", json!({ "name": "open-room" }))
            .await
            .expect("room.create open");
        let open_id = open["room_id"].as_str().expect("room_id").to_owned();
        let closed = engine
            .dispatch("room.create", json!({ "name": "closed-room" }))
            .await
            .expect("room.create closed");
        let closed_id = closed["room_id"].as_str().expect("room_id").to_owned();
        // Open only the first room; the second stays closed.
        engine
            .dispatch("room.open", json!({ "room_id": open_id }))
            .await
            .expect("room.open");

        let policy = TtyPolicy {
            engine,
            supervised: false,
            lines: None,
        };
        let rooms = policy.current_rooms().await;
        let ids: BTreeSet<String> = rooms.into_iter().map(|(id, _)| id).collect();
        assert!(ids.contains(&open_id), "the open room is grantable");
        assert!(
            !ids.contains(&closed_id),
            "a closed room must never be silently granted at pairing"
        );
    }

    #[test]
    fn structural_records_parses_empty_and_fails_safe() {
        let clock = Arc::new(ManualClock::new(NOW));
        let empty = ControlGateway::with_clock(Box::new(clock)).snapshot_json();
        assert!(structural_records(&empty).is_empty());
        // An unparseable snapshot yields an empty map, so install_since never
        // reads a corrupt read as an install.
        assert!(structural_records("garbage").is_empty());
    }

    #[test]
    fn install_since_counts_installs_not_evictions_or_churn() {
        use std::collections::BTreeMap;
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let a: BTreeMap<[u8; 32], String> = [(k1, "grant-a".to_owned())].into_iter().collect();
        let empty: BTreeMap<[u8; 32], String> = BTreeMap::new();

        // A first pairing (a key appears) is an install.
        assert!(install_since(&empty, &a));
        // No change is not.
        assert!(!install_since(&a, &a));
        // A re-pair (same key, changed authority projection) IS an install.
        let a2: BTreeMap<[u8; 32], String> = [(k1, "grant-b".to_owned())].into_iter().collect();
        assert!(install_since(&a, &a2));
        // A second key installed alongside the first is an install.
        let a_plus: BTreeMap<[u8; 32], String> =
            [(k1, "grant-a".to_owned()), (k2, "grant-c".to_owned())]
                .into_iter()
                .collect();
        assert!(install_since(&a, &a_plus));
        // The regression: a background eviction (a key disappears) is NOT an
        // install — the pairing loop must not read housekeeping as success.
        assert!(!install_since(&a, &empty));
    }

    /// A test policy standing in for the terminal: approves with the exact
    /// grant shape the TTY policy issues.
    struct ApproveRooms {
        rooms: BTreeSet<String>,
    }
    impl ControlPolicy for ApproveRooms {
        fn confirm_pairing(&self, _sas: &str) -> BoxFuture<'_, PairingDecision> {
            let rooms = self.rooms.clone();
            Box::pin(async move {
                PairingDecision::Approve {
                    scopes: [Scope::RoomRead, Scope::MessageSend].into_iter().collect(),
                    rooms,
                    lifetime: DEFAULT_LIFETIME,
                }
            })
        }
    }

    struct RejectAll;
    impl ControlPolicy for RejectAll {
        fn confirm_pairing(&self, _sas: &str) -> BoxFuture<'_, PairingDecision> {
            Box::pin(async move { PairingDecision::Reject })
        }
    }

    fn test_clock(clock: &Arc<ManualClock>) -> Arc<dyn Clock> {
        Arc::new(clock.clone())
    }

    async fn handshake(
        browser: &mut DuplexChannel<tokio::io::DuplexStream>,
        init: &mut Initiator,
        client_hello: jeliya_protocol::Frame,
    ) {
        browser
            .write_frame(client_hello)
            .await
            .expect("client hello");
        let sh = browser.read_frame().await.expect("server hello");
        let h1 = init.on_server_hello(&sh).expect("handshake1");
        browser.write_frame(h1).await.expect("handshake1 out");
        let h2 = browser.read_frame().await.expect("handshake2");
        let h3 = init.on_handshake2(&h2).expect("handshake3");
        browser.write_frame(h3).await.expect("handshake3 out");
    }

    /// The whole daemon-side stack end to end: pair with the derived companion
    /// identity, persist the grant through the single writer, reload it into a
    /// fresh gateway (a daemon restart), then drive the real engine over a
    /// scoped control session — including the per-room denial for a room outside
    /// the grant, which the engine itself would have served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pairing_persistence_and_scoped_control_drive_the_real_engine() {
        let dir = TempDir::new().expect("tempdir");
        let engine = test_engine(&dir);
        engine
            .dispatch("identity.create", json!({}))
            .await
            .expect("identity.create");
        let granted = engine
            .dispatch("room.create", json!({ "name": "granted" }))
            .await
            .expect("room.create granted");
        let granted_id = granted["room_id"].as_str().expect("room_id").to_owned();
        let outside = engine
            .dispatch("room.create", json!({ "name": "outside" }))
            .await
            .expect("room.create outside");
        let outside_id = outside["room_id"].as_str().expect("room_id").to_owned();
        engine
            .dispatch("room.open", json!({ "room_id": granted_id }))
            .await
            .expect("room.open");

        let keys = SecretKeys::load(dir.path()).expect("secret keys");
        let noise_secret = derive_companion_secret(&keys, COMPANION_NOISE_KDF_CONTEXT_V1);
        let companion_public = KeyPair::from_secret(Zeroizing::new(*noise_secret)).public();

        let clock = Arc::new(ManualClock::new(NOW));
        let gateway = Arc::new(Mutex::new(ControlGateway::with_clock(Box::new(
            clock.clone(),
        ))));
        let offers = Arc::new(Mutex::new(PairingOffers::new()));
        let nonce = offers.lock().await.open(NOW).expect("offer").nonce;
        let dispatch = Arc::new(EngineDispatch {
            engine: engine.clone(),
        });

        // The single writer starts on the empty store (as in production, before
        // any pairing), so the install below is a real change it will flush.
        let path = control_keys_path(dir.path());
        let persister = Persister::start(gateway.clone(), path.clone());

        // ---- Pairing ceremony over an in-memory duplex --------------------
        let (c_io, b_io) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn(serve_connection(
            DuplexChannel::new(c_io),
            KeyPair::from_secret(Zeroizing::new(*noise_secret)),
            1,
            offers,
            test_clock(&clock),
            gateway.clone(),
            dispatch.clone() as Arc<dyn ControlDispatch>,
            Arc::new(ApproveRooms {
                rooms: [granted_id.clone()].into_iter().collect(),
            }) as Arc<dyn ControlPolicy>,
            Arc::new(Notify::new()),
        ));
        let mut browser = DuplexChannel::new(b_io);
        let (mut init, ch) = Initiator::new(
            KeyPair::from_secret(Zeroizing::new(BROWSER_SECRET)),
            SessionKind::Pairing,
            nonce,
            None,
        );
        handshake(&mut browser, &mut init, ch).await;
        let pc = init.pair_confirm().expect("pair confirm");
        browser.write_frame(pc).await.expect("pair confirm out");
        let pr = browser.read_frame().await.expect("pair result");
        match init.read(&pr).expect("pair result decodes") {
            Msg::PairResult { installed, .. } => assert!(installed, "the grant installs"),
            other => panic!("expected PairResult, got {other:?}"),
        }
        drop(browser);
        served.await.expect("companion task");

        // ---- Persist through the single writer, then reload (a restart) ---
        flush_now(&persister.tx).await.expect("durable flush");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "control_keys.json must stay owner-only");
        }
        let snapshot = std::fs::read_to_string(&path).expect("read back");
        let structural_before = structural_records(&snapshot);
        let mut reloaded = ControlGateway::with_clock(Box::new(clock.clone()));
        let count = reloaded.load_persisted(&snapshot).expect("load persisted");
        assert_eq!(count, 1, "the pairing survives a restart");
        let reloaded = Arc::new(Mutex::new(reloaded));
        let reloaded_probe = reloaded.clone();

        // ---- A scoped control session against the reloaded gateway --------
        let (c_io, b_io) = tokio::io::duplex(64 * 1024);
        let served = tokio::spawn(serve_connection(
            DuplexChannel::new(c_io),
            KeyPair::from_secret(Zeroizing::new(*noise_secret)),
            2,
            Arc::new(Mutex::new(PairingOffers::new())),
            test_clock(&clock),
            reloaded,
            dispatch as Arc<dyn ControlDispatch>,
            Arc::new(RejectAll) as Arc<dyn ControlPolicy>,
            Arc::new(Notify::new()),
        ));
        let mut browser = DuplexChannel::new(b_io);
        let (mut init, ch) = Initiator::new(
            KeyPair::from_secret(Zeroizing::new(BROWSER_SECRET)),
            SessionKind::Control,
            [0u8; 16],
            Some(companion_public),
        );
        handshake(&mut browser, &mut init, ch).await;
        match init
            .read(&browser.read_frame().await.expect("session verdict"))
            .expect("verdict decodes")
        {
            Msg::SessionAccept { .. } => {}
            other => panic!("expected SessionAccept, got {other:?}"),
        }

        let req = init
            .request(
                method::MESSAGE_SEND,
                &MethodCall::MessageSend {
                    room_id: granted_id.clone(),
                    body: "over the control wire".to_owned(),
                    client_msg_id: "wire-1".to_owned(),
                },
            )
            .expect("request");
        browser.write_frame(req).await.expect("request out");
        match init
            .read(&browser.read_frame().await.expect("response"))
            .expect("response decodes")
        {
            Msg::Response { ok, body, .. } => {
                assert!(ok, "the granted room's send is authorized");
                let value: Value = serde_json::from_slice(&body).expect("engine JSON");
                assert!(value["event_id"].is_string());
            }
            other => panic!("expected Response, got {other:?}"),
        }

        let req = init
            .request(
                method::ROOM_MEMBERS,
                &MethodCall::RoomMembers {
                    room_id: outside_id.clone(),
                },
            )
            .expect("request");
        browser.write_frame(req).await.expect("request out");
        match init
            .read(&browser.read_frame().await.expect("response"))
            .expect("response decodes")
        {
            Msg::Response { ok, .. } => assert!(!ok, "room outside the grant is denied"),
            other => panic!("expected Response, got {other:?}"),
        }
        drop(browser);
        served.await.expect("companion task");

        // The authorized RPCs bumped last_used_ms (the raw snapshot moved), but
        // the structural projection — what the pair loop watches for success —
        // is invariant under a pure last-used bump, so an active session is
        // never mistaken for a pairing install.
        let after_snapshot = reloaded_probe.lock().await.snapshot_json();
        let after_records = structural_records(&after_snapshot);
        assert_eq!(
            after_records, structural_before,
            "last-used churn must not read as a structural change"
        );
        assert!(
            !install_since(&structural_before, &after_records),
            "an active session's last-used bump is not a pairing install"
        );

        let timeline = engine
            .dispatch(
                "room.timeline",
                json!({ "room_id": granted_id, "limit": 10 }),
            )
            .await
            .expect("engine timeline");
        assert!(timeline["events"]
            .as_array()
            .expect("events")
            .iter()
            .any(|event| event["body"] == json!("over the control wire")));
    }
}
