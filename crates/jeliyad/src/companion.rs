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

use jeliya_companion::{
    BoxFuture, ControlDispatch, ControlEndpoint, ControlPolicy, PairingDecision, RelayConfig,
    OFFER_TTL_MS,
};
use jeliya_control::{load_records, ControlGateway, Scope, DEFAULT_LIFETIME};
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
    let device_seed = keys.device.to_seed();
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
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .take(MAX)
        .collect();
    if s.chars().count() > MAX {
        out.push('…');
    }
    out
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
                MethodCall::RoomTimeline {
                    room_id,
                    limit,
                    after,
                } => (
                    "room.timeline",
                    json!({ "room_id": room_id, "limit": limit, "after_event_id": after }),
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
    /// The rooms the grant would cover: every room this identity belongs to
    /// right now, enumerated at confirmation time. Conservative on purpose —
    /// rooms joined after pairing are NOT covered until a future re-pair or a
    /// native grant-management UI widens them. Names are sanitized for display
    /// but the *ids* (never remote-chosen) are what the grant binds.
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
                println!("   NOTE: this identity is in no rooms yet; the grant");
                println!("   would authorize nothing until you re-pair later.");
            } else {
                println!("   If approved, the browser may read and send in:");
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
    /// Write now if the store changed; ack when the write (if any) is durable.
    Flush(oneshot::Sender<()>),
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

            let write_if_changed = |last: &mut String, gw_snapshot: String| {
                if gw_snapshot != *last {
                    match persist_snapshot(&keys_path, &gw_snapshot) {
                        Ok(()) => *last = gw_snapshot,
                        Err(err) => error!("control-key persistence failed: {err}"),
                    }
                }
            };

            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        let snapshot = {
                            let mut gw = gateway.lock().await;
                            gw.evict_expired();
                            gw.snapshot_json()
                        };
                        write_if_changed(&mut last_written, snapshot);
                    }
                    msg = rx.recv() => match msg {
                        Some(PersistMsg::Flush(ack)) => {
                            let snapshot = gateway.lock().await.snapshot_json();
                            write_if_changed(&mut last_written, snapshot);
                            let _ = ack.send(());
                        }
                        Some(PersistMsg::Shutdown(ack)) => {
                            let snapshot = {
                                let mut gw = gateway.lock().await;
                                gw.evict_expired();
                                gw.snapshot_json()
                            };
                            write_if_changed(&mut last_written, snapshot);
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

/// Flush now and wait until the write (if any) is durable. Used on a successful
/// pairing so a hard kill right after "Pairing complete" cannot lose the
/// just-installed grant.
async fn flush_now(tx: &mpsc::Sender<PersistMsg>) {
    let (ack_tx, ack_rx) = oneshot::channel();
    if tx.send(PersistMsg::Flush(ack_tx)).await.is_ok() {
        let _ = ack_rx.await;
    }
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

/// Flush the new grant durably, then tell the operator.
async fn announce_success(persist_tx: &mpsc::Sender<PersistMsg>) {
    flush_now(persist_tx).await;
    println!("   Pairing complete: the browser now holds a control key.");
    info!("companion pairing complete; offer loop stopped");
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
    use jeliya_control::{Clock, Initiator, KeyPair, ManualClock};
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
        flush_now(&persister.tx).await;
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
