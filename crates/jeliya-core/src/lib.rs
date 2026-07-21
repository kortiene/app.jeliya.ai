//! Jeliya resident core — the only crate in the project that imports the
//! `iroh_rooms` SDK (stable tier for authoring/validation, experimental tier
//! for the online runtime), consumed by the `jeliyad` daemon.
//!
//! Modules:
//! * [`engine`] — the transport-free engine facade: protocol dispatch,
//!   request/response envelope, and push fan-out per `docs/PROTOCOL.md`,
//!   shared by every transport (the `jeliyad` WebSocket daemon, the mobile
//!   FFI shim).
//! * [`fleet`] — pure agent-liveness derivation (the `agents.fleet` /
//!   `agent.history` decision table per `docs/agent-orchestration.md` §1.2).
//! * [`identity`] — create/load the device identity under `--data-dir`
//!   (mirrors the iroh-rooms CLI's `identity.json` / `identity.secret` split).
//! * [`localstate`] — daemon-local JSON state: known-rooms index + local name
//!   overrides. Note: the wire protocol *does* carry a room name
//!   (`room.created.room_name`), so the local name is an index/override, not
//!   the source of truth.
//! * [`materializer`] — pure `StoredEvent -> TimelineEvent` JSON view-models
//!   per `docs/PROTOCOL.md`.
//! * [`recovery`] — Phase 1 D1 recovery bundle (ADR #3): a versioned
//!   authenticated-encryption envelope keyed by a random 256-bit recovery key,
//!   so an accountless identity can be backed up and restored to a fresh install.
//! * [`supervisor`] — `RoomSupervisor`: one experimental `Node` per open room
//!   (spawned the way the reference CLI spawns its room session), plus the
//!   offline flows (create/invite/join/reads) mirrored from the CLI.

pub mod engine;
pub mod error;
pub mod fleet;
pub mod identity;
pub mod localstate;
pub mod materializer;
pub mod recovery;
pub mod supervisor;

pub use engine::{Engine, EngineConfig, PROTOCOL_VERSION};
pub use error::{CoreError, CoreResult, ErrorKind};

/// Compile-time attestation used only by the controlled relay verifier build.
///
/// This item does not exist in ordinary builds. Enabling Jeliya's diagnostic
/// feature against an upstream SDK without its matching transport feature
/// fails at compile time below; it can never produce a falsely attested
/// direct-capable binary.
#[cfg(feature = "relay-only-test")]
pub const RELAY_ONLY_TEST_BUILD: bool = iroh_rooms::experimental::session::RELAY_ONLY_TEST_BUILD;

#[cfg(feature = "relay-only-test")]
const _: () = assert!(
    RELAY_ONLY_TEST_BUILD,
    "relay-only-test requires the reviewed upstream clear_ip_transports feature"
);

/// Wall-clock milliseconds since the Unix epoch (advisory/display only — the
/// protocol never orders by it).
#[must_use]
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
