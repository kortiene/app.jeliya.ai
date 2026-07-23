//! The two host seams the control-session runtime calls out to: the engine
//! **dispatch** (execute an authorized scoped RPC) and the pairing **policy**
//! (the companion-local, trusted-surface confirmation of a pairing).
//!
//! Both are host-supplied so the runtime stays decoupled from `jeliya-core` and
//! from any particular UI: the daemon provides an engine-backed dispatch and a
//! native-UI-backed policy; tests provide deterministic fakes. Methods return
//! boxed `Send` futures so the runtime future stays `Send` and the seams are
//! usable as `&dyn`.

use std::collections::BTreeSet;
use std::time::Duration;

use jeliya_control::Scope;
use jeliya_protocol::MethodCall;

use crate::channel::BoxFuture;

/// Executes an authorized, already-decoded scoped RPC against the engine. The
/// runtime only calls this **after** the gateway authorized the call, so an
/// implementation performs the engine operation and returns its result JSON
/// bytes (UTF-8) or an engine error message. It must never widen scope: the
/// `MethodCall` is one of the three v1 methods, already room-bound.
pub trait ControlDispatch: Send + Sync {
    fn dispatch(&self, call: MethodCall) -> BoxFuture<'_, Result<Vec<u8>, String>>;
}

/// The companion's local decision on a pairing, taken on a surface the browser
/// origin cannot render or forge (ADR #2 adoption). Returned by
/// [`ControlPolicy::confirm_pairing`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairingDecision {
    /// Install a control key with these scopes, rooms, and lifetime.
    Approve {
        scopes: BTreeSet<Scope>,
        rooms: BTreeSet<String>,
        lifetime: Duration,
    },
    /// Reject (wrong SAS, or the user declined): install nothing.
    Reject,
}

/// The companion-local pairing confirmation surface. The runtime hands it the
/// SAS to present on the trusted surface; the human compares it against the
/// browser's display and either approves a scoped grant or rejects.
pub trait ControlPolicy: Send + Sync {
    fn confirm_pairing(&self, sas: &str) -> BoxFuture<'_, PairingDecision>;
}
