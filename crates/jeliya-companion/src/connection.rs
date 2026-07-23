//! The per-connection control-session driver: read a frame, drive the sans-I/O
//! [`Responder`], carry out the actions it emits (write frames, ask the policy
//! to confirm a pairing, dispatch an authorized RPC to the engine), and tear the
//! session down on close, protocol error, or key revocation.
//!
//! The gateway mutex is **never** held across an `await`: each frame is fed to
//! the responder under a brief lock that yields a list of actions, the lock is
//! dropped, and the actions (which may await the policy or the engine) run
//! lock-free; any follow-up actions re-lock only for the synchronous responder
//! call. This keeps one companion's single gateway a point of serialization
//! without blocking every session behind one slow engine call.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Notify};

use jeliya_control::{ControlGateway, ControlKey, KeyPair, Out, Responder, SessionId};

use crate::channel::{ChannelError, FrameChannel};
use crate::dispatch::{ControlDispatch, ControlPolicy, PairingDecision};
use crate::offers::PairingOffers;

/// The registry of live sessions' revocation signals, so a `revoke` can tear
/// down the exact connections bound to a key. Shared by the endpoint and every
/// connection task.
#[derive(Clone, Default)]
pub struct Revocations {
    inner: Arc<Mutex<HashMap<SessionId, Arc<Notify>>>>,
}

impl Revocations {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a session and get the `Notify` its connection task waits on.
    pub async fn register(&self, session_id: SessionId) -> Arc<Notify> {
        let notify = Arc::new(Notify::new());
        self.inner.lock().await.insert(session_id, notify.clone());
        notify
    }

    pub async fn deregister(&self, session_id: SessionId) {
        self.inner.lock().await.remove(&session_id);
    }

    /// Revoke `key` in `gateway` and signal every live session bound to it to
    /// tear down. The gateway lock is taken and released before the registry
    /// lock, so the two never nest. Uses `notify_one` (permit-storing), not
    /// `notify_waiters`: a revoke fired while the connection task is mid-frame
    /// (awaiting the engine or the human confirmation, so not parked on
    /// `notified()`) still tears the session down on the task's next poll,
    /// rather than being silently lost.
    pub async fn revoke(&self, gateway: &Mutex<ControlGateway>, key: &ControlKey) {
        let sessions = {
            let mut gw = gateway.lock().await;
            gw.revoke(key)
        };
        let map = self.inner.lock().await;
        for sid in sessions {
            if let Some(notify) = map.get(&sid) {
                notify.notify_one();
            }
        }
    }
}

/// The v1 pairing-session deadline (spec: 120 s). A pairing connection that has
/// not installed within this window is torn down.
const PAIRING_DEADLINE: Duration = Duration::from_secs(120);

/// Drive one control connection to completion. `static_key` is a fresh keypair
/// built from the companion's long-lived static secret; `session_id` identifies
/// this connection for revocation; `offers` is the companion's pairing-offer
/// registry, against which a pairing `ClientHello`'s nonce is **atomically
/// spent** (single-use) before the ceremony runs — so a concurrent second
/// connection presenting the same nonce is refused, preventing interleaved-
/// ceremony SAS confusion. Non-fatal: a protocol error closes the connection but
/// is the expected fail-closed outcome, not an error to propagate.
#[allow(clippy::too_many_arguments)]
pub async fn serve_connection<C: FrameChannel>(
    mut chan: C,
    static_key: KeyPair,
    session_id: SessionId,
    offers: Arc<Mutex<PairingOffers>>,
    now_ms: u64,
    gateway: Arc<Mutex<ControlGateway>>,
    dispatch: Arc<dyn ControlDispatch>,
    policy: Arc<dyn ControlPolicy>,
    revoked: Arc<Notify>,
) {
    // Read the first frame; if it is a pairing ClientHello, atomically claim its
    // offer nonce under the offers lock (single-use). The resolved
    // `expected_pairing_nonce` is what the Responder validates against.
    let first = match chan.read_frame().await {
        Ok(f) => f,
        Err(_) => return,
    };
    let expected = claim_pairing_offer(&first, &offers, now_ms).await;
    let is_pairing = expected.is_some();
    let mut resp = Responder::new(static_key, session_id, expected);

    // A pairing session is bounded by the deadline; a control session is not
    // (its lifetime is bounded by the key expiry and the session-age cap).
    let deadline = if is_pairing {
        Some(tokio::time::Instant::now() + PAIRING_DEADLINE)
    } else {
        None
    };

    let mut pending = Some(first);
    loop {
        let frame = match pending.take() {
            Some(f) => f,
            None => {
                let timer = async {
                    match deadline {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending::<()>().await,
                    }
                };
                tokio::select! {
                    biased;
                    () = revoked.notified() => break,
                    () = timer => break, // pairing deadline elapsed
                    read = chan.read_frame() => match read {
                        Ok(f) => f,
                        Err(_) => break, // stream closed or errored → session ends
                    },
                }
            }
        };

        let outs = {
            let mut gw = gateway.lock().await;
            match resp.on_frame(&frame, &mut gw) {
                Ok(outs) => outs,
                Err(_) => break, // protocol error → fail closed
            }
        };

        match run_outs(outs, &mut chan, &mut resp, &gateway, &*dispatch, &*policy).await {
            Ok(false) => {}
            Ok(true) | Err(_) => break, // close requested or write failed
        }
    }

    // Cleanup: drop this session from the gateway's live set and the registry.
    if let Some(key) = resp.authenticated_key() {
        gateway.lock().await.close_session(&key, session_id);
    }
    chan.close().await;
}

/// If `frame` is a pairing `ClientHello`, atomically spend its offer nonce and
/// return it (so the Responder accepts the pairing); otherwise return `None`.
/// The spend is single-use under the offers lock, so at most one connection ever
/// resolves a given offer nonce.
async fn claim_pairing_offer(
    frame: &jeliya_protocol::Frame,
    offers: &Mutex<PairingOffers>,
    now_ms: u64,
) -> Option<[u8; 16]> {
    use jeliya_protocol::{ClientHello, FrameType, SessionKind};
    if frame.frame_type != FrameType::ClientHello {
        return None;
    }
    let hello = ClientHello::decode_body(&frame.body).ok()?;
    if hello.session_kind != SessionKind::Pairing {
        return None;
    }
    let mut off = offers.lock().await;
    let _ = off.live_nonce(now_ms); // expire a stale offer before the claim
    if off.spend(&hello.pairing_nonce) {
        Some(hello.pairing_nonce)
    } else {
        None
    }
}

/// Carry out a list of responder actions. Returns `Ok(true)` when the session
/// should close, `Ok(false)` to keep serving, `Err` on a write failure.
async fn run_outs<C: FrameChannel>(
    initial: Vec<Out>,
    chan: &mut C,
    resp: &mut Responder,
    gateway: &Arc<Mutex<ControlGateway>>,
    dispatch: &dyn ControlDispatch,
    policy: &dyn ControlPolicy,
) -> Result<bool, ChannelError> {
    let mut queue: VecDeque<Out> = initial.into();
    while let Some(out) = queue.pop_front() {
        match out {
            Out::Send(frame) => chan.write_frame(frame).await?,
            Out::Close => return Ok(true),
            Out::Installed(_key) => {
                // The record is already in the gateway; a control session
                // registers itself as live at admission. Nothing to do here.
            }
            Out::SasReady(sas) => {
                let decision = policy.confirm_pairing(&sas).await;
                let follow = {
                    let mut gw = gateway.lock().await;
                    match decision {
                        PairingDecision::Approve {
                            scopes,
                            rooms,
                            lifetime,
                        } => resp.confirm_pairing(&mut gw, scopes, rooms, lifetime),
                        PairingDecision::Reject => resp.abort_pairing(),
                    }
                };
                match follow {
                    Ok(more) => queue.extend(more),
                    Err(_) => return Ok(true),
                }
            }
            Out::Dispatch { nonce, call } => {
                // The engine call runs lock-free; sealing the response needs no
                // gateway access.
                let result = dispatch.dispatch(call).await;
                match resp.complete_dispatch(nonce, result) {
                    Ok(more) => queue.extend(more),
                    Err(_) => return Ok(true),
                }
            }
        }
    }
    Ok(false)
}
