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
/// The v1 control-session age cap (spec: 24 h). A control session older than
/// this is torn down regardless of the key's remaining lifetime.
const CONTROL_DEADLINE: Duration = Duration::from_secs(24 * 60 * 60);
/// The maximum time a peer may take, after a handshake-rate token is spent, to
/// open the stream and send its first frame before the connection is dropped.
/// Bounds stuck connections that never speak.
const FIRST_FRAME_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest engine-result body that fits a single transport frame after the
/// message framing, the Noise tag, and the frame header. A larger result is
/// turned into a bounded engine error rather than a `FrameTooLarge` write drop.
const MAX_RESULT_LEN: usize = jeliya_protocol::MAX_FRAME_LEN - 256;

/// Drive one control connection to completion. `static_key` is a fresh keypair
/// built from the companion's long-lived static secret; `session_id` identifies
/// this connection for revocation; `offers` is the companion's pairing-offer
/// registry, against which a pairing `ClientHello`'s nonce is **atomically
/// claimed** (single-use, and the slot stays busy for the whole ceremony) so a
/// concurrent second connection is refused; `clock` is sampled at ClientHello
/// time so a stale offer cannot be claimed after its TTL. Non-fatal: a protocol
/// error closes the connection but is the expected fail-closed outcome.
#[allow(clippy::too_many_arguments)]
pub async fn serve_connection<C: FrameChannel>(
    mut chan: C,
    static_key: KeyPair,
    session_id: SessionId,
    offers: Arc<Mutex<PairingOffers>>,
    clock: Arc<dyn jeliya_control::Clock>,
    gateway: Arc<Mutex<ControlGateway>>,
    dispatch: Arc<dyn ControlDispatch>,
    policy: Arc<dyn ControlPolicy>,
    revoked: Arc<Notify>,
) {
    // Read the first frame under a bound: a peer that opens a connection but
    // never speaks is dropped rather than leaking a task.
    let first = match tokio::time::timeout(FIRST_FRAME_TIMEOUT, chan.read_frame()).await {
        Ok(Ok(f)) => f,
        _ => return,
    };
    // If the first frame is a pairing ClientHello, atomically claim its offer
    // nonce, sampling the clock *now* (at ClientHello time) so a peer cannot sit
    // on a live connection until the offer expires and then claim a stale nonce.
    let claimed = claim_pairing_offer(&first, &offers, clock.now_ms()).await;
    let is_pairing = claimed.is_some();
    let mut resp = Responder::new(static_key, session_id, claimed);

    // Deadlines: a pairing session is bounded by the 120 s ceremony window; a
    // control session by the 24 h age cap.
    let deadline = tokio::time::Instant::now()
        + if is_pairing {
            PAIRING_DEADLINE
        } else {
            CONTROL_DEADLINE
        };

    let mut pending = Some(first);
    loop {
        let frame = match pending.take() {
            Some(f) => f,
            None => {
                tokio::select! {
                    biased;
                    () = revoked.notified() => break,
                    () = tokio::time::sleep_until(deadline) => break, // session deadline
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

        match run_outs(
            outs, &mut chan, &mut resp, &gateway, &*dispatch, &*policy, &revoked, deadline,
        )
        .await
        {
            Ok(false) => {}
            Ok(true) | Err(_) => break, // close requested / cancelled / write failed
        }
    }

    // Cleanup: release a claimed pairing offer (freeing the busy slot), drop this
    // session from the gateway's live set, and close the channel.
    if is_pairing {
        offers.lock().await.release();
    }
    if let Some(key) = resp.authenticated_key() {
        gateway.lock().await.close_session(&key, session_id);
    }
    chan.close().await;
}

/// If `frame` is a pairing `ClientHello`, atomically claim its offer nonce
/// (keeping the offer slot busy for the whole ceremony) and return it; otherwise
/// return `None`. At most one connection ever claims a given offer.
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
    if offers.lock().await.claim(&hello.pairing_nonce, now_ms) {
        Some(hello.pairing_nonce)
    } else {
        None
    }
}

/// Await revocation or the session deadline — the cancellation signal raced
/// against the policy and engine awaits below, so a revoke or a blown deadline
/// tears the session down even mid-dispatch.
async fn cancelled(revoked: &Notify, deadline: tokio::time::Instant) {
    tokio::select! {
        () = revoked.notified() => (),
        () = tokio::time::sleep_until(deadline) => (),
    }
}

/// Carry out a list of responder actions. Returns `Ok(true)` when the session
/// should close, `Ok(false)` to keep serving, `Err` on a write failure. The two
/// awaits that can block on an external party — the policy's SAS confirmation
/// and the engine dispatch — are raced against `cancelled`, so a revocation or a
/// blown deadline tears the session down *without* installing a key or sealing a
/// response after it should have closed.
#[allow(clippy::too_many_arguments)]
async fn run_outs<C: FrameChannel>(
    initial: Vec<Out>,
    chan: &mut C,
    resp: &mut Responder,
    gateway: &Arc<Mutex<ControlGateway>>,
    dispatch: &dyn ControlDispatch,
    policy: &dyn ControlPolicy,
    revoked: &Notify,
    deadline: tokio::time::Instant,
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
                let decision = tokio::select! {
                    d = policy.confirm_pairing(&sas) => d,
                    () = cancelled(revoked, deadline) => return Ok(true), // no install
                };
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
                // The engine call runs lock-free, raced against revocation/the
                // deadline: if either wins, close without sealing a response.
                let result = tokio::select! {
                    r = dispatch.dispatch(call) => r,
                    () = cancelled(revoked, deadline) => return Ok(true),
                };
                // Guard an oversized engine result: turn it into a bounded engine
                // error rather than a frame that would exceed MAX_FRAME_LEN and
                // drop the session on write.
                let result = match result {
                    Ok(body) if body.len() > MAX_RESULT_LEN => Err("result too large".to_string()),
                    other => other,
                };
                match resp.complete_dispatch(nonce, result) {
                    Ok(more) => queue.extend(more),
                    Err(_) => return Ok(true),
                }
            }
        }
    }
    Ok(false)
}
