//! The sans-I/O session driver: a deterministic state machine that consumes
//! decoded frames and emits actions, tying the D6 hellos, the Noise handshake,
//! the SAS ceremony, and the gateway-checked RPC path together without owning a
//! socket or an async runtime. The iroh transport adapter (the companion) drives
//! the [`Responder`] by reading a frame off the QUIC stream, feeding it in, and
//! writing out the produced frames; the end-to-end tests drive it against the
//! reference [`Initiator`]. Keeping the protocol logic sans-I/O makes every
//! branch — including the four fail-closed gate assertions — exercisable as a
//! pure unit test.

use std::time::Duration;

use jeliya_protocol::{
    ClientHello, Frame, FrameType, MethodCall, Msg, ServerHello, SessionKind, MIN_SAFE_VERSION,
    PROTOCOL_VERSION_V1,
};

use crate::crypto::KeyPair;
use crate::gateway::{
    Clock, ControlGateway, ControlKey, ControlKeyRecord, Denial, ReplayWindow, Scope, SessionId,
};
use crate::noise::{HandshakeState, NoiseError, TransportState};
use crate::sas::sas_from_handshake_hash;

/// A session-level failure. Any of these tears the session (and its underlying
/// connection) down.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionError {
    /// A frame arrived in the wrong state, or had the wrong type.
    Unexpected(&'static str),
    /// A wire decode failed.
    Proto(jeliya_protocol::ProtoError),
    /// The Noise layer failed (tamper, bad key, reorder).
    Noise(NoiseError),
    /// No compatible protocol version (the companion already emitted an
    /// incompatible `ServerHello`; the connection then closes).
    Incompatible,
}

impl From<jeliya_protocol::ProtoError> for SessionError {
    fn from(e: jeliya_protocol::ProtoError) -> Self {
        SessionError::Proto(e)
    }
}
impl From<NoiseError> for SessionError {
    fn from(e: NoiseError) -> Self {
        SessionError::Noise(e)
    }
}

/// An action the driver asks its host (transport) to take.
#[derive(Clone, Debug)]
pub enum Out {
    /// Write this frame to the peer.
    Send(Frame),
    /// The SAS is ready; present it on the companion's trusted surface.
    SasReady(String),
    /// A scoped RPC authorized; dispatch it to the engine, then call
    /// [`Responder::complete_dispatch`] with the result.
    Dispatch { nonce: u64, call: MethodCall },
    /// A control key was installed by a completed pairing.
    Installed(ControlKey),
    /// Close the session/connection.
    Close,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitClientHello,
    AwaitHandshake1,
    AwaitHandshake3,
    AwaitConfirmations,
    Serving,
    Closed,
}

/// The companion side of a control session.
///
/// This driver is sans-I/O and single-connection: it enforces the per-session
/// protocol (version negotiation, handshake, SAS ceremony, admission, scoped
/// RPC), and it checks that a pairing session presents the live offer's nonce.
/// It deliberately does **not** own cross-connection or wall-clock offer
/// orchestration — the companion's offer registry (the transport adapter) owns
/// those, because they need state and a clock the sans-I/O core does not hold:
/// - **single-use offers**: the transport spends the rendezvous nonce on the
///   first `ClientHello` that presents it (success or not) and passes
///   `expected_pairing_nonce = None` to every later session.
/// - **one outstanding pairing at a time** and the **120 s pairing deadline**:
///   the transport refuses a second concurrent pairing offer and drops a
///   pairing connection that has not installed within the deadline.
/// - **handshake-tier rate limiting** ([`crate::HandshakeLimiter`]): the
///   transport gates handshakes by the iroh `EndpointId` before constructing a
///   `Responder`.
pub struct Responder {
    static_key: KeyPair,
    session_id: SessionId,
    supported_max: u16,
    min_safe: u16,
    /// The outstanding pairing offer's rendezvous nonce, if a pairing is being
    /// offered right now. `None` means no pairing offer — a `Pairing` hello is
    /// refused.
    expected_pairing_nonce: Option<[u8; 16]>,
    state: State,
    kind: Option<SessionKind>,
    client_hello_bytes: Vec<u8>,
    handshake: Option<HandshakeState>,
    transport: Option<TransportState>,
    authed_key: Option<ControlKey>,
    handshake_hash: Option<[u8; 32]>,
    browser_confirmed: bool,
    // companion-local grant, set by confirm_pairing:
    local_grant: Option<Grant>,
    replay: ReplayWindow,
}

struct Grant {
    scopes: std::collections::BTreeSet<Scope>,
    rooms: std::collections::BTreeSet<String>,
    lifetime: Duration,
}

impl Responder {
    /// Create a responder for one inbound connection. `static_key` is the
    /// companion's long-lived pairing identity; `session_id` identifies this
    /// connection for revocation teardown; `expected_pairing_nonce` is the live
    /// pairing offer's nonce (or `None` when not pairing).
    #[must_use]
    pub fn new(
        static_key: KeyPair,
        session_id: SessionId,
        expected_pairing_nonce: Option<[u8; 16]>,
    ) -> Self {
        Self {
            static_key,
            session_id,
            supported_max: PROTOCOL_VERSION_V1,
            min_safe: MIN_SAFE_VERSION,
            expected_pairing_nonce,
            state: State::AwaitClientHello,
            kind: None,
            client_hello_bytes: Vec::new(),
            handshake: None,
            transport: None,
            authed_key: None,
            handshake_hash: None,
            browser_confirmed: false,
            local_grant: None,
            replay: ReplayWindow::new(),
        }
    }

    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    #[must_use]
    pub fn authenticated_key(&self) -> Option<ControlKey> {
        self.authed_key
    }

    /// Feed one decoded frame; return the actions to take. `gateway` is needed
    /// once the session reaches admission/RPC.
    pub fn on_frame(
        &mut self,
        frame: &Frame,
        gateway: &mut ControlGateway,
    ) -> Result<Vec<Out>, SessionError> {
        match self.state {
            State::AwaitClientHello => self.on_client_hello(frame),
            State::AwaitHandshake1 => self.on_handshake1(frame),
            State::AwaitHandshake3 => self.on_handshake3(frame, gateway),
            State::AwaitConfirmations => self.on_pairing_frame(frame, gateway),
            State::Serving => self.on_request_frame(frame, gateway),
            State::Closed => Err(SessionError::Unexpected("frame after close")),
        }
    }

    fn expect(
        &self,
        frame: &Frame,
        want: FrameType,
        ctx: &'static str,
    ) -> Result<(), SessionError> {
        if frame.frame_type == want {
            Ok(())
        } else {
            let _ = frame;
            Err(SessionError::Unexpected(ctx))
        }
    }

    fn on_client_hello(&mut self, frame: &Frame) -> Result<Vec<Out>, SessionError> {
        self.expect(frame, FrameType::ClientHello, "expected ClientHello")?;
        let hello = ClientHello::decode_body(&frame.body)?;
        self.kind = Some(hello.session_kind);
        // Negotiate: highest offered version we support that is >= min_safe.
        let chosen = hello
            .versions
            .iter()
            .copied()
            .filter(|v| *v <= self.supported_max && *v >= self.min_safe)
            .max();
        let server_hello = ServerHello {
            version: chosen.unwrap_or(0),
            min_version: self.min_safe,
        };
        let sh_frame = server_hello.to_frame();
        if server_hello.is_incompatible() {
            self.state = State::Closed;
            return Ok(vec![Out::Send(sh_frame), Out::Close]);
        }
        // Pairing sessions must present the live offer's nonce.
        if hello.session_kind == SessionKind::Pairing {
            match self.expected_pairing_nonce {
                Some(n) if n == hello.pairing_nonce => {}
                _ => {
                    self.state = State::Closed;
                    return Err(SessionError::Unexpected("no matching pairing offer"));
                }
            }
        }
        // Build the prologue from the exact hello frames (canonical re-encode).
        self.client_hello_bytes = hello.to_frame()?.encode()?;
        let mut prologue = self.client_hello_bytes.clone();
        prologue.extend_from_slice(&sh_frame.encode()?);
        self.handshake = Some(HandshakeState::new_responder(
            std::mem::replace(
                &mut self.static_key,
                KeyPair::from_secret(zeroize_placeholder()),
            ),
            &prologue,
        ));
        self.state = State::AwaitHandshake1;
        Ok(vec![Out::Send(sh_frame)])
    }

    fn on_handshake1(&mut self, frame: &Frame) -> Result<Vec<Out>, SessionError> {
        self.expect(frame, FrameType::Handshake1, "expected Handshake1")?;
        let hs = self
            .handshake
            .as_mut()
            .ok_or(SessionError::Unexpected("no handshake"))?;
        hs.read_message_1(&frame.body)?;
        let m2 = hs.write_message_2()?;
        self.state = State::AwaitHandshake3;
        Ok(vec![Out::Send(Frame::new(FrameType::Handshake2, m2))])
    }

    fn on_handshake3(
        &mut self,
        frame: &Frame,
        gateway: &mut ControlGateway,
    ) -> Result<Vec<Out>, SessionError> {
        self.expect(frame, FrameType::Handshake3, "expected Handshake3")?;
        let hs = self
            .handshake
            .take()
            .ok_or(SessionError::Unexpected("no handshake"))?;
        let (transport, browser_key, hh) = hs.read_message_3(&frame.body)?;
        self.transport = Some(transport);
        self.authed_key = Some(ControlKey(browser_key));
        self.handshake_hash = Some(hh);

        match self.kind {
            Some(SessionKind::Pairing) => {
                let sas = sas_from_handshake_hash(&hh);
                self.state = State::AwaitConfirmations;
                Ok(vec![Out::SasReady(sas)])
            }
            Some(SessionKind::Control) => {
                let key = ControlKey(browser_key);
                match gateway.admit_session(&key) {
                    Ok(record) => {
                        let accept = Msg::SessionAccept {
                            methods: record.granted_methods(),
                            expires_at_ms: record.expires_at_ms(),
                        };
                        let frame = self.seal(&accept)?;
                        gateway.open_session(key, self.session_id);
                        self.state = State::Serving;
                        Ok(vec![Out::Send(frame)])
                    }
                    Err(reason) => {
                        let reject = Msg::SessionReject {
                            reason: reason.registry_code(),
                        };
                        let frame = self.seal(&reject)?;
                        self.state = State::Closed;
                        Ok(vec![Out::Send(frame), Out::Close])
                    }
                }
            }
            None => Err(SessionError::Unexpected("no session kind")),
        }
    }

    fn on_pairing_frame(
        &mut self,
        frame: &Frame,
        gateway: &mut ControlGateway,
    ) -> Result<Vec<Out>, SessionError> {
        let msg = self.open(frame)?;
        match msg {
            Msg::PairConfirm => {
                self.browser_confirmed = true;
                Ok(self.try_finish_pairing(gateway)?)
            }
            _ => Err(SessionError::Unexpected("expected PairConfirm")),
        }
    }

    /// Companion-local confirmation: the user compared the SAS on the trusted
    /// surface and approved the grant. Installs iff the browser has also
    /// confirmed. Selecting scopes/rooms/lifetime here is the human authority
    /// the browser origin cannot forge.
    pub fn confirm_pairing(
        &mut self,
        gateway: &mut ControlGateway,
        scopes: std::collections::BTreeSet<Scope>,
        rooms: std::collections::BTreeSet<String>,
        lifetime: Duration,
    ) -> Result<Vec<Out>, SessionError> {
        if self.state != State::AwaitConfirmations {
            return Err(SessionError::Unexpected("not awaiting confirmation"));
        }
        self.local_grant = Some(Grant {
            scopes,
            rooms,
            lifetime,
        });
        self.try_finish_pairing(gateway)
    }

    /// The companion user rejected the SAS (or the grant): abort without
    /// installing. This is the "wrong-SAS fail closed" path on the companion —
    /// no record is produced.
    pub fn abort_pairing(&mut self) -> Result<Vec<Out>, SessionError> {
        if self.state != State::AwaitConfirmations {
            return Err(SessionError::Unexpected("not awaiting confirmation"));
        }
        let result = Msg::PairResult {
            installed: false,
            scopes: vec![],
            rooms: vec![],
            expires_at_ms: 0,
        };
        let frame = self.seal(&result)?;
        self.state = State::Closed;
        Ok(vec![Out::Send(frame), Out::Close])
    }

    fn try_finish_pairing(
        &mut self,
        gateway: &mut ControlGateway,
    ) -> Result<Vec<Out>, SessionError> {
        if !self.browser_confirmed {
            return Ok(vec![]);
        }
        let Some(grant) = self.local_grant.take() else {
            return Ok(vec![]); // still awaiting the companion-local confirmation
        };
        let key = self.authed_key.ok_or(SessionError::Unexpected("no key"))?;
        let now = gateway.now_ms();
        let record = ControlKeyRecord::new(key, grant.scopes, grant.rooms, now, grant.lifetime);
        let expires = record.expires_at_ms();
        let scopes: Vec<u16> = record.scopes().map(Scope::registry_id).collect();
        let rooms: Vec<String> = record.rooms().map(str::to_owned).collect();
        gateway.install(record);
        let result = Msg::PairResult {
            installed: true,
            scopes,
            rooms,
            expires_at_ms: expires,
        };
        let frame = self.seal(&result)?;
        self.state = State::Closed;
        Ok(vec![Out::Installed(key), Out::Send(frame), Out::Close])
    }

    fn on_request_frame(
        &mut self,
        frame: &Frame,
        gateway: &mut ControlGateway,
    ) -> Result<Vec<Out>, SessionError> {
        let request_bytes = frame.body.len();
        let msg = self.open(frame)?;
        let Msg::Request {
            nonce,
            method,
            params,
        } = msg
        else {
            return Err(SessionError::Unexpected("expected Request"));
        };
        let key = self.authed_key.ok_or(SessionError::Unexpected("no key"))?;

        // Method must be in the v1 registry (fails closed before scope eval).
        let Some(scope) = Scope::for_method_id(method) else {
            return Ok(vec![self.error(
                nonce,
                jeliya_protocol::error::METHOD_UNKNOWN,
                "unknown method",
            )?]);
        };
        let call = match MethodCall::decode(method, &params) {
            Ok(c) => c,
            Err(_) => {
                return Ok(vec![self.error(
                    nonce,
                    jeliya_protocol::error::PARAMS_INVALID,
                    "invalid params",
                )?]);
            }
        };
        let room = call.room_id().to_string();
        let bytes = u32::try_from(request_bytes).unwrap_or(u32::MAX);
        match gateway.authorize(&key, scope, &room, bytes, nonce, &mut self.replay) {
            Ok(()) => Ok(vec![Out::Dispatch { nonce, call }]),
            Err(err) => {
                let mut outs =
                    vec![self.error(nonce, err.denial.registry_code(), deny_msg(err.denial))?];
                if err.teardown {
                    self.state = State::Closed;
                    outs.push(Out::Close);
                }
                Ok(outs)
            }
        }
    }

    /// Supply the engine result for a previously-emitted [`Out::Dispatch`]. On
    /// `Ok` the bytes are the daemon result JSON; on `Err` they are an engine
    /// error kind + message passed through.
    pub fn complete_dispatch(
        &mut self,
        nonce: u64,
        result: Result<Vec<u8>, String>,
    ) -> Result<Vec<Out>, SessionError> {
        let msg = match result {
            Ok(body) => Msg::Response {
                nonce,
                ok: true,
                body,
            },
            Err(message) => {
                Msg::error_response(nonce, jeliya_protocol::error::ENGINE_ERROR, &message)?
            }
        };
        Ok(vec![Out::Send(self.seal(&msg)?)])
    }

    fn error(&mut self, nonce: u64, code: u16, message: &str) -> Result<Out, SessionError> {
        let msg = Msg::error_response(nonce, code, message)?;
        Ok(Out::Send(self.seal(&msg)?))
    }

    fn seal(&mut self, msg: &Msg) -> Result<Frame, SessionError> {
        let transport = self
            .transport
            .as_mut()
            .ok_or(SessionError::Unexpected("no transport"))?;
        let ct = transport.encrypt(&msg.encode()?)?;
        Ok(Frame::new(FrameType::Transport, ct))
    }

    fn open(&mut self, frame: &Frame) -> Result<Msg, SessionError> {
        self.expect(frame, FrameType::Transport, "expected Transport")?;
        let transport = self
            .transport
            .as_mut()
            .ok_or(SessionError::Unexpected("no transport"))?;
        let pt = transport.decrypt(&frame.body)?;
        Ok(Msg::decode(&pt)?)
    }
}

fn deny_msg(d: Denial) -> &'static str {
    match d {
        Denial::UnknownKey => "unknown key",
        Denial::Revoked => "revoked",
        Denial::Expired => "expired",
        Denial::ScopeDenied => "scope denied",
        Denial::RoomDenied => "room denied",
        Denial::RateLimited => "rate limited",
        Denial::Replay => "replay",
    }
}

/// A throwaway keypair used only to move the responder's real static key into
/// the handshake state (the responder never uses this placeholder for anything).
fn zeroize_placeholder() -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new([0u8; 32])
}

// ------------------------------------------------------------------------
// Reference initiator (browser side): a minimal driver used by the end-to-end
// tests and as the reference the TypeScript controller mirrors. It is not a
// security boundary — the browser's real authority checks live on the
// responder; this only produces well-formed frames and reads the responses.
// ------------------------------------------------------------------------

/// The reference browser-side driver.
pub struct Initiator {
    static_key: KeyPair,
    kind: SessionKind,
    versions: Vec<u16>,
    pairing_nonce: [u8; 16],
    /// The companion static key to pin. Per the spec, the browser verifies the
    /// companion's static key against the fingerprint in the QR/link before the
    /// SAS on a pairing session, and against the full stored key on a control
    /// (reconnect) session. `None` on a first pairing (the key is learned, then
    /// stored for future control sessions).
    expected_companion_key: Option<[u8; 32]>,
    companion_key: Option<[u8; 32]>,
    client_hello_bytes: Vec<u8>,
    handshake: Option<HandshakeState>,
    transport: Option<TransportState>,
    sas: Option<String>,
    next_nonce: u64,
}

impl Initiator {
    /// Build the initiator and its opening `ClientHello` frame.
    ///
    /// `expected_companion_key` pins the companion static key: pass `None` for a
    /// first pairing (learn it, then store it), or `Some(stored_key)` for a
    /// control/reconnect session so a substituted companion aborts the handshake.
    #[must_use]
    pub fn new(
        static_key: KeyPair,
        kind: SessionKind,
        pairing_nonce: [u8; 16],
        expected_companion_key: Option<[u8; 32]>,
    ) -> (Self, Frame) {
        let versions = vec![PROTOCOL_VERSION_V1];
        let hello = ClientHello {
            versions: versions.clone(),
            session_kind: kind,
            pairing_nonce,
        };
        let frame = hello.to_frame().expect("client hello encodes");
        let client_hello_bytes = frame.encode().expect("frame encodes");
        (
            Self {
                static_key,
                kind,
                versions,
                pairing_nonce,
                expected_companion_key,
                companion_key: None,
                client_hello_bytes,
                handshake: None,
                transport: None,
                sas: None,
                next_nonce: 1,
            },
            frame,
        )
    }

    /// The companion static key learned during the handshake, to store after a
    /// first pairing and pin on later control sessions.
    #[must_use]
    pub fn companion_key(&self) -> Option<[u8; 32]> {
        self.companion_key
    }

    /// Consume the companion's `ServerHello`, returning the `Handshake1` frame.
    pub fn on_server_hello(&mut self, frame: &Frame) -> Result<Frame, SessionError> {
        if frame.frame_type != FrameType::ServerHello {
            return Err(SessionError::Unexpected("expected ServerHello"));
        }
        let sh = ServerHello::decode_body(&frame.body)?;
        if sh.is_incompatible() {
            return Err(SessionError::Incompatible);
        }
        let mut prologue = self.client_hello_bytes.clone();
        prologue.extend_from_slice(&frame.encode()?);
        let mut hs = HandshakeState::new_initiator(
            std::mem::replace(
                &mut self.static_key,
                KeyPair::from_secret(zeroize_placeholder()),
            ),
            &prologue,
        );
        let m1 = hs.write_message_1()?;
        self.handshake = Some(hs);
        let _ = &self.versions;
        let _ = self.pairing_nonce;
        let _ = self.kind;
        Ok(Frame::new(FrameType::Handshake1, m1))
    }

    /// Consume `Handshake2`, returning the `Handshake3` frame and completing the
    /// handshake. The SAS is available afterwards via [`Initiator::sas`].
    pub fn on_handshake2(&mut self, frame: &Frame) -> Result<Frame, SessionError> {
        if frame.frame_type != FrameType::Handshake2 {
            return Err(SessionError::Unexpected("expected Handshake2"));
        }
        let mut hs = self
            .handshake
            .take()
            .ok_or(SessionError::Unexpected("no handshake"))?;
        hs.read_message_2(&frame.body)?;
        // Pin the companion static key: on a reconnect the browser aborts if the
        // key does not match the one it stored at pairing (a substituted
        // companion). On a first pairing it is learned and the SAS ceremony is
        // the MITM authority.
        let learned = hs
            .remote_static()
            .ok_or(SessionError::Unexpected("no companion static key"))?;
        if let Some(pinned) = self.expected_companion_key {
            if learned != pinned {
                return Err(SessionError::Unexpected("companion key pin mismatch"));
            }
        }
        self.companion_key = Some(learned);
        let (m3, transport, hh) = hs.write_message_3()?;
        self.sas = Some(sas_from_handshake_hash(&hh));
        self.transport = Some(transport);
        Ok(Frame::new(FrameType::Handshake3, m3))
    }

    /// The SAS the browser user compares against the companion's display.
    #[must_use]
    pub fn sas(&self) -> Option<&str> {
        self.sas.as_deref()
    }

    /// Build a `PairConfirm` transport frame (the browser user confirmed).
    pub fn pair_confirm(&mut self) -> Result<Frame, SessionError> {
        self.seal(&Msg::PairConfirm)
    }

    /// Build a scoped `Request` transport frame with the next session nonce.
    pub fn request(&mut self, method: u16, call: &MethodCall) -> Result<Frame, SessionError> {
        let nonce = self.next_nonce;
        self.next_nonce += 1;
        let params = call.encode()?;
        self.seal(&Msg::Request {
            nonce,
            method,
            params,
        })
    }

    /// Build a `Request` with an explicit (possibly replayed) nonce, for tests.
    pub fn request_with_nonce(
        &mut self,
        nonce: u64,
        method: u16,
        call: &MethodCall,
    ) -> Result<Frame, SessionError> {
        let params = call.encode()?;
        self.seal(&Msg::Request {
            nonce,
            method,
            params,
        })
    }

    /// Decrypt and decode a transport frame from the companion.
    pub fn read(&mut self, frame: &Frame) -> Result<Msg, SessionError> {
        if frame.frame_type != FrameType::Transport {
            return Err(SessionError::Unexpected("expected Transport"));
        }
        let transport = self
            .transport
            .as_mut()
            .ok_or(SessionError::Unexpected("no transport"))?;
        let pt = transport.decrypt(&frame.body)?;
        Ok(Msg::decode(&pt)?)
    }

    fn seal(&mut self, msg: &Msg) -> Result<Frame, SessionError> {
        let transport = self
            .transport
            .as_mut()
            .ok_or(SessionError::Unexpected("no transport"))?;
        let ct = transport.encrypt(&msg.encode()?)?;
        Ok(Frame::new(FrameType::Transport, ct))
    }
}

/// A test/system clock that returns a fixed, advanceable time. Public so
/// integration tests (and the companion's own tests) can drive expiry and rate
/// limits deterministically.
pub struct ManualClock(std::sync::atomic::AtomicU64);

impl ManualClock {
    #[must_use]
    pub fn new(start_ms: u64) -> Self {
        Self(std::sync::atomic::AtomicU64::new(start_ms))
    }
    pub fn set(&self, ms: u64) {
        self.0.store(ms, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn advance(&self, delta_ms: u64) {
        self.0
            .fetch_add(delta_ms, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for std::sync::Arc<ManualClock> {
    fn now_ms(&self) -> u64 {
        self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    const OFFER: [u8; 16] = [0x22; 16];
    const BROWSER_SECRET: [u8; 32] = [5u8; 32];

    fn browser_kp() -> KeyPair {
        KeyPair::from_secret(Zeroizing::new(BROWSER_SECRET))
    }

    fn browser_key() -> ControlKey {
        ControlKey(browser_kp().public())
    }

    fn gateway(clock: &Arc<ManualClock>) -> ControlGateway {
        ControlGateway::with_clock(Box::new(clock.clone()))
    }

    fn only_send(outs: &[Out]) -> Frame {
        outs.iter()
            .find_map(|o| match o {
                Out::Send(f) => Some(f.clone()),
                _ => None,
            })
            .expect("a Send output")
    }

    fn find_sas(outs: &[Out]) -> String {
        outs.iter()
            .find_map(|o| match o {
                Out::SasReady(s) => Some(s.clone()),
                _ => None,
            })
            .expect("a SasReady output")
    }

    /// Drive a full handshake between a fresh Initiator/Responder pair up to the
    /// point just after Handshake3 is delivered, returning the responder's
    /// output for that step plus both drivers.
    fn handshake(
        kind: SessionKind,
        nonce: [u8; 16],
        session_id: SessionId,
        gw: &mut ControlGateway,
    ) -> (Initiator, Responder, Vec<Out>) {
        let comp = KeyPair::generate();
        let offer = if kind == SessionKind::Pairing {
            Some(nonce)
        } else {
            None
        };
        let mut resp = Responder::new(comp, session_id, offer);
        let (mut init, ch) = Initiator::new(browser_kp(), kind, nonce, None);
        let outs = resp.on_frame(&ch, gw).unwrap();
        let sh = only_send(&outs);
        let h1 = init.on_server_hello(&sh).unwrap();
        let outs = resp.on_frame(&h1, gw).unwrap();
        let h2 = only_send(&outs);
        let h3 = init.on_handshake2(&h2).unwrap();
        let outs = resp.on_frame(&h3, gw).unwrap();
        (init, resp, outs)
    }

    fn full_scopes() -> BTreeSet<Scope> {
        [Scope::RoomRead, Scope::MessageSend].into_iter().collect()
    }

    /// Pair the browser key into the gateway for room "room-1" with both scopes.
    fn pair(gw: &mut ControlGateway) {
        let (mut init, mut resp, outs) = handshake(SessionKind::Pairing, OFFER, 1, gw);
        // Both sides derive the same SAS.
        assert_eq!(init.sas().unwrap(), find_sas(&outs));
        // Browser confirms.
        let pc = init.pair_confirm().unwrap();
        let outs = resp.on_frame(&pc, gw).unwrap();
        assert!(outs.is_empty(), "no install before companion-local confirm");
        // Companion confirms on its trusted surface.
        let rooms: BTreeSet<String> = ["room-1".to_string()].into_iter().collect();
        let outs = resp
            .confirm_pairing(gw, full_scopes(), rooms, DEFAULT_LIFETIME_TEST())
            .unwrap();
        let pr = init.read(&only_send(&outs)).unwrap();
        assert!(matches!(
            pr,
            Msg::PairResult {
                installed: true,
                ..
            }
        ));
        assert!(gw.contains(&browser_key()));
    }

    #[allow(non_snake_case)]
    fn DEFAULT_LIFETIME_TEST() -> Duration {
        Duration::from_secs(30 * 24 * 3600)
    }

    /// Establish a control session with the (already-installed) browser key.
    fn control(gw: &mut ControlGateway, session_id: SessionId) -> (Initiator, Responder, Msg) {
        let (mut init, resp, outs) = handshake(SessionKind::Control, [0; 16], session_id, gw);
        let msg = init.read(&only_send(&outs)).unwrap();
        (init, resp, msg)
    }

    #[test]
    fn pairing_then_scoped_send_succeeds_end_to_end() {
        let clock = Arc::new(ManualClock::new(1_000));
        let mut gw = gateway(&clock);
        pair(&mut gw);

        let (mut init, mut resp, accept) = control(&mut gw, 2);
        match accept {
            Msg::SessionAccept { methods, .. } => {
                assert!(methods.contains(&jeliya_protocol::method::MESSAGE_SEND));
            }
            other => panic!("expected SessionAccept, got {other:?}"),
        }
        let call = MethodCall::MessageSend {
            room_id: "room-1".into(),
            body: "hi".into(),
            client_msg_id: "c1".into(),
        };
        let req = init
            .request(jeliya_protocol::method::MESSAGE_SEND, &call)
            .unwrap();
        let outs = resp.on_frame(&req, &mut gw).unwrap();
        // The RPC authorized: the driver asks the host to dispatch it.
        let (nonce, dispatched) = match &outs[0] {
            Out::Dispatch { nonce, call } => (*nonce, call.clone()),
            other => panic!("expected Dispatch, got {other:?}"),
        };
        assert_eq!(dispatched, call);
        // Host returns the engine result; the driver seals the Response.
        let outs = resp
            .complete_dispatch(nonce, Ok(b"{\"event_id\":\"e9\"}".to_vec()))
            .unwrap();
        let resp_msg = init.read(&only_send(&outs)).unwrap();
        assert!(matches!(resp_msg, Msg::Response { ok: true, .. }));
    }

    // ---- The four fail-closed gate assertions ---------------------------

    #[test]
    fn replayed_nonce_fails_closed() {
        let clock = Arc::new(ManualClock::new(1_000));
        let mut gw = gateway(&clock);
        pair(&mut gw);
        let (mut init, mut resp, _accept) = control(&mut gw, 2);
        let call = MethodCall::RoomMembers {
            room_id: "room-1".into(),
        };
        let req = init
            .request_with_nonce(1, jeliya_protocol::method::ROOM_MEMBERS, &call)
            .unwrap();
        // First use authorizes (Dispatch).
        assert!(matches!(
            resp.on_frame(&req, &mut gw).unwrap()[0],
            Out::Dispatch { .. }
        ));
        // Encrypting the same nonce again requires a fresh transport frame (the
        // Noise counter differs); build a new frame with nonce 1 reused.
        let replay = init
            .request_with_nonce(1, jeliya_protocol::method::ROOM_MEMBERS, &call)
            .unwrap();
        let outs = resp.on_frame(&replay, &mut gw).unwrap();
        let msg = init.read(&only_send(&outs)).unwrap();
        assert_error(&msg, jeliya_protocol::error::DENIED_REPLAY);
    }

    #[test]
    fn wrong_sas_yields_no_installed_key() {
        let clock = Arc::new(ManualClock::new(1_000));
        let mut gw = gateway(&clock);
        let (_init, mut resp, _outs) = handshake(SessionKind::Pairing, OFFER, 1, &mut gw);
        // The companion user compared the SAS, saw a mismatch, and aborted.
        let outs = resp.abort_pairing().unwrap();
        let closed = outs.iter().any(|o| matches!(o, Out::Close));
        assert!(closed);
        assert!(!gw.contains(&browser_key()), "wrong SAS installs nothing");
    }

    #[test]
    fn expired_key_admission_fails_closed() {
        let clock = Arc::new(ManualClock::new(1_000));
        let mut gw = gateway(&clock);
        pair(&mut gw);
        // Jump past the 30-day lifetime.
        clock.advance(31 * 24 * 3600 * 1000);
        let (mut init, _resp, msg) = control(&mut gw, 2);
        match msg {
            Msg::SessionReject { reason } => {
                assert_eq!(reason, jeliya_protocol::reject::EXPIRED);
            }
            other => panic!("expected SessionReject(expired), got {other:?}"),
        }
        let _ = &mut init;
    }

    #[test]
    fn revoked_key_admission_fails_closed() {
        let clock = Arc::new(ManualClock::new(1_000));
        let mut gw = gateway(&clock);
        pair(&mut gw);
        let torn = gw.revoke(&browser_key());
        assert!(torn.is_empty(), "no live control session yet");
        let (_init, _resp, msg) = control(&mut gw, 2);
        assert!(matches!(
            msg,
            Msg::SessionReject {
                reason
            } if reason == jeliya_protocol::reject::REVOKED
        ));
    }

    // ---- Scope / room / method / version ---------------------------------

    #[test]
    fn scope_and_room_are_default_deny() {
        let clock = Arc::new(ManualClock::new(1_000));
        let mut gw = gateway(&clock);
        // Pair with ONLY room.read on room-1.
        let (mut init, mut resp, outs) = handshake(SessionKind::Pairing, OFFER, 1, &mut gw);
        assert_eq!(init.sas().unwrap(), find_sas(&outs));
        let pc = init.pair_confirm().unwrap();
        resp.on_frame(&pc, &mut gw).unwrap();
        let rooms: BTreeSet<String> = ["room-1".to_string()].into_iter().collect();
        let read_only: BTreeSet<Scope> = [Scope::RoomRead].into_iter().collect();
        let outs = resp
            .confirm_pairing(&mut gw, read_only, rooms, DEFAULT_LIFETIME_TEST())
            .unwrap();
        init.read(&only_send(&outs)).unwrap();

        let (mut init, mut resp, _accept) = control(&mut gw, 2);
        // message.send is out of scope.
        let send = MethodCall::MessageSend {
            room_id: "room-1".into(),
            body: "x".into(),
            client_msg_id: "c".into(),
        };
        let req = init
            .request(jeliya_protocol::method::MESSAGE_SEND, &send)
            .unwrap();
        let outs = resp.on_frame(&req, &mut gw).unwrap();
        assert_error(
            &init.read(&only_send(&outs)).unwrap(),
            jeliya_protocol::error::DENIED_SCOPE,
        );
        // room.read on a room NOT granted is denied.
        let read_other = MethodCall::RoomMembers {
            room_id: "room-2".into(),
        };
        let req = init
            .request(jeliya_protocol::method::ROOM_MEMBERS, &read_other)
            .unwrap();
        let outs = resp.on_frame(&req, &mut gw).unwrap();
        assert_error(
            &init.read(&only_send(&outs)).unwrap(),
            jeliya_protocol::error::DENIED_ROOM,
        );
    }

    #[test]
    fn incompatible_version_closes_before_handshake() {
        let clock = Arc::new(ManualClock::new(1_000));
        let mut gw = gateway(&clock);
        let comp = KeyPair::generate();
        let mut resp = Responder::new(comp, 1, None);
        // A client offering only version 0 (never valid) gets an incompatible
        // ServerHello and a close.
        let hello = ClientHello {
            versions: vec![9],
            session_kind: SessionKind::Control,
            pairing_nonce: [0; 16],
        };
        let outs = resp.on_frame(&hello.to_frame().unwrap(), &mut gw).unwrap();
        let sh = ServerHello::decode_body(&only_send(&outs).body).unwrap();
        assert!(sh.is_incompatible());
        assert!(outs.iter().any(|o| matches!(o, Out::Close)));
    }

    #[test]
    fn initiator_pins_the_companion_key_and_aborts_on_substitution() {
        let clock = Arc::new(ManualClock::new(1_000));
        let mut gw = gateway(&clock);
        // A control session whose initiator pins a companion key that will NOT
        // match the responder's actual (fresh) static key: the handshake aborts
        // at message 2, before any transport frame.
        let comp = KeyPair::generate();
        let mut resp = Responder::new(comp, 1, None);
        let wrong_pin = [0xAB; 32];
        let (mut init, ch) =
            Initiator::new(browser_kp(), SessionKind::Control, [0; 16], Some(wrong_pin));
        let outs = resp.on_frame(&ch, &mut gw).unwrap();
        let h1 = init.on_server_hello(&only_send(&outs)).unwrap();
        let outs = resp.on_frame(&h1, &mut gw).unwrap();
        let h2 = only_send(&outs);
        assert_eq!(
            init.on_handshake2(&h2),
            Err(SessionError::Unexpected("companion key pin mismatch"))
        );
    }

    #[test]
    fn initiator_learns_then_pins_the_real_companion_key() {
        let clock = Arc::new(ManualClock::new(1_000));
        let mut gw = gateway(&clock);
        // Learn the companion key over one handshake…
        let comp = KeyPair::generate();
        let comp_pub = comp.public();
        let mut resp = Responder::new(comp, 1, Some(OFFER));
        let (mut init, ch) = Initiator::new(browser_kp(), SessionKind::Pairing, OFFER, None);
        let outs = resp.on_frame(&ch, &mut gw).unwrap();
        let h1 = init.on_server_hello(&only_send(&outs)).unwrap();
        let outs = resp.on_frame(&h1, &mut gw).unwrap();
        init.on_handshake2(&only_send(&outs)).unwrap();
        // …and it matches the responder's actual static key, ready to pin next time.
        assert_eq!(init.companion_key(), Some(comp_pub));
    }

    #[test]
    fn revocation_tears_down_a_live_session() {
        let clock = Arc::new(ManualClock::new(1_000));
        let mut gw = gateway(&clock);
        pair(&mut gw);
        // Open a live control session (registers session id 7).
        let (_init, _resp, _accept) = control(&mut gw, 7);
        let torn = gw.revoke(&browser_key());
        assert_eq!(
            torn,
            vec![7],
            "revoke returns the live session to tear down"
        );
    }

    #[test]
    fn persistence_round_trip_keeps_the_key_usable() {
        let clock = Arc::new(ManualClock::new(1_000));
        let mut gw = gateway(&clock);
        pair(&mut gw);
        let json = gw.snapshot_json();
        // A fresh gateway (a restart) loads the store and still admits the key.
        let mut gw2 = gateway(&clock);
        assert_eq!(gw2.load_persisted(&json).unwrap(), 1);
        assert!(gw2.admit_session(&browser_key()).is_ok());
    }

    fn assert_error(msg: &Msg, code: u16) {
        match msg {
            Msg::Response {
                ok: false, body, ..
            } => {
                let (got, _) = Msg::decode_error_body(body).unwrap();
                assert_eq!(
                    got,
                    code,
                    "expected error {}",
                    jeliya_protocol::error_name(code)
                );
            }
            other => panic!("expected error Response, got {other:?}"),
        }
    }
}
