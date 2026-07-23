//! The Iroh control-ALPN binding: the thin layer that gives the transport-
//! agnostic [`serve_connection`] runtime a real socket. It creates a dedicated
//! Iroh [`Endpoint`] with a stable identity, registers the `/jeliya/control/1`
//! ALPN, and per accepted connection runs one control session over the QUIC
//! bidirectional stream, framed exactly like the in-memory duplex the runtime
//! tests use.
//!
//! Two keys, deliberately distinct:
//! - the **Iroh endpoint secret** (Ed25519) is only transport addressing — the
//!   dialable [`iroh::EndpointId`]. No authorization depends on it; the browser's
//!   iroh identity is ephemeral and proves nothing here.
//! - the **Noise static secret** (X25519) is the companion's long-lived pairing
//!   identity — the key in the QR fingerprint, authenticated in the XX
//!   handshake and pinned by the browser.
//!
//! The handshake-tier rate limit is the one control keyed off the
//! (unauthenticated) remote iroh id; it can only deny service.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::{presets, Connection, RecvStream, SendStream};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use iroh::{Endpoint, EndpointAddr, RelayMode, SecretKey, TransportAddr};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use jeliya_control::{Clock, ControlGateway, ControlKey, HandshakeLimiter, KeyPair, SystemClock};
use jeliya_protocol::{Frame, ALPN};

use crate::channel::{frame_from_parts, parse_header, BoxFuture, ChannelError, FrameChannel};
use crate::connection::{serve_connection, Revocations};
use crate::dispatch::{ControlDispatch, ControlPolicy};
use crate::offers::{companion_fingerprint, Offer, PairingOffers};

/// The relay posture of the control endpoint. Production relay-auth (a dedicated
/// relay with endpoint-bound tokens) is a deferred decision (issue #49); until
/// it lands the choices are direct-only (loopback/LAN) or n0's default relays.
#[derive(Clone, Copy, Debug)]
pub enum RelayConfig {
    /// No relay — direct connectivity only (loopback, LAN, or hole-punched).
    Direct,
    /// n0's default relay infrastructure (for NAT-separated peers).
    N0Default,
}

impl RelayConfig {
    fn to_mode(self) -> RelayMode {
        match self {
            RelayConfig::Direct => RelayMode::Disabled,
            RelayConfig::N0Default => RelayMode::Default,
        }
    }
}

/// A [`FrameChannel`] over an Iroh QUIC bidirectional stream. Frames bytes the
/// same way the in-memory [`crate::DuplexChannel`] does.
struct IrohChannel {
    send: SendStream,
    recv: RecvStream,
}

impl FrameChannel for IrohChannel {
    fn read_frame(&mut self) -> BoxFuture<'_, Result<Frame, ChannelError>> {
        Box::pin(async move {
            let mut header = [0u8; 5];
            self.recv
                .read_exact(&mut header)
                .await
                .map_err(|e| ChannelError::Io(e.to_string()))?;
            let (len, tag) = parse_header(&header)?;
            let mut body = vec![0u8; len];
            self.recv
                .read_exact(&mut body)
                .await
                .map_err(|e| ChannelError::Io(e.to_string()))?;
            frame_from_parts(tag, body)
        })
    }

    fn write_frame(&mut self, frame: Frame) -> BoxFuture<'_, Result<(), ChannelError>> {
        Box::pin(async move {
            let bytes = frame.encode()?;
            self.send
                .write_all(&bytes)
                .await
                .map_err(|e| ChannelError::Io(e.to_string()))
        })
    }

    fn close(&mut self) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            // Finish the send stream (FIN + flush the final frame), then wait
            // (bounded) for the peer to stop it — the delivery barrier — before
            // the Connection drops and would reset an unacknowledged stream.
            let _ = self.send.finish();
            let _ = tokio::time::timeout(Duration::from_secs(3), self.send.stopped()).await;
        })
    }
}

/// Shared state every connection task reads.
struct ControlState {
    noise_static_secret: Zeroizing<[u8; 32]>,
    noise_static_public: [u8; 32],
    gateway: Arc<Mutex<ControlGateway>>,
    offers: Arc<Mutex<PairingOffers>>,
    revocations: Revocations,
    dispatch: Arc<dyn ControlDispatch>,
    policy: Arc<dyn ControlPolicy>,
    handshake_limiter: Arc<Mutex<HandshakeLimiter>>,
    clock: Arc<dyn Clock>,
    next_session_id: AtomicU64,
}

/// The Iroh ProtocolHandler for the control ALPN.
#[derive(Clone)]
struct ControlProtocol {
    state: Arc<ControlState>,
}

impl std::fmt::Debug for ControlProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ControlProtocol")
    }
}

impl ProtocolHandler for ControlProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let st = &self.state;
        let now = st.clock.now_ms();

        // Handshake-tier rate limit, keyed by the (unauthenticated) remote iroh
        // id. On denial, drop the connection (returning closes it).
        let remote = *conn.remote_id().as_bytes();
        if !st.handshake_limiter.lock().await.allow(remote, now) {
            return Ok(());
        }

        // Bound the wait for the first stream: a peer that consumes a handshake
        // token but never opens a stream is dropped, not leaked.
        let (send, recv) =
            match tokio::time::timeout(Duration::from_secs(10), conn.accept_bi()).await {
                Ok(Ok(streams)) => streams,
                _ => return Ok(()),
            };
        let chan = IrohChannel { send, recv };
        let session_id = st.next_session_id.fetch_add(1, Ordering::SeqCst);
        // Clone the Zeroizing secret directly (no plain [u8;32] stack temporary).
        let static_key = KeyPair::from_secret(st.noise_static_secret.clone());
        let notify = st.revocations.register(session_id).await;

        // The driver atomically claims the pairing offer at the first
        // ClientHello (single-use), sampling the clock then.
        serve_connection(
            chan,
            static_key,
            session_id,
            st.offers.clone(),
            st.clock.clone(),
            st.gateway.clone(),
            st.dispatch.clone(),
            st.policy.clone(),
            notify,
        )
        .await;

        st.revocations.deregister(session_id).await;
        Ok(())
    }
}

/// A bound control endpoint: the Iroh socket + router serving the control ALPN,
/// plus the pairing-offer and revocation surface the companion drives.
pub struct ControlEndpoint {
    endpoint: Endpoint,
    _router: Router,
    state: Arc<ControlState>,
}

impl ControlEndpoint {
    /// Bind the control endpoint. `iroh_secret` is the stable Ed25519 endpoint
    /// seed (its dialable identity); `noise_secret` is the companion's Noise
    /// static X25519 pairing-identity secret. The gateway, dispatch, and policy
    /// are the shared control surface.
    pub async fn bind(
        iroh_secret: [u8; 32],
        noise_secret: [u8; 32],
        relay: RelayConfig,
        gateway: Arc<Mutex<ControlGateway>>,
        dispatch: Arc<dyn ControlDispatch>,
        policy: Arc<dyn ControlPolicy>,
    ) -> Result<Self, iroh::endpoint::BindError> {
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let now = clock.now_ms();
        let noise_static_public = KeyPair::from_secret(Zeroizing::new(noise_secret)).public();

        let endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&iroh_secret))
            .relay_mode(relay.to_mode())
            .bind()
            .await?;
        // Wait until the endpoint has advertised its reachable paths, so a QR /
        // link built from `addr()` right after `bind` is actually dialable
        // (otherwise the first pairing attempt can fail to connect, especially
        // with a relay).
        endpoint.online().await;

        let state = Arc::new(ControlState {
            noise_static_secret: Zeroizing::new(noise_secret),
            noise_static_public,
            gateway,
            offers: Arc::new(Mutex::new(PairingOffers::new())),
            revocations: Revocations::new(),
            dispatch,
            policy,
            handshake_limiter: Arc::new(Mutex::new(HandshakeLimiter::new(now))),
            clock,
            next_session_id: AtomicU64::new(1),
        });

        let router = Router::builder(endpoint.clone())
            .accept(
                ALPN,
                ControlProtocol {
                    state: state.clone(),
                },
            )
            .spawn();

        Ok(Self {
            endpoint,
            _router: router,
            state,
        })
    }

    /// The dialable address (endpoint id + reachable paths) to place in the QR /
    /// custom-protocol link.
    #[must_use]
    pub fn addr(&self) -> EndpointAddr {
        self.endpoint.addr()
    }

    /// The dialable address as plain strings for a host rendering the QR /
    /// link surface: the endpoint id plus each reachable transport address, in
    /// iroh's own `Display` forms (parseable back by an iroh dialer). Keeps
    /// hosts from needing an iroh dependency just to print an offer.
    #[must_use]
    pub fn addr_strings(&self) -> (String, Vec<String>) {
        let addr = self.endpoint.addr();
        let addrs = addr
            .addrs
            .iter()
            .filter_map(|transport| match transport {
                TransportAddr::Ip(sock) => Some(sock.to_string()),
                TransportAddr::Relay(url) => Some(url.to_string()),
                _ => None,
            })
            .collect();
        (addr.id.to_string(), addrs)
    }

    /// The companion static-key fingerprint (SHA-256(noise static)[0..8]) for
    /// the QR / link, which the browser pins before the SAS.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 8] {
        companion_fingerprint(&self.state.noise_static_public)
    }

    /// Open a new single-use pairing offer, or `None` if one is already
    /// outstanding. The returned rendezvous nonce goes in the QR / link.
    pub async fn open_offer(&self) -> Option<Offer> {
        let now = self.state.clock.now_ms();
        self.state.offers.lock().await.open(now)
    }

    /// Revoke a control key immediately and tear down every live session bound
    /// to it.
    pub async fn revoke(&self, key: &ControlKey) {
        self.state
            .revocations
            .revoke(&self.state.gateway, key)
            .await;
    }

    /// Close the endpoint (best-effort).
    pub async fn shutdown(self) {
        self.endpoint.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::time::Duration;

    use zeroize::Zeroizing;

    use jeliya_control::{ControlKey, Initiator, KeyPair, Scope};
    use jeliya_protocol::{Msg, SessionKind};

    use crate::dispatch::PairingDecision;

    struct OkDispatch;
    impl ControlDispatch for OkDispatch {
        fn dispatch(
            &self,
            _call: jeliya_protocol::MethodCall,
        ) -> BoxFuture<'_, Result<Vec<u8>, String>> {
            Box::pin(async move { Ok(b"{}".to_vec()) })
        }
    }

    struct ApproveAll;
    impl ControlPolicy for ApproveAll {
        fn confirm_pairing(&self, _sas: &str) -> BoxFuture<'_, PairingDecision> {
            Box::pin(async move {
                PairingDecision::Approve {
                    scopes: [Scope::RoomRead].into_iter().collect::<BTreeSet<_>>(),
                    rooms: ["room-1".to_string()].into_iter().collect(),
                    lifetime: Duration::from_secs(30 * 24 * 3600),
                }
            })
        }
    }

    /// A full pairing ceremony over a real loopback Iroh connection. `#[ignore]`d
    /// because direct-UDP loopback is not reliable in every sandbox/CI; run it
    /// with `cargo test -p jeliya-companion -- --ignored` on a normal host. The
    /// CI coverage of the same protocol runs over the in-memory duplex in
    /// `crate::tests`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires direct-UDP loopback connectivity"]
    async fn loopback_pairing_over_iroh() {
        let browser_secret = [5u8; 32];
        let noise_secret = [7u8; 32];
        let browser_control_key =
            ControlKey(KeyPair::from_secret(Zeroizing::new(browser_secret)).public());

        let gateway = Arc::new(Mutex::new(ControlGateway::new()));
        let companion = ControlEndpoint::bind(
            [1u8; 32],
            noise_secret,
            RelayConfig::Direct,
            gateway.clone(),
            Arc::new(OkDispatch),
            Arc::new(ApproveAll),
        )
        .await
        .expect("bind companion");
        let offer = companion.open_offer().await.expect("offer opens");
        let addr = companion.addr();

        // Browser-side iroh endpoint dials the companion's control ALPN.
        let client = Endpoint::builder(presets::Minimal)
            .secret_key(SecretKey::from_bytes(&[3u8; 32]))
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .expect("bind client");
        let conn = client.connect(addr, ALPN).await.expect("connect");
        let (send, recv) = conn.open_bi().await.expect("open_bi");
        let mut chan = IrohChannel { send, recv };

        let (mut init, ch) = Initiator::new(
            KeyPair::from_secret(Zeroizing::new(browser_secret)),
            SessionKind::Pairing,
            offer.nonce,
            None,
        );
        chan.write_frame(ch).await.unwrap();
        let sh = chan.read_frame().await.unwrap();
        let h1 = init.on_server_hello(&sh).unwrap();
        chan.write_frame(h1).await.unwrap();
        let h2 = chan.read_frame().await.unwrap();
        let h3 = init.on_handshake2(&h2).unwrap();
        chan.write_frame(h3).await.unwrap();
        let pc = init.pair_confirm().unwrap();
        chan.write_frame(pc).await.unwrap();
        let pr = init.read(&chan.read_frame().await.unwrap()).unwrap();
        assert!(matches!(
            pr,
            Msg::PairResult {
                installed: true,
                ..
            }
        ));

        // The key is installed in the shared gateway.
        assert!(gateway.lock().await.contains(&browser_control_key));
    }
}
