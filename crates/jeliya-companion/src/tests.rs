//! End-to-end runtime tests: run the companion [`serve_connection`] against the
//! reference `jeliya_control::Initiator` over an in-memory Tokio duplex, driving
//! the full pairing ceremony and a scoped control session with no socket. This
//! exercises the async driver, the atomic single-use offer claim, the
//! policy/dispatch seams, and revocation teardown deterministically in CI; the
//! Iroh binding reuses the same driver over a QUIC stream.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use zeroize::Zeroizing;

use jeliya_control::{ControlGateway, ControlKey, Initiator, KeyPair, ManualClock, Scope};
use jeliya_protocol::{method, MethodCall, Msg, SessionKind};

use crate::channel::{DuplexChannel, FrameChannel};
use crate::connection::{serve_connection, Revocations};
use crate::dispatch::{ControlDispatch, ControlPolicy, PairingDecision};
use crate::offers::PairingOffers;

const COMPANION_SECRET: [u8; 32] = [7u8; 32];
const BROWSER_SECRET: [u8; 32] = [5u8; 32];
const NOW: u64 = 1_000;

fn companion_key() -> KeyPair {
    KeyPair::from_secret(Zeroizing::new(COMPANION_SECRET))
}
fn browser_key() -> KeyPair {
    KeyPair::from_secret(Zeroizing::new(BROWSER_SECRET))
}
fn browser_control_key() -> ControlKey {
    ControlKey(browser_key().public())
}

type Offers = Arc<Mutex<PairingOffers>>;

async fn open_offer() -> (Offers, [u8; 16]) {
    let offers: Offers = Arc::new(Mutex::new(PairingOffers::new()));
    let nonce = offers.lock().await.open(NOW).unwrap().nonce;
    (offers, nonce)
}
fn empty_offers() -> Offers {
    Arc::new(Mutex::new(PairingOffers::new()))
}
fn notify() -> Arc<tokio::sync::Notify> {
    Arc::new(tokio::sync::Notify::new())
}
fn test_clock() -> Arc<dyn jeliya_control::Clock> {
    // `Clock` is implemented for `Arc<ManualClock>`, so wrap once more to get an
    // `Arc<dyn Clock>` fixed at NOW (matching the offers' created_at).
    Arc::new(Arc::new(ManualClock::new(NOW)))
}

/// A dispatch that echoes a fixed result and records the calls it received.
struct FakeDispatch {
    calls: Arc<Mutex<Vec<MethodCall>>>,
}
impl ControlDispatch for FakeDispatch {
    fn dispatch(&self, call: MethodCall) -> crate::channel::BoxFuture<'_, Result<Vec<u8>, String>> {
        let calls = self.calls.clone();
        Box::pin(async move {
            calls.lock().await.push(call);
            Ok(b"{\"ok\":true}".to_vec())
        })
    }
}

/// A policy that approves every pairing with a fixed grant.
struct ApprovePolicy {
    seen_sas: Arc<Mutex<Vec<String>>>,
}
impl ControlPolicy for ApprovePolicy {
    fn confirm_pairing(&self, sas: &str) -> crate::channel::BoxFuture<'_, PairingDecision> {
        let seen = self.seen_sas.clone();
        let sas = sas.to_string();
        Box::pin(async move {
            seen.lock().await.push(sas);
            PairingDecision::Approve {
                scopes: [Scope::RoomRead, Scope::MessageSend].into_iter().collect(),
                rooms: ["room-1".to_string()].into_iter().collect(),
                lifetime: Duration::from_secs(30 * 24 * 3600),
            }
        })
    }
}

/// A policy that rejects every pairing (wrong-SAS / user declines).
struct RejectPolicy;
impl ControlPolicy for RejectPolicy {
    fn confirm_pairing(&self, _sas: &str) -> crate::channel::BoxFuture<'_, PairingDecision> {
        Box::pin(async move { PairingDecision::Reject })
    }
}

/// Drive the browser side of a pairing ceremony over `chan`.
async fn browser_pair(
    chan: &mut DuplexChannel<tokio::io::DuplexStream>,
    offer_nonce: [u8; 16],
) -> Msg {
    browser_pair_as(chan, BROWSER_SECRET, offer_nonce).await
}

/// Drive a pairing ceremony with a specific browser identity.
async fn browser_pair_as(
    chan: &mut DuplexChannel<tokio::io::DuplexStream>,
    secret: [u8; 32],
    offer_nonce: [u8; 16],
) -> Msg {
    let bk = KeyPair::from_secret(Zeroizing::new(secret));
    let (mut init, ch) = Initiator::new(bk, SessionKind::Pairing, offer_nonce, None);
    chan.write_frame(ch).await.unwrap();
    let sh = chan.read_frame().await.unwrap();
    let h1 = init.on_server_hello(&sh).unwrap();
    chan.write_frame(h1).await.unwrap();
    let h2 = chan.read_frame().await.unwrap();
    let h3 = init.on_handshake2(&h2).unwrap();
    chan.write_frame(h3).await.unwrap();
    let pc = init.pair_confirm().unwrap();
    // A rejecting companion may close its read half the instant it decides to
    // reject — before it consumes our pair-confirm frame — so this write can
    // lose a race with that teardown and surface a broken pipe (flaky under a
    // loaded scheduler, e.g. CI). Tolerate it: the companion has already queued
    // the rejection PairResult, which the read below still returns. On the
    // accept path the companion reads pc and this write succeeds normally.
    let _ = chan.write_frame(pc).await;
    let pr = chan.read_frame().await.unwrap();
    init.read(&pr).unwrap()
}

fn gateway_with_clock() -> (Arc<ManualClock>, Arc<Mutex<ControlGateway>>) {
    let clock = Arc::new(ManualClock::new(NOW));
    let gw = Arc::new(Mutex::new(ControlGateway::with_clock(Box::new(
        clock.clone(),
    ))));
    (clock, gw)
}

fn approve_policy() -> (Arc<ApprovePolicy>, Arc<Mutex<Vec<String>>>) {
    let seen = Arc::new(Mutex::new(Vec::new()));
    (
        Arc::new(ApprovePolicy {
            seen_sas: seen.clone(),
        }),
        seen,
    )
}

fn fake_dispatch() -> (Arc<FakeDispatch>, Arc<Mutex<Vec<MethodCall>>>) {
    let calls = Arc::new(Mutex::new(Vec::new()));
    (
        Arc::new(FakeDispatch {
            calls: calls.clone(),
        }),
        calls,
    )
}

/// Pair the browser key into `gw`, returning once installed.
async fn pair_into(gw: &Arc<Mutex<ControlGateway>>, dispatch: Arc<dyn ControlDispatch>) {
    let (policy, _seen) = approve_policy();
    let (offers, nonce) = open_offer().await;
    let (c_io, b_io) = tokio::io::duplex(64 * 1024);
    let companion = tokio::spawn(serve_connection(
        DuplexChannel::new(c_io),
        companion_key(),
        1,
        offers,
        test_clock(),
        gw.clone(),
        dispatch,
        policy as Arc<dyn ControlPolicy>,
        notify(),
    ));
    let mut browser = DuplexChannel::new(b_io);
    browser_pair(&mut browser, nonce).await;
    drop(browser);
    companion.await.unwrap();
}

async fn open_control_session(
    browser: &mut DuplexChannel<tokio::io::DuplexStream>,
    init: &mut Initiator,
) -> Msg {
    let sh = browser.read_frame().await.unwrap();
    let h1 = init.on_server_hello(&sh).unwrap();
    browser.write_frame(h1).await.unwrap();
    let h2 = browser.read_frame().await.unwrap();
    let h3 = init.on_handshake2(&h2).unwrap();
    browser.write_frame(h3).await.unwrap();
    init.read(&browser.read_frame().await.unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pairing_installs_the_key_over_a_duplex() {
    let (_clock, gw) = gateway_with_clock();
    let (dispatch, _calls) = fake_dispatch();
    let (policy, seen) = approve_policy();
    let (offers, nonce) = open_offer().await;

    let (c_io, b_io) = tokio::io::duplex(64 * 1024);
    let companion = tokio::spawn(serve_connection(
        DuplexChannel::new(c_io),
        companion_key(),
        1,
        offers.clone(),
        test_clock(),
        gw.clone(),
        dispatch as Arc<dyn ControlDispatch>,
        policy as Arc<dyn ControlPolicy>,
        notify(),
    ));

    let mut browser = DuplexChannel::new(b_io);
    match browser_pair(&mut browser, nonce).await {
        Msg::PairResult { installed, .. } => assert!(installed, "pairing installs the key"),
        other => panic!("expected PairResult, got {other:?}"),
    }
    drop(browser);
    companion.await.unwrap();

    assert!(gw.lock().await.contains(&browser_control_key()));
    assert_eq!(seen.lock().await.len(), 1, "the policy saw one SAS");
    // The single-use offer was spent by the ceremony.
    assert!(
        !offers.lock().await.is_busy(NOW),
        "the offer slot is released after the ceremony"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_session_dispatches_a_scoped_send() {
    let (_clock, gw) = gateway_with_clock();
    let (dispatch, calls) = fake_dispatch();
    pair_into(&gw, dispatch.clone() as Arc<dyn ControlDispatch>).await;

    let (c_io, b_io) = tokio::io::duplex(64 * 1024);
    let companion = tokio::spawn(serve_connection(
        DuplexChannel::new(c_io),
        companion_key(),
        2,
        empty_offers(),
        test_clock(),
        gw.clone(),
        dispatch as Arc<dyn ControlDispatch>,
        Arc::new(RejectPolicy) as Arc<dyn ControlPolicy>,
        notify(),
    ));

    let mut browser = DuplexChannel::new(b_io);
    let (mut init, ch) = Initiator::new(
        browser_key(),
        SessionKind::Control,
        [0; 16],
        Some(companion_key().public()),
    );
    browser.write_frame(ch).await.unwrap();
    let accept = open_control_session(&mut browser, &mut init).await;
    assert!(matches!(accept, Msg::SessionAccept { .. }));

    let call = MethodCall::MessageSend {
        room_id: "room-1".into(),
        body: "hi".into(),
        client_msg_id: "c1".into(),
    };
    let req = init.request(method::MESSAGE_SEND, &call).unwrap();
    browser.write_frame(req).await.unwrap();
    match init.read(&browser.read_frame().await.unwrap()).unwrap() {
        Msg::Response { ok, .. } => assert!(ok, "the scoped send is authorized and dispatched"),
        other => panic!("expected Response, got {other:?}"),
    }
    drop(browser);
    companion.await.unwrap();

    let seen = calls.lock().await;
    assert_eq!(seen.len(), 1);
    assert!(matches!(&seen[0], MethodCall::MessageSend { room_id, .. } if room_id == "room-1"));
}

/// A dispatch that returns an oversized result body.
struct HugeDispatch;
impl ControlDispatch for HugeDispatch {
    fn dispatch(
        &self,
        _call: MethodCall,
    ) -> crate::channel::BoxFuture<'_, Result<Vec<u8>, String>> {
        Box::pin(async move { Ok(vec![b'x'; jeliya_protocol::MAX_FRAME_LEN]) })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_dispatch_result_becomes_an_engine_error_not_a_drop() {
    let (_clock, gw) = gateway_with_clock();
    let (dispatch, _calls) = fake_dispatch();
    pair_into(&gw, dispatch as Arc<dyn ControlDispatch>).await;

    let (c_io, b_io) = tokio::io::duplex(256 * 1024);
    let companion = tokio::spawn(serve_connection(
        DuplexChannel::new(c_io),
        companion_key(),
        2,
        empty_offers(),
        test_clock(),
        gw.clone(),
        Arc::new(HugeDispatch) as Arc<dyn ControlDispatch>,
        Arc::new(RejectPolicy) as Arc<dyn ControlPolicy>,
        notify(),
    ));
    let mut browser = DuplexChannel::new(b_io);
    let (mut init, ch) = Initiator::new(
        browser_key(),
        SessionKind::Control,
        [0; 16],
        Some(companion_key().public()),
    );
    browser.write_frame(ch).await.unwrap();
    open_control_session(&mut browser, &mut init).await;
    let call = MethodCall::RoomMembers {
        room_id: "room-1".into(),
    };
    let req = init.request(method::ROOM_MEMBERS, &call).unwrap();
    browser.write_frame(req).await.unwrap();
    // The huge result is turned into a bounded engine error, delivered as a
    // Response — the browser gets an answer, not a silent connection drop.
    match init.read(&browser.read_frame().await.unwrap()).unwrap() {
        Msg::Response { ok, body, .. } => {
            assert!(!ok, "oversized result → error response");
            let (code, _) = Msg::decode_error_body(&body).unwrap();
            assert_eq!(code, jeliya_protocol::error::ENGINE_ERROR);
        }
        other => panic!("expected error Response, got {other:?}"),
    }
    drop(browser);
    companion.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejected_pairing_installs_nothing() {
    let (_clock, gw) = gateway_with_clock();
    let (dispatch, _calls) = fake_dispatch();
    let (offers, nonce) = open_offer().await;
    let (c_io, b_io) = tokio::io::duplex(64 * 1024);
    let companion = tokio::spawn(serve_connection(
        DuplexChannel::new(c_io),
        companion_key(),
        1,
        offers,
        test_clock(),
        gw.clone(),
        dispatch as Arc<dyn ControlDispatch>,
        Arc::new(RejectPolicy) as Arc<dyn ControlPolicy>,
        notify(),
    ));
    let mut browser = DuplexChannel::new(b_io);
    match browser_pair(&mut browser, nonce).await {
        Msg::PairResult { installed, .. } => {
            assert!(!installed, "rejected pairing installs nothing")
        }
        other => panic!("expected PairResult(installed=false), got {other:?}"),
    }
    drop(browser);
    companion.await.unwrap();
    assert!(!gw.lock().await.contains(&browser_control_key()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_or_missing_offer_rejects_pairing() {
    // No offer is open: a pairing ClientHello with any nonce fails to claim, so
    // the Responder rejects the pairing and nothing installs.
    let (_clock, gw) = gateway_with_clock();
    let (dispatch, _calls) = fake_dispatch();
    let (policy, _seen) = approve_policy();
    let (c_io, b_io) = tokio::io::duplex(64 * 1024);
    let companion = tokio::spawn(serve_connection(
        DuplexChannel::new(c_io),
        companion_key(),
        1,
        empty_offers(), // no live offer
        test_clock(),
        gw.clone(),
        dispatch as Arc<dyn ControlDispatch>,
        policy as Arc<dyn ControlPolicy>,
        notify(),
    ));
    let mut browser = DuplexChannel::new(b_io);
    let (_init, ch) = Initiator::new(browser_key(), SessionKind::Pairing, [0x99; 16], None);
    browser.write_frame(ch).await.unwrap();
    // The unmatched-offer pairing is rejected at the ClientHello (before any
    // ServerHello); the companion closes and installs nothing.
    drop(browser);
    companion.await.unwrap();
    assert!(!gw.lock().await.contains(&browser_control_key()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_use_offer_admits_only_the_first_presenter() {
    // One offer, two connections presenting the SAME nonce with different
    // browser keys. The first ceremony claims (spends) the offer and installs;
    // the second's claim fails (offer already spent), so its pairing is rejected
    // — the interleaved-ceremony race is closed.
    let (_clock, gw) = gateway_with_clock();
    let (dispatch, _calls) = fake_dispatch();
    let (policy, _seen) = approve_policy();
    let (offers, nonce) = open_offer().await;

    let first_secret = [5u8; 32];
    let second_secret = [6u8; 32];
    let first_key = ControlKey(KeyPair::from_secret(Zeroizing::new(first_secret)).public());
    let second_key = ControlKey(KeyPair::from_secret(Zeroizing::new(second_secret)).public());

    // Connection A pairs to completion, spending the offer.
    {
        let (c_io, b_io) = tokio::io::duplex(64 * 1024);
        let companion = tokio::spawn(serve_connection(
            DuplexChannel::new(c_io),
            companion_key(),
            1,
            offers.clone(),
            test_clock(),
            gw.clone(),
            dispatch.clone() as Arc<dyn ControlDispatch>,
            policy.clone() as Arc<dyn ControlPolicy>,
            notify(),
        ));
        let mut browser = DuplexChannel::new(b_io);
        let r = browser_pair_as(&mut browser, first_secret, nonce).await;
        assert!(matches!(
            r,
            Msg::PairResult {
                installed: true,
                ..
            }
        ));
        drop(browser);
        companion.await.unwrap();
    }

    // Connection B presents the SAME (now-spent) nonce: its claim fails and the
    // Responder rejects the pairing before any ceremony.
    {
        let (c_io, b_io) = tokio::io::duplex(64 * 1024);
        let companion = tokio::spawn(serve_connection(
            DuplexChannel::new(c_io),
            companion_key(),
            2,
            offers.clone(),
            test_clock(),
            gw.clone(),
            dispatch as Arc<dyn ControlDispatch>,
            policy as Arc<dyn ControlPolicy>,
            notify(),
        ));
        let mut browser = DuplexChannel::new(b_io);
        let (_init, ch) = Initiator::new(
            KeyPair::from_secret(Zeroizing::new(second_secret)),
            SessionKind::Pairing,
            nonce,
            None,
        );
        browser.write_frame(ch).await.unwrap();
        // Claim fails on the spent nonce → rejected at the ClientHello → closed.
        drop(browser);
        companion.await.unwrap();
    }

    assert!(
        gw.lock().await.contains(&first_key),
        "first presenter installed"
    );
    assert!(
        !gw.lock().await.contains(&second_key),
        "second presenter of a spent nonce installs nothing"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_tears_down_a_live_control_session() {
    let (_clock, gw) = gateway_with_clock();
    let (dispatch, _calls) = fake_dispatch();
    pair_into(&gw, dispatch.clone() as Arc<dyn ControlDispatch>).await;

    let revocations = Revocations::new();
    let notify = revocations.register(2).await;
    let (c_io, b_io) = tokio::io::duplex(64 * 1024);
    let companion = tokio::spawn(serve_connection(
        DuplexChannel::new(c_io),
        companion_key(),
        2,
        empty_offers(),
        test_clock(),
        gw.clone(),
        dispatch as Arc<dyn ControlDispatch>,
        Arc::new(RejectPolicy) as Arc<dyn ControlPolicy>,
        notify,
    ));
    let mut browser = DuplexChannel::new(b_io);
    let (mut init, ch) = Initiator::new(
        browser_key(),
        SessionKind::Control,
        [0; 16],
        Some(companion_key().public()),
    );
    browser.write_frame(ch).await.unwrap();
    let _accept = open_control_session(&mut browser, &mut init).await;

    revocations.revoke(&gw, &browser_control_key()).await;
    tokio::time::timeout(Duration::from_secs(5), companion)
        .await
        .expect("companion tears down promptly")
        .unwrap();
    assert!(gw
        .lock()
        .await
        .admit_session(&browser_control_key())
        .is_err());
}
