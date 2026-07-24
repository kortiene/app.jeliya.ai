//! `Noise_XX_25519_AESGCM_SHA256` — the mutually-authenticated, forward-secret,
//! initiator-identity-hiding handshake ADR #2 decision 2 specifies, implemented
//! directly against the Noise Protocol Framework (rev 34) semantics over the
//! primitives in [`crate::crypto`]. The initiator (browser) and responder
//! (companion) are genuinely separate code paths: a handshake that completes
//! with both sides agreeing on the handshake hash and transport keys is a
//! cross-check between two independent state machines, not one function run
//! twice. The dev-only `snow` interop test additionally validates the wire
//! against a reference implementation.
//!
//! Payloads are empty in v1 (still authenticated), so message sizes are fixed:
//! msg1 = 32 bytes, msg2 = 96 bytes, msg3 = 64 bytes.

use crate::crypto::{
    aead_open, aead_seal, hkdf, sha256, AeadError, KeyPair, DHLEN, HASHLEN, TAGLEN,
};
use zeroize::Zeroizing;

const PROTOCOL_NAME: &[u8] = b"Noise_XX_25519_AESGCM_SHA256";
const ENC_STATIC_LEN: usize = DHLEN + TAGLEN; // encrypted static key field = 48
const EMPTY_PAYLOAD_CT: usize = TAGLEN; // encrypt_and_hash(&[]) once keyed = 16

/// A handshake failure. Every variant aborts the handshake and (at the
/// transport layer) closes the connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoiseError {
    /// An AEAD field failed to authenticate (tamper, wrong key, wrong order).
    Aead,
    /// A handshake message was the wrong length or otherwise malformed.
    BadMessage,
    /// A DH produced the all-zero point (non-contributory / low-order key).
    NonContributoryKey,
    /// A transport cipherstate exhausted its 64-bit nonce (never reached under
    /// the session bounds, but checked rather than wrapped).
    NonceExhausted,
}

impl From<AeadError> for NoiseError {
    fn from(_: AeadError) -> Self {
        NoiseError::Aead
    }
}

/// A keyed AES-GCM cipherstate with an incrementing 64-bit nonce (Noise §5.1).
struct CipherState {
    key: Option<Zeroizing<[u8; HASHLEN]>>,
    nonce: u64,
}

impl CipherState {
    fn empty() -> Self {
        Self {
            key: None,
            nonce: 0,
        }
    }

    fn keyed(key: Zeroizing<[u8; HASHLEN]>) -> Self {
        Self {
            key: Some(key),
            nonce: 0,
        }
    }

    fn encrypt_with_ad(&mut self, ad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        match &self.key {
            None => Ok(plaintext.to_vec()),
            Some(k) => {
                if self.nonce == u64::MAX {
                    return Err(NoiseError::NonceExhausted);
                }
                let ct = aead_seal(k, self.nonce, ad, plaintext);
                self.nonce += 1;
                Ok(ct)
            }
        }
    }

    fn decrypt_with_ad(&mut self, ad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        match &self.key {
            None => Ok(ciphertext.to_vec()),
            Some(k) => {
                if self.nonce == u64::MAX {
                    return Err(NoiseError::NonceExhausted);
                }
                let pt = aead_open(k, self.nonce, ad, ciphertext)?;
                self.nonce += 1;
                Ok(pt)
            }
        }
    }
}

/// The Noise symmetric state: chaining key, handshake hash, and the current
/// handshake cipherstate. The chaining key `ck` is secret — both transport keys
/// are `HKDF(ck, "")` of the *final* `ck` — so it is held in a [`Zeroizing`]
/// buffer that wipes on every reassignment and on drop, upholding the crate's
/// "every secret is wiped" invariant. `h` (the handshake hash) is not secret:
/// it is the SAS display input, returned by `handshake_hash()`.
struct SymmetricState {
    ck: Zeroizing<[u8; HASHLEN]>,
    h: [u8; HASHLEN],
    cs: CipherState,
}

impl SymmetricState {
    fn initialize(prologue: &[u8]) -> Self {
        // protocol_name is 28 bytes < HASHLEN, so h = name ‖ zeros.
        let mut h = [0u8; HASHLEN];
        h[..PROTOCOL_NAME.len()].copy_from_slice(PROTOCOL_NAME);
        let mut sym = Self {
            ck: Zeroizing::new(h),
            h,
            cs: CipherState::empty(),
        };
        sym.mix_hash(prologue);
        sym
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut input = Vec::with_capacity(HASHLEN + data.len());
        input.extend_from_slice(&self.h);
        input.extend_from_slice(data);
        self.h = sha256(&input);
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let out = hkdf(&self.ck, ikm, 2);
        self.ck = out[0].clone();
        self.cs = CipherState::keyed(out[1].clone());
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ct = self.cs.encrypt_with_ad(&self.h, plaintext)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let pt = self.cs.decrypt_with_ad(&self.h, ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    fn split(&self) -> (CipherState, CipherState) {
        let out = hkdf(&self.ck, &[], 2);
        (
            CipherState::keyed(out[0].clone()),
            CipherState::keyed(out[1].clone()),
        )
    }
}

/// The XX handshake state for one party.
pub struct HandshakeState {
    sym: SymmetricState,
    s: KeyPair,
    e: Option<KeyPair>,
    rs: Option<[u8; DHLEN]>,
    re: Option<[u8; DHLEN]>,
    initiator: bool,
}

impl HandshakeState {
    /// Start an initiator (browser) handshake with static key `s`.
    #[must_use]
    pub fn new_initiator(s: KeyPair, prologue: &[u8]) -> Self {
        Self::new(s, prologue, true)
    }

    /// Start a responder (companion) handshake with static key `s`.
    #[must_use]
    pub fn new_responder(s: KeyPair, prologue: &[u8]) -> Self {
        Self::new(s, prologue, false)
    }

    fn new(s: KeyPair, prologue: &[u8], initiator: bool) -> Self {
        Self {
            sym: SymmetricState::initialize(prologue),
            s,
            e: None,
            rs: None,
            re: None,
            initiator,
        }
    }

    fn ephemeral(&mut self) -> &KeyPair {
        if self.e.is_none() {
            self.e = Some(KeyPair::generate());
        }
        self.e.as_ref().unwrap()
    }

    /// The final handshake hash (available after the handshake completes). This
    /// binds the prologue, both static keys, both ephemerals, and every
    /// handshake ciphertext — it is the SAS input.
    #[must_use]
    pub fn handshake_hash(&self) -> [u8; HASHLEN] {
        self.sym.h
    }

    /// The remote static public key learned during the handshake (the browser's
    /// control key on the responder; the companion's pairing identity on the
    /// initiator). `None` before it is received.
    #[must_use]
    pub fn remote_static(&self) -> Option<[u8; DHLEN]> {
        self.rs
    }

    // ---- Initiator ----------------------------------------------------

    /// Initiator writes message 1 (`e`).
    pub fn write_message_1(&mut self) -> Result<Vec<u8>, NoiseError> {
        debug_assert!(self.initiator);
        let epub = self.ephemeral().public();
        self.sym.mix_hash(&epub);
        let mut msg = epub.to_vec();
        msg.extend_from_slice(&self.sym.encrypt_and_hash(&[])?);
        Ok(msg)
    }

    /// Initiator reads message 2 (`e, ee, s, es`).
    pub fn read_message_2(&mut self, msg: &[u8]) -> Result<(), NoiseError> {
        debug_assert!(self.initiator);
        if msg.len() != DHLEN + ENC_STATIC_LEN + EMPTY_PAYLOAD_CT {
            return Err(NoiseError::BadMessage);
        }
        let re: [u8; DHLEN] = msg[..DHLEN].try_into().unwrap();
        self.sym.mix_hash(&re);
        self.re = Some(re);
        // ee
        let e = self.e.as_ref().ok_or(NoiseError::BadMessage)?;
        let ee = e.dh(&re).ok_or(NoiseError::NonContributoryKey)?;
        self.sym.mix_key(&ee[..]);
        // s
        let rs_pt = self
            .sym
            .decrypt_and_hash(&msg[DHLEN..DHLEN + ENC_STATIC_LEN])?;
        let rs: [u8; DHLEN] = rs_pt
            .as_slice()
            .try_into()
            .map_err(|_| NoiseError::BadMessage)?;
        self.rs = Some(rs);
        // es (initiator: DH(e, rs))
        let es = self
            .e
            .as_ref()
            .unwrap()
            .dh(&rs)
            .ok_or(NoiseError::NonContributoryKey)?;
        self.sym.mix_key(&es[..]);
        // payload
        let payload = self.sym.decrypt_and_hash(&msg[DHLEN + ENC_STATIC_LEN..])?;
        if payload.is_empty() {
            Ok(())
        } else {
            Err(NoiseError::BadMessage)
        }
    }

    /// Initiator writes message 3 (`s, se`) and completes, returning the
    /// transport state.
    pub fn write_message_3(
        mut self,
    ) -> Result<(Vec<u8>, TransportState, [u8; HASHLEN]), NoiseError> {
        debug_assert!(self.initiator);
        let re = self.re.ok_or(NoiseError::BadMessage)?;
        // s
        let spub = self.s.public();
        let mut msg = self.sym.encrypt_and_hash(&spub)?;
        // se (initiator: DH(s, re))
        let se = self.s.dh(&re).ok_or(NoiseError::NonContributoryKey)?;
        self.sym.mix_key(&se[..]);
        // payload
        msg.extend_from_slice(&self.sym.encrypt_and_hash(&[])?);
        let hh = self.sym.h;
        let transport = TransportState::from_split(self.sym.split(), true);
        Ok((msg, transport, hh))
    }

    // ---- Responder ----------------------------------------------------

    /// Responder reads message 1 (`e`).
    pub fn read_message_1(&mut self, msg: &[u8]) -> Result<(), NoiseError> {
        debug_assert!(!self.initiator);
        if msg.len() != DHLEN {
            return Err(NoiseError::BadMessage);
        }
        let re: [u8; DHLEN] = msg[..DHLEN].try_into().unwrap();
        self.sym.mix_hash(&re);
        self.re = Some(re);
        let payload = self.sym.decrypt_and_hash(&[])?;
        if payload.is_empty() {
            Ok(())
        } else {
            Err(NoiseError::BadMessage)
        }
    }

    /// Responder writes message 2 (`e, ee, s, es`).
    pub fn write_message_2(&mut self) -> Result<Vec<u8>, NoiseError> {
        debug_assert!(!self.initiator);
        let re = self.re.ok_or(NoiseError::BadMessage)?;
        // e
        let epub = self.ephemeral().public();
        self.sym.mix_hash(&epub);
        let mut msg = epub.to_vec();
        // ee
        let ee = self
            .e
            .as_ref()
            .unwrap()
            .dh(&re)
            .ok_or(NoiseError::NonContributoryKey)?;
        self.sym.mix_key(&ee[..]);
        // s
        let spub = self.s.public();
        msg.extend_from_slice(&self.sym.encrypt_and_hash(&spub)?);
        // es (responder: DH(s, re))
        let es = self.s.dh(&re).ok_or(NoiseError::NonContributoryKey)?;
        self.sym.mix_key(&es[..]);
        // payload
        msg.extend_from_slice(&self.sym.encrypt_and_hash(&[])?);
        Ok(msg)
    }

    /// Responder reads message 3 (`s, se`) and completes, returning the
    /// transport state and the browser control key it authenticated.
    pub fn read_message_3(
        mut self,
        msg: &[u8],
    ) -> Result<(TransportState, [u8; DHLEN], [u8; HASHLEN]), NoiseError> {
        debug_assert!(!self.initiator);
        if msg.len() != ENC_STATIC_LEN + EMPTY_PAYLOAD_CT {
            return Err(NoiseError::BadMessage);
        }
        // s
        let rs_pt = self.sym.decrypt_and_hash(&msg[..ENC_STATIC_LEN])?;
        let rs: [u8; DHLEN] = rs_pt
            .as_slice()
            .try_into()
            .map_err(|_| NoiseError::BadMessage)?;
        self.rs = Some(rs);
        // se (responder: DH(e, rs))
        let se = self
            .e
            .as_ref()
            .ok_or(NoiseError::BadMessage)?
            .dh(&rs)
            .ok_or(NoiseError::NonContributoryKey)?;
        self.sym.mix_key(&se[..]);
        // payload
        let payload = self.sym.decrypt_and_hash(&msg[ENC_STATIC_LEN..])?;
        if !payload.is_empty() {
            return Err(NoiseError::BadMessage);
        }
        let hh = self.sym.h;
        let transport = TransportState::from_split(self.sym.split(), false);
        Ok((transport, rs, hh))
    }
}

/// The post-handshake transport state: two cipherstates, one per direction.
pub struct TransportState {
    send: CipherState,
    recv: CipherState,
}

impl TransportState {
    fn from_split(split: (CipherState, CipherState), initiator: bool) -> Self {
        let (cs1, cs2) = split;
        if initiator {
            Self {
                send: cs1,
                recv: cs2,
            }
        } else {
            Self {
                send: cs2,
                recv: cs1,
            }
        }
    }

    /// Encrypt an outbound transport message.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.send.encrypt_with_ad(&[], plaintext)
    }

    /// Decrypt an inbound transport message. A frame that fails here (tamper,
    /// reorder, replay, truncation) aborts the session.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.recv.decrypt_with_ad(&[], ciphertext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256;

    /// Run a full XX handshake between two independent state machines, returning
    /// both transport states, the browser static key the responder learned, and
    /// both handshake hashes.
    fn run_handshake(
        prologue: &[u8],
    ) -> (
        TransportState,
        TransportState,
        [u8; DHLEN],
        [u8; HASHLEN],
        [u8; HASHLEN],
    ) {
        let init_s = KeyPair::generate();
        let resp_s = KeyPair::generate();
        let mut init = HandshakeState::new_initiator(init_s, prologue);
        let mut resp = HandshakeState::new_responder(resp_s, prologue);

        let m1 = init.write_message_1().unwrap();
        resp.read_message_1(&m1).unwrap();
        let m2 = resp.write_message_2().unwrap();
        init.read_message_2(&m2).unwrap();
        let (m3, init_t, init_hh) = init.write_message_3().unwrap();
        let (resp_t, learned_key, resp_hh) = resp.read_message_3(&m3).unwrap();

        (init_t, resp_t, learned_key, init_hh, resp_hh)
    }

    #[test]
    fn handshake_completes_and_hashes_agree() {
        let (_i, _r, _learned, ihh, rhh) = run_handshake(b"prologue");
        assert_eq!(ihh, rhh, "both sides derive the same handshake hash");
    }

    #[test]
    fn responder_learns_the_browser_control_key() {
        let init_s = KeyPair::generate();
        let browser_key = init_s.public();
        let resp_s = KeyPair::generate();
        let mut init = HandshakeState::new_initiator(init_s, b"p");
        let mut resp = HandshakeState::new_responder(resp_s, b"p");
        let m1 = init.write_message_1().unwrap();
        resp.read_message_1(&m1).unwrap();
        let m2 = resp.write_message_2().unwrap();
        init.read_message_2(&m2).unwrap();
        let (m3, _t, _hh) = init.write_message_3().unwrap();
        let (_t2, learned, _hh2) = resp.read_message_3(&m3).unwrap();
        assert_eq!(learned, browser_key);
    }

    #[test]
    fn transport_messages_flow_both_ways() {
        let (mut init_t, mut resp_t, _k, _a, _b) = run_handshake(b"p");
        let ct = init_t.encrypt(b"ping").unwrap();
        assert_eq!(resp_t.decrypt(&ct).unwrap(), b"ping");
        let ct2 = resp_t.encrypt(b"pong").unwrap();
        assert_eq!(init_t.decrypt(&ct2).unwrap(), b"pong");
    }

    #[test]
    fn message_sizes_are_fixed() {
        let init_s = KeyPair::generate();
        let resp_s = KeyPair::generate();
        let mut init = HandshakeState::new_initiator(init_s, b"p");
        let mut resp = HandshakeState::new_responder(resp_s, b"p");
        let m1 = init.write_message_1().unwrap();
        assert_eq!(m1.len(), 32);
        resp.read_message_1(&m1).unwrap();
        let m2 = resp.write_message_2().unwrap();
        assert_eq!(m2.len(), 96);
        init.read_message_2(&m2).unwrap();
        let (m3, _t, _hh) = init.write_message_3().unwrap();
        assert_eq!(m3.len(), 64);
    }

    #[test]
    fn tampered_message_2_fails() {
        let init_s = KeyPair::generate();
        let resp_s = KeyPair::generate();
        let mut init = HandshakeState::new_initiator(init_s, b"p");
        let mut resp = HandshakeState::new_responder(resp_s, b"p");
        let m1 = init.write_message_1().unwrap();
        resp.read_message_1(&m1).unwrap();
        let mut m2 = resp.write_message_2().unwrap();
        // Flip a bit in the encrypted static key: authentication must fail.
        m2[40] ^= 1;
        assert_eq!(init.read_message_2(&m2), Err(NoiseError::Aead));
    }

    #[test]
    fn different_prologues_break_the_handshake() {
        // The prologue carries the D6 hellos; a downgrade edit changes it and
        // the handshake fails at the first authenticated field.
        let init_s = KeyPair::generate();
        let resp_s = KeyPair::generate();
        let mut init = HandshakeState::new_initiator(init_s, b"client-offer-A");
        let mut resp = HandshakeState::new_responder(resp_s, b"client-offer-B");
        let m1 = init.write_message_1().unwrap();
        resp.read_message_1(&m1).unwrap();
        let m2 = resp.write_message_2().unwrap();
        // ee mixed different h into the key schedule → AEAD auth fails.
        assert_eq!(init.read_message_2(&m2), Err(NoiseError::Aead));
    }

    #[test]
    fn non_contributory_ephemeral_is_rejected() {
        // A hostile initiator that sends the all-zero ephemeral public (a
        // low-order point): the responder's `ee` DH yields the zero shared
        // secret and the handshake aborts. Craft m1 directly — message 1 is
        // exactly the 32-byte ephemeral (no keyed payload yet).
        let resp_s = KeyPair::generate();
        let mut resp = HandshakeState::new_responder(resp_s, b"p");
        let m1 = [0u8; DHLEN];
        resp.read_message_1(&m1).unwrap();
        assert_eq!(resp.write_message_2(), Err(NoiseError::NonContributoryKey));
    }

    #[test]
    fn out_of_order_transport_frame_fails() {
        let (mut init_t, mut resp_t, _k, _a, _b) = run_handshake(b"p");
        let c1 = init_t.encrypt(b"one").unwrap();
        let c2 = init_t.encrypt(b"two").unwrap();
        // Delivering c2 before c1 fails: the recv nonce expects c1's counter.
        assert_eq!(resp_t.decrypt(&c2), Err(NoiseError::Aead));
        let _ = c1;
    }

    #[test]
    fn handshake_hash_is_prologue_dependent() {
        let (_i, _r, _k, hh_a, _) = run_handshake(b"AAAA");
        let (_i2, _r2, _k2, hh_b, _) = run_handshake(b"BBBB");
        assert_ne!(hh_a, hh_b);
        // And it is a real 32-byte hash, not a fixed constant.
        assert_ne!(hh_a, sha256(b"AAAA"));
    }

    /// Cross-validate our responder against the `snow` reference implementation
    /// acting as the initiator: a full XX handshake + a transport message each
    /// way must succeed across the two implementations, and the handshake hash
    /// (the SAS input) must agree byte-for-byte. This catches a "wrong but
    /// self-consistent" construction error that our own initiator/responder
    /// interop could not — e.g. a swapped nonce endianness or an HKDF ordering
    /// bug that both of our sides would share.
    #[test]
    fn interop_with_snow_reference() {
        const PARAMS: &str = "Noise_XX_25519_AESGCM_SHA256";
        const PROLOGUE: &[u8] = b"interop-prologue-bytes";

        let snow_kp = snow::Builder::new(PARAMS.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let mut snow_init = snow::Builder::new(PARAMS.parse().unwrap())
            .prologue(PROLOGUE)
            .unwrap()
            .local_private_key(&snow_kp.private)
            .unwrap()
            .build_initiator()
            .unwrap();

        let my_static = KeyPair::generate();
        let mut resp = HandshakeState::new_responder(my_static, PROLOGUE);

        let mut buf = [0u8; 1024];
        let mut payload = [0u8; 1024];

        // msg1: snow → us
        let n = snow_init.write_message(&[], &mut buf).unwrap();
        resp.read_message_1(&buf[..n]).unwrap();
        // msg2: us → snow
        let m2 = resp.write_message_2().unwrap();
        snow_init.read_message(&m2, &mut payload).unwrap();
        // msg3: snow → us
        let n = snow_init.write_message(&[], &mut buf).unwrap();
        let snow_hh = snow_init.get_handshake_hash().to_vec();
        let (mut my_transport, learned, my_hh) = resp.read_message_3(&buf[..n]).unwrap();

        // The responder authenticated snow's static key…
        assert_eq!(&learned[..], &snow_kp.public[..]);
        // …and both implementations agree on the handshake hash (the SAS input).
        assert_eq!(&my_hh[..], &snow_hh[..]);

        // Transport messages decrypt across implementations, both directions.
        let mut snow_t = snow_init.into_transport_mode().unwrap();
        let n = snow_t.write_message(b"from-snow", &mut buf).unwrap();
        assert_eq!(my_transport.decrypt(&buf[..n]).unwrap(), b"from-snow");
        let ct = my_transport.encrypt(b"from-us").unwrap();
        let n = snow_t.read_message(&ct, &mut payload).unwrap();
        assert_eq!(&payload[..n], b"from-us");
    }

    // ---- The TypeScript cross-implementation vector --------------------
    //
    // `ui/src/lib/control/conformance/noise-cross-vector.json` is the one
    // artifact the browser controller and this crate both assert against: the
    // TypeScript initiator (`ui/src/lib/control/noise.test.ts`) replays it and
    // must reproduce m1, m3, the handshake hash and the SAS byte-for-byte. It
    // was originally emitted through a temporary, reverted fixed-ephemeral
    // hook, which left it unregenerable from committed code — a change here
    // could have drifted from the browser's expectations with nothing on the
    // Rust side to notice. The test below closes that: it re-derives the whole
    // vector from the fixed scalars and fails if the committed file no longer
    // matches, so a deliberate change is a one-command regeneration and an
    // accidental one is a red test.
    //
    // No production seam is needed. `e` is private to this module, so a child
    // test module can plant a fixed ephemeral directly; shipped code still has
    // exactly one way to obtain an ephemeral, `KeyPair::generate`.

    /// Path of the committed vector, relative to this crate's manifest dir.
    const CROSS_VECTOR_PATH: &str = "../../ui/src/lib/control/conformance/noise-cross-vector.json";

    /// How to regenerate, named in the failure message so the fix is obvious.
    const CROSS_VECTOR_UPDATE_ENV: &str = "JELIYA_UPDATE_CROSS_VECTOR";

    /// The fixed inputs. Arbitrary but immutable: changing one invalidates the
    /// committed vector and every expectation the TypeScript test holds.
    const INIT_STATIC_SCALAR: [u8; DHLEN] = [0x01; DHLEN];
    const RESP_STATIC_SCALAR: [u8; DHLEN] = [0x02; DHLEN];
    const INIT_EPHEMERAL_SCALAR: [u8; DHLEN] = [0x03; DHLEN];
    const RESP_EPHEMERAL_SCALAR: [u8; DHLEN] = [0x04; DHLEN];
    const CROSS_VECTOR_PROLOGUE: &[u8] = b"jeliya-cross-vector-prologue";
    const INIT_TO_RESP_PLAINTEXT: &str = "hello-control";
    const RESP_TO_INIT_PLAINTEXT: &str = "pong";

    /// Every field of the committed JSON, in file order (serde emits struct
    /// fields in declaration order, which is what keeps the regenerated file a
    /// byte-for-byte match rather than a reordering diff).
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Eq, Debug)]
    struct CrossVector {
        #[serde(rename = "_comment")]
        comment: String,
        init_static_scalar: String,
        resp_static_scalar: String,
        init_ephemeral_scalar: String,
        resp_ephemeral_scalar: String,
        prologue: String,
        init_static_public: String,
        resp_static_public: String,
        init_ephemeral_public: String,
        resp_ephemeral_public: String,
        m1: String,
        m2: String,
        m3: String,
        handshake_hash: String,
        sas: String,
        learned_init_static: String,
        transport_init_to_resp_plaintext: String,
        transport_init_to_resp: String,
        transport_resp_to_init_plaintext: String,
        transport_resp_to_init: String,
    }

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn fixed(scalar: [u8; DHLEN]) -> KeyPair {
        KeyPair::from_secret(zeroize::Zeroizing::new(scalar))
    }

    /// Run the deterministic handshake and record everything the committed
    /// vector states. Both parties are this implementation, so the vector is a
    /// statement about *this* code; the cross-implementation claim is the
    /// TypeScript side reproducing it independently.
    fn generate_cross_vector() -> CrossVector {
        let init_e = fixed(INIT_EPHEMERAL_SCALAR);
        let resp_e = fixed(RESP_EPHEMERAL_SCALAR);
        let init_static_public = fixed(INIT_STATIC_SCALAR).public();
        let resp_static_public = fixed(RESP_STATIC_SCALAR).public();
        let init_ephemeral_public = init_e.public();
        let resp_ephemeral_public = resp_e.public();

        let mut init =
            HandshakeState::new_initiator(fixed(INIT_STATIC_SCALAR), CROSS_VECTOR_PROLOGUE);
        let mut resp =
            HandshakeState::new_responder(fixed(RESP_STATIC_SCALAR), CROSS_VECTOR_PROLOGUE);
        // Plant the fixed ephemerals before either party reaches for one.
        init.e = Some(init_e);
        resp.e = Some(resp_e);

        let m1 = init.write_message_1().expect("message 1");
        resp.read_message_1(&m1).expect("responder reads m1");
        let m2 = resp.write_message_2().expect("message 2");
        init.read_message_2(&m2).expect("initiator reads m2");
        let (m3, mut init_t, init_hh) = init.write_message_3().expect("message 3");
        let (mut resp_t, learned, resp_hh) = resp.read_message_3(&m3).expect("responder reads m3");
        assert_eq!(init_hh, resp_hh, "both sides agree on the handshake hash");

        let init_to_resp = init_t
            .encrypt(INIT_TO_RESP_PLAINTEXT.as_bytes())
            .expect("initiator transport message");
        assert_eq!(
            resp_t.decrypt(&init_to_resp).expect("responder decrypts"),
            INIT_TO_RESP_PLAINTEXT.as_bytes(),
        );
        let resp_to_init = resp_t
            .encrypt(RESP_TO_INIT_PLAINTEXT.as_bytes())
            .expect("responder transport message");
        assert_eq!(
            init_t.decrypt(&resp_to_init).expect("initiator decrypts"),
            RESP_TO_INIT_PLAINTEXT.as_bytes(),
        );

        CrossVector {
            comment: "A deterministic Noise_XX_25519_AESGCM_SHA256 handshake, emitted by the \
                      Rust reference implementation (crates/jeliya-control/src/noise.rs) with \
                      fixed static and ephemeral scalars. The TypeScript initiator, driven with \
                      the same fixed scalars, must reproduce m1, m3, the handshake hash, and the \
                      SAS byte-for-byte, decrypt m2 and the responder->initiator transport \
                      message, and produce the initiator->responder transport message the Rust \
                      responder decrypted. This is the cross-implementation cross-check. \
                      Regenerate with JELIYA_UPDATE_CROSS_VECTOR=1 cargo test -p jeliya-control \
                      cross_vector."
                .to_owned(),
            init_static_scalar: to_hex(&INIT_STATIC_SCALAR),
            resp_static_scalar: to_hex(&RESP_STATIC_SCALAR),
            init_ephemeral_scalar: to_hex(&INIT_EPHEMERAL_SCALAR),
            resp_ephemeral_scalar: to_hex(&RESP_EPHEMERAL_SCALAR),
            prologue: to_hex(CROSS_VECTOR_PROLOGUE),
            init_static_public: to_hex(&init_static_public),
            resp_static_public: to_hex(&resp_static_public),
            init_ephemeral_public: to_hex(&init_ephemeral_public),
            resp_ephemeral_public: to_hex(&resp_ephemeral_public),
            m1: to_hex(&m1),
            m2: to_hex(&m2),
            m3: to_hex(&m3),
            handshake_hash: to_hex(&init_hh),
            sas: crate::sas::sas_from_handshake_hash(&init_hh),
            learned_init_static: to_hex(&learned),
            transport_init_to_resp_plaintext: INIT_TO_RESP_PLAINTEXT.to_owned(),
            transport_init_to_resp: to_hex(&init_to_resp),
            transport_resp_to_init_plaintext: RESP_TO_INIT_PLAINTEXT.to_owned(),
            transport_resp_to_init: to_hex(&resp_to_init),
        }
    }

    /// The generated vector, rendered exactly as the file is committed:
    /// two-space pretty JSON with a trailing newline.
    fn render(vector: &CrossVector) -> String {
        let mut json = serde_json::to_string_pretty(vector).expect("the vector serializes");
        json.push('\n');
        json
    }

    /// The handshake is deterministic given the fixed scalars — the property
    /// the committed vector rests on. Without this, a nondeterminism bug would
    /// surface only as a confusing intermittent failure in the comparison test
    /// below (or, worse, as a "regeneration" that silently rewrites the file).
    #[test]
    fn cross_vector_generation_is_deterministic() {
        assert_eq!(generate_cross_vector(), generate_cross_vector());
    }

    /// The committed cross-implementation vector still describes this
    /// implementation. If this fails, either a deliberate protocol change needs
    /// the vector regenerated (and the TypeScript side re-checked against it),
    /// or something changed that should not have.
    #[test]
    fn cross_vector_matches_the_committed_file() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(CROSS_VECTOR_PATH);
        let generated = render(&generate_cross_vector());

        let committed = std::fs::read_to_string(&path).unwrap_or_else(|err| {
            panic!(
                "could not read the cross-implementation vector at {}: {err}",
                path.display()
            )
        });
        if generated == committed {
            return;
        }

        if std::env::var_os(CROSS_VECTOR_UPDATE_ENV).is_some() {
            std::fs::write(&path, &generated)
                .unwrap_or_else(|err| panic!("could not rewrite {}: {err}", path.display()));
            eprintln!(
                "regenerated {} — re-run the ui suite (npm run test:unit) to confirm the \
                 TypeScript initiator still reproduces it",
                path.display()
            );
            return;
        }

        panic!(
            "the committed cross-implementation vector no longer matches this implementation\
             \n  file    : {}\
             \n  changed : {}\
             \nIf the change is intended, regenerate with `{CROSS_VECTOR_UPDATE_ENV}=1 cargo test \
             -p jeliya-control cross_vector` and re-run the ui suite, which asserts the \
             TypeScript initiator reproduces the same bytes.",
            path.display(),
            changed_fields(&committed, &generated),
        );
    }

    #[test]
    fn changed_fields_reports_additions_removals_and_edits() {
        let committed = r#"{"a":"1","b":"2"}"#;
        assert_eq!(
            changed_fields(committed, committed),
            "only formatting (field order or whitespace)"
        );
        assert_eq!(changed_fields(committed, r#"{"a":"1","b":"3"}"#), "b");
        // A field the generator NO LONGER emits — the case that iterating only
        // the generated keys would miss, reporting "only formatting" instead.
        assert_eq!(changed_fields(committed, r#"{"a":"1"}"#), "b");
        // …and one it newly emits.
        assert_eq!(
            changed_fields(committed, r#"{"a":"1","b":"2","c":"4"}"#),
            "c"
        );
        assert_eq!(
            changed_fields("{not json", committed),
            "the committed file is not valid JSON"
        );
    }

    /// Which top-level fields differ, so the failure names what moved instead
    /// of printing two walls of JSON. An unparseable committed file reports
    /// itself rather than pretending nothing changed.
    fn changed_fields(committed: &str, generated: &str) -> String {
        let (Ok(committed), Ok(generated)) = (
            serde_json::from_str::<serde_json::Value>(committed),
            serde_json::from_str::<serde_json::Value>(generated),
        ) else {
            return "the committed file is not valid JSON".to_owned();
        };
        let (Some(committed), Some(generated)) = (committed.as_object(), generated.as_object())
        else {
            return "the committed file is not a JSON object".to_owned();
        };
        // Over the UNION of both key sets: a field dropped from `CrossVector`
        // is present in the committed file and absent from the generated one,
        // and iterating only the generated keys would miss it entirely — the
        // message would then claim "only formatting" for a real change.
        let keys: std::collections::BTreeSet<&str> = generated
            .keys()
            .chain(committed.keys())
            .map(String::as_str)
            .collect();
        let changed: Vec<&str> = keys
            .into_iter()
            .filter(|key| committed.get(*key) != generated.get(*key))
            .collect();
        if changed.is_empty() {
            "only formatting (field order or whitespace)".to_owned()
        } else {
            changed.join(", ")
        }
    }
}
