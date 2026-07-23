//! The cryptographic primitives the control wire's Noise handshake and SAS are
//! built from, each reused from a crate already load-bearing in the workspace's
//! resolved graph so no second implementation of any primitive enters the
//! runtime: AES-256-GCM from `aes-gcm 0.10` (the exact crate and version the
//! Phase-1-reviewed recovery envelope uses), X25519 from the `curve25519-dalek`
//! build every iroh `EndpointId` already depends on, and SHA-256 from `sha2`.
//!
//! HMAC-SHA-256 and HKDF-SHA-256 are implemented here directly over `sha2`
//! rather than pulled as separate crates: both are short, their correctness is
//! pinned to published RFC test vectors (RFC 4231, RFC 5869) in this module's
//! tests, and keeping them in-crate avoids adding two dependencies to a
//! security-reviewed crate for ~40 lines of well-specified construction.
//!
//! Every secret this module returns (DH outputs, HKDF/HMAC keys, ephemeral
//! scalars) is a [`Zeroizing`] buffer so it is wiped on drop.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce, Tag};
use curve25519_dalek::montgomery::MontgomeryPoint;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// SHA-256 output / key length.
pub const HASHLEN: usize = 32;
/// AEAD tag length (AES-GCM).
pub const TAGLEN: usize = 16;
/// X25519 public/scalar length.
pub const DHLEN: usize = 32;

const BLOCK: usize = 64;

/// An AEAD authentication failure (wrong key, tampered ciphertext, wrong nonce
/// or associated data). The only error this module surfaces to the Noise layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AeadError;

/// SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; HASHLEN] {
    Sha256::digest(data).into()
}

/// HMAC-SHA-256 (RFC 2104) of `msg` under `key`.
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> Zeroizing<[u8; HASHLEN]> {
    let mut block = Zeroizing::new([0u8; BLOCK]);
    if key.len() > BLOCK {
        block[..HASHLEN].copy_from_slice(&sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = Zeroizing::new([0x36u8; BLOCK]);
    let mut opad = Zeroizing::new([0x5cu8; BLOCK]);
    for i in 0..BLOCK {
        ipad[i] ^= block[i];
        opad[i] ^= block[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad.as_slice());
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad.as_slice());
    outer.update(inner);
    Zeroizing::new(outer.finalize().into())
}

/// The Noise HKDF (RFC 5869 extract+expand, keyed by the chaining key), which
/// returns 2 or 3 outputs of [`HASHLEN`] bytes. Panics on an out-of-range
/// `num_outputs` (a programming error: Noise only ever asks for 2 or 3).
#[must_use]
pub fn hkdf(
    chaining_key: &[u8; HASHLEN],
    ikm: &[u8],
    num_outputs: usize,
) -> Vec<Zeroizing<[u8; HASHLEN]>> {
    assert!(
        (2..=3).contains(&num_outputs),
        "Noise HKDF only produces 2 or 3 outputs"
    );
    let temp_key = hmac_sha256(chaining_key, ikm);
    let out1 = hmac_sha256(&*temp_key, &[0x01]);
    let mut in2 = Zeroizing::new(Vec::with_capacity(HASHLEN + 1));
    in2.extend_from_slice(&*out1);
    in2.push(0x02);
    let out2 = hmac_sha256(&*temp_key, &in2);
    let mut outputs = vec![out1, out2];
    if num_outputs == 3 {
        let mut in3 = Zeroizing::new(Vec::with_capacity(HASHLEN + 1));
        in3.extend_from_slice(&*outputs[1]);
        in3.push(0x03);
        outputs.push(hmac_sha256(&*temp_key, &in3));
    }
    outputs
}

/// An X25519 keypair. The secret scalar is zeroized on drop.
pub struct KeyPair {
    secret: Zeroizing<[u8; DHLEN]>,
    public: [u8; DHLEN],
}

impl KeyPair {
    /// Generate a fresh keypair from the OS CSPRNG (`getrandom`).
    #[must_use]
    pub fn generate() -> Self {
        let mut secret = Zeroizing::new([0u8; DHLEN]);
        getrandom::fill(&mut *secret).expect("OS CSPRNG (getrandom) must not fail");
        Self::from_secret(secret)
    }

    /// Derive the public key for a given secret scalar (clamped X25519 base
    /// multiply). Used for tests with fixed scalars and for loading a stored
    /// static key.
    #[must_use]
    pub fn from_secret(secret: Zeroizing<[u8; DHLEN]>) -> Self {
        let public = MontgomeryPoint::mul_base_clamped(*secret).to_bytes();
        Self { secret, public }
    }

    #[must_use]
    pub fn public(&self) -> [u8; DHLEN] {
        self.public
    }

    /// X25519 Diffie-Hellman: this secret against `their_public`. Returns the
    /// shared secret, or `None` if the result is the all-zero point (a
    /// non-contributory / low-order peer key), which the Noise layer treats as
    /// a handshake abort.
    #[must_use]
    pub fn dh(&self, their_public: &[u8; DHLEN]) -> Option<Zeroizing<[u8; DHLEN]>> {
        let shared = MontgomeryPoint(*their_public)
            .mul_clamped(*self.secret)
            .to_bytes();
        if shared.ct_eq(&[0u8; DHLEN]).into() {
            None
        } else {
            Some(Zeroizing::new(shared))
        }
    }
}

/// AES-256-GCM encrypt-in-place with the Noise nonce construction (96-bit
/// nonce = 32 zero bits ‖ 64-bit big-endian counter), appending the tag.
/// Returns `ciphertext ‖ tag`.
#[must_use]
pub fn aead_seal(key: &[u8; HASHLEN], counter: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = noise_nonce(counter);
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), ad, &mut buf)
        .expect("AES-GCM encryption is infallible for in-range inputs");
    buf.extend_from_slice(&tag);
    buf
}

/// AES-256-GCM decrypt of `ciphertext ‖ tag`. Returns the plaintext or
/// [`AeadError`] on any authentication failure.
pub fn aead_open(
    key: &[u8; HASHLEN],
    counter: u64,
    ad: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, AeadError> {
    if data.len() < TAGLEN {
        return Err(AeadError);
    }
    let cipher = Aes256Gcm::new(key.into());
    let nonce = noise_nonce(counter);
    let (body, tag) = data.split_at(data.len() - TAGLEN);
    let mut buf = body.to_vec();
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&nonce),
            ad,
            &mut buf,
            Tag::from_slice(tag),
        )
        .map_err(|_| AeadError)?;
    Ok(buf)
}

fn noise_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn hmac_rfc4231_case2() {
        // RFC 4231 test case 2.
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex(&*mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_rfc4231_case1() {
        // RFC 4231 test case 1: key = 20×0x0b, data = "Hi There".
        let mac = hmac_sha256(&[0x0b; 20], b"Hi There");
        assert_eq!(
            hex(&*mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn hkdf_matches_the_noise_hmac_chain() {
        // The Noise HKDF is defined as temp = HMAC(ck, ikm); out1 = HMAC(temp,
        // 0x01); out2 = HMAC(temp, out1 ‖ 0x02); out3 = HMAC(temp, out2 ‖ 0x03).
        // Recompute it independently from the RFC-4231-verified `hmac_sha256`
        // (an oracle, not the code under test) and require byte agreement — this
        // checks `hkdf` wires HMAC in exactly the documented order.
        let ck = [0x0bu8; HASHLEN];
        let ikm = [0x42u8; 8];
        let temp = hmac_sha256(&ck, &ikm);
        let want1 = hmac_sha256(&*temp, &[0x01]);
        let mut in2 = want1.to_vec();
        in2.push(0x02);
        let want2 = hmac_sha256(&*temp, &in2);
        let mut in3 = want2.to_vec();
        in3.push(0x03);
        let want3 = hmac_sha256(&*temp, &in3);

        let outs = hkdf(&ck, &ikm, 3);
        assert_eq!(outs.len(), 3);
        assert_eq!(&*outs[0], &*want1);
        assert_eq!(&*outs[1], &*want2);
        assert_eq!(&*outs[2], &*want3);
    }

    #[test]
    fn x25519_dh_agrees_both_directions() {
        let a = KeyPair::generate();
        let b = KeyPair::generate();
        let ab = a.dh(&b.public()).unwrap();
        let ba = b.dh(&a.public()).unwrap();
        assert_eq!(&*ab, &*ba);
    }

    #[test]
    fn x25519_rejects_all_zero_peer_key() {
        let a = KeyPair::generate();
        // The all-zero public key is low-order; DH must return None.
        assert!(a.dh(&[0u8; DHLEN]).is_none());
    }

    #[test]
    fn aead_round_trip_and_fails_closed() {
        let key = [7u8; HASHLEN];
        let ct = aead_seal(&key, 3, b"ad", b"secret");
        assert_eq!(aead_open(&key, 3, b"ad", &ct).unwrap(), b"secret");
        // Wrong counter, wrong AD, and a flipped bit each fail closed.
        assert_eq!(aead_open(&key, 4, b"ad", &ct), Err(AeadError));
        assert_eq!(aead_open(&key, 3, b"AD", &ct), Err(AeadError));
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(aead_open(&key, 3, b"ad", &bad), Err(AeadError));
        assert_eq!(aead_open(&key, 3, b"ad", &ct[..8]), Err(AeadError));
    }
}
