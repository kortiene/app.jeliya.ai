//! The pairing-offer registry — the cross-connection, wall-clock state the
//! sans-I/O session core deliberately does not own (see `jeliya_control`'s
//! `Responder` docs). The companion holds one [`PairingOffers`] and enforces:
//!
//! - **single-use**: a rendezvous nonce is spent by the first connection that
//!   presents it, successful or not;
//! - **one outstanding**: a second pairing offer is refused while one is live;
//! - **a deadline**: an offer that is not consumed within [`OFFER_TTL_MS`] of
//!   creation expires and frees the slot.
//!
//! The QR / custom-protocol link the companion displays carries the offer's
//! rendezvous nonce and the companion static-key fingerprint; a browser opening
//! a pairing session must present the nonce in its `ClientHello`.

/// How long an unconsumed pairing offer stays live (ADR #2 / spec: 120 s).
pub const OFFER_TTL_MS: u64 = 120_000;

/// A live pairing offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer {
    pub nonce: [u8; 16],
    pub created_at_ms: u64,
}

/// The single-slot pairing-offer registry.
pub struct PairingOffers {
    current: Option<Offer>,
}

impl PairingOffers {
    #[must_use]
    pub fn new() -> Self {
        Self { current: None }
    }

    /// Open a new pairing offer, or `None` if one is already outstanding (and
    /// not yet expired at `now_ms`). The 16-byte rendezvous nonce is drawn from
    /// the OS CSPRNG.
    pub fn open(&mut self, now_ms: u64) -> Option<Offer> {
        self.expire_if_stale(now_ms);
        if self.current.is_some() {
            return None; // one outstanding at a time
        }
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).expect("OS CSPRNG (getrandom) must not fail");
        let offer = Offer {
            nonce,
            created_at_ms: now_ms,
        };
        self.current = Some(offer);
        Some(offer)
    }

    /// The nonce a `Responder` should be given as its `expected_pairing_nonce`
    /// for a pairing connection right now, or `None` if no live offer exists.
    pub fn live_nonce(&mut self, now_ms: u64) -> Option<[u8; 16]> {
        self.expire_if_stale(now_ms);
        self.current.map(|o| o.nonce)
    }

    /// Spend the outstanding offer (single-use): called when a pairing
    /// connection presents the nonce, successful or not. Frees the slot.
    pub fn spend(&mut self, nonce: &[u8; 16]) -> bool {
        match self.current {
            Some(o) if &o.nonce == nonce => {
                self.current = None;
                true
            }
            _ => false,
        }
    }

    fn expire_if_stale(&mut self, now_ms: u64) {
        if let Some(o) = self.current {
            if now_ms.saturating_sub(o.created_at_ms) >= OFFER_TTL_MS {
                self.current = None;
            }
        }
    }
}

impl Default for PairingOffers {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the QR/link fingerprint of a companion static public key: the first
/// 8 bytes of its SHA-256 (per the wire spec). The browser verifies the static
/// key it receives in the handshake against this before the SAS.
#[must_use]
pub fn companion_fingerprint(static_public: &[u8; 32]) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(static_public);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_offer_outstanding_at_a_time() {
        let mut offers = PairingOffers::new();
        let a = offers.open(1_000).expect("first offer opens");
        assert!(
            offers.open(1_000).is_none(),
            "second offer refused while one is live"
        );
        // After spending it, a new one can open.
        assert!(offers.spend(&a.nonce));
        assert!(offers.open(1_000).is_some());
    }

    #[test]
    fn offer_expires_after_ttl() {
        let mut offers = PairingOffers::new();
        let a = offers.open(1_000).unwrap();
        // Just before the deadline it is still live.
        assert_eq!(offers.live_nonce(1_000 + OFFER_TTL_MS - 1), Some(a.nonce));
        // At the deadline it is gone and the slot is free.
        assert_eq!(offers.live_nonce(1_000 + OFFER_TTL_MS), None);
        assert!(offers.open(1_000 + OFFER_TTL_MS).is_some());
    }

    #[test]
    fn spend_is_single_use_and_nonce_specific() {
        let mut offers = PairingOffers::new();
        let a = offers.open(0).unwrap();
        assert!(!offers.spend(&[0xFF; 16]), "wrong nonce does not spend");
        assert!(offers.spend(&a.nonce), "correct nonce spends");
        assert!(!offers.spend(&a.nonce), "already spent");
    }

    #[test]
    fn nonces_are_unique_across_offers() {
        let mut offers = PairingOffers::new();
        let a = offers.open(0).unwrap();
        offers.spend(&a.nonce);
        let b = offers.open(0).unwrap();
        assert_ne!(a.nonce, b.nonce, "fresh random nonce each offer");
    }

    #[test]
    fn fingerprint_is_eight_bytes_of_sha256() {
        let fp = companion_fingerprint(&[0x11; 32]);
        assert_eq!(fp.len(), 8);
        // Deterministic and key-dependent.
        assert_ne!(fp, companion_fingerprint(&[0x12; 32]));
        assert_eq!(fp, companion_fingerprint(&[0x11; 32]));
    }
}
