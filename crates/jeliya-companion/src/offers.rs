//! The pairing-offer registry — the cross-connection, wall-clock state the
//! sans-I/O session core deliberately does not own (see `jeliya_control`'s
//! `Responder` docs). The companion holds one [`PairingOffers`] and enforces the
//! **one-outstanding pairing-session** rule as a small state machine:
//!
//! - `Idle` → `open` mints an offer (a fresh 16-byte rendezvous nonce) → `Offered`.
//! - `Offered` → `claim` (the first `ClientHello` presenting the nonce) →
//!   `InProgress`. The slot stays **busy** — a second `open` or a second `claim`
//!   is refused — until the ceremony ends.
//! - `InProgress`/`Offered` → `release` (ceremony installed, aborted, or the
//!   connection closed) or the deadline elapses → `Idle`.
//!
//! Keeping the slot busy through the whole ceremony (not just until the claim)
//! is what prevents two concurrent SAS ceremonies with different nonces — the
//! interleaved-ceremony confusion the wire spec forbids.
//!
//! The QR / custom-protocol link carries the offer's nonce and the companion
//! static-key fingerprint; a browser opening a pairing session presents the
//! nonce in its `ClientHello`.

/// How long an unconsumed offer, or an in-progress ceremony, may live before the
/// slot is force-freed (spec: 120 s). The in-progress guard is a safety net; the
/// driver releases the slot on every ceremony exit.
pub const OFFER_TTL_MS: u64 = 120_000;

/// A live pairing offer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Offer {
    pub nonce: [u8; 16],
    pub created_at_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Slot {
    Idle,
    Offered(Offer),
    InProgress { started_at_ms: u64 },
}

/// The single-slot pairing-offer registry.
pub struct PairingOffers {
    slot: Slot,
}

impl PairingOffers {
    #[must_use]
    pub fn new() -> Self {
        Self { slot: Slot::Idle }
    }

    /// Open a new pairing offer, or `None` if the slot is busy (an offer is
    /// outstanding or a ceremony is in progress). The 16-byte nonce is from the
    /// OS CSPRNG.
    pub fn open(&mut self, now_ms: u64) -> Option<Offer> {
        self.expire_stale(now_ms);
        if !matches!(self.slot, Slot::Idle) {
            return None;
        }
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).expect("OS CSPRNG (getrandom) must not fail");
        let offer = Offer {
            nonce,
            created_at_ms: now_ms,
        };
        self.slot = Slot::Offered(offer);
        Some(offer)
    }

    /// Claim the outstanding offer for a starting pairing ceremony: if the slot
    /// is `Offered` with this exact nonce, transition to `InProgress` (keeping
    /// the slot busy) and return `true`. A second claim — same or different
    /// connection — returns `false`, so at most one ceremony ever runs per offer.
    pub fn claim(&mut self, nonce: &[u8; 16], now_ms: u64) -> bool {
        self.expire_stale(now_ms);
        match self.slot {
            Slot::Offered(offer) if &offer.nonce == nonce => {
                self.slot = Slot::InProgress {
                    started_at_ms: now_ms,
                };
                true
            }
            _ => false,
        }
    }

    /// Release the slot back to `Idle` when a claimed ceremony ends (installed,
    /// aborted, or the connection closed). Only the connection that claimed the
    /// offer calls this. Idempotent.
    pub fn release(&mut self) {
        self.slot = Slot::Idle;
    }

    /// Whether the slot is busy (an offer is outstanding or a ceremony is in
    /// progress) at `now_ms`.
    pub fn is_busy(&mut self, now_ms: u64) -> bool {
        self.expire_stale(now_ms);
        !matches!(self.slot, Slot::Idle)
    }

    fn expire_stale(&mut self, now_ms: u64) {
        let stale = match self.slot {
            Slot::Offered(offer) => now_ms.saturating_sub(offer.created_at_ms) >= OFFER_TTL_MS,
            Slot::InProgress { started_at_ms } => {
                now_ms.saturating_sub(started_at_ms) >= OFFER_TTL_MS
            }
            Slot::Idle => false,
        };
        if stale {
            self.slot = Slot::Idle;
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
    fn slot_stays_busy_through_the_whole_ceremony() {
        let mut offers = PairingOffers::new();
        let a = offers.open(1_000).expect("first offer opens");
        // A second offer is refused while the first is merely Offered…
        assert!(offers.open(1_000).is_none());
        // …and still refused once a ceremony is InProgress (claimed but not
        // released) — this is what blocks concurrent ceremonies.
        assert!(offers.claim(&a.nonce, 1_000));
        assert!(
            offers.open(1_000).is_none(),
            "no new offer while a ceremony is in progress"
        );
        // Only after the ceremony releases the slot can a new offer open.
        offers.release();
        assert!(offers.open(1_000).is_some());
    }

    #[test]
    fn claim_is_single_use_and_nonce_specific() {
        let mut offers = PairingOffers::new();
        let a = offers.open(0).unwrap();
        assert!(!offers.claim(&[0xFF; 16], 0), "wrong nonce does not claim");
        assert!(offers.claim(&a.nonce, 0), "correct nonce claims");
        assert!(!offers.claim(&a.nonce, 0), "already claimed (in progress)");
    }

    #[test]
    fn offered_slot_expires_after_ttl() {
        let mut offers = PairingOffers::new();
        let _a = offers.open(1_000).unwrap();
        assert!(offers.is_busy(1_000 + OFFER_TTL_MS - 1));
        assert!(
            !offers.is_busy(1_000 + OFFER_TTL_MS),
            "offer expired, slot free"
        );
        assert!(offers.open(1_000 + OFFER_TTL_MS).is_some());
    }

    #[test]
    fn in_progress_slot_has_a_safety_net_expiry() {
        let mut offers = PairingOffers::new();
        let a = offers.open(0).unwrap();
        offers.claim(&a.nonce, 0);
        // Even if the driver never releases, an in-progress ceremony that
        // outlives the TTL frees the slot so pairing is not wedged forever.
        assert!(!offers.is_busy(OFFER_TTL_MS));
    }

    #[test]
    fn nonces_are_unique_across_offers() {
        let mut offers = PairingOffers::new();
        let a = offers.open(0).unwrap();
        offers.release();
        let b = offers.open(0).unwrap();
        assert_ne!(a.nonce, b.nonce, "fresh random nonce each offer");
    }

    #[test]
    fn fingerprint_is_eight_bytes_of_sha256() {
        let fp = companion_fingerprint(&[0x11; 32]);
        assert_eq!(fp.len(), 8);
        assert_ne!(fp, companion_fingerprint(&[0x12; 32]));
        assert_eq!(fp, companion_fingerprint(&[0x11; 32]));
    }
}
