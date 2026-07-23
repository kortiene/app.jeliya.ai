//! The short authentication string, derived from the Noise handshake hash.
//!
//! ADR #2 decision 4 specifies a ~30-bit SAS shown as two 5-digit groups and
//! confirmed by the user on both sides. Deriving it from the handshake hash
//! `h` — which covers the prologue, both static keys, both ephemerals, and
//! every handshake ciphertext — means a middle party cannot present the same
//! SAS on both sides without breaking the Diffie-Hellman. This replaces the
//! Phase-1 scaffolding's BLAKE3-over-two-public-keys construction (which bound
//! only the two identities, not the live transcript) and adds the
//! domain-separation tag the Phase-1 review flagged as missing.

use crate::crypto::hmac_sha256;

/// The SAS domain-separation label.
const SAS_LABEL: &[u8] = b"jeliya/control/sas/v1";

/// Derive the SAS display string `"ddddd-ddddd"` from a completed handshake
/// hash. Both parties compute this from the same `h`, so both display the same
/// string; the user compares them.
#[must_use]
pub fn sas_from_handshake_hash(handshake_hash: &[u8; 32]) -> String {
    let mac = hmac_sha256(handshake_hash, SAS_LABEL);
    let group1 = u16::from_be_bytes([mac[0], mac[1]]);
    let group2 = u16::from_be_bytes([mac[2], mac[3]]);
    format!("{group1:05}-{group2:05}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_is_two_five_digit_groups() {
        let sas = sas_from_handshake_hash(&[0x11; 32]);
        assert_eq!(sas.len(), 11, "ddddd-ddddd");
        assert_eq!(sas.as_bytes()[5], b'-');
        assert!(sas
            .bytes()
            .enumerate()
            .all(|(i, b)| i == 5 || b.is_ascii_digit()));
    }

    #[test]
    fn different_transcripts_yield_different_sas() {
        assert_ne!(
            sas_from_handshake_hash(&[0x01; 32]),
            sas_from_handshake_hash(&[0x02; 32])
        );
    }

    #[test]
    fn a_single_bit_flip_in_the_transcript_changes_the_sas() {
        let mut h = [0x55u8; 32];
        let base = sas_from_handshake_hash(&h);
        h[31] ^= 1;
        assert_ne!(base, sas_from_handshake_hash(&h));
    }

    #[test]
    fn sas_is_deterministic() {
        assert_eq!(
            sas_from_handshake_hash(&[7; 32]),
            sas_from_handshake_hash(&[7; 32])
        );
    }
}
