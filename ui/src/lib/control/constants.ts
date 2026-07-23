/** Wire-level constants shared across the control library (mirror of the
 *  top-level `jeliya-protocol` constants). */

/** The custom-protocol ALPN the companion accepts (informational for the
 *  browser; the transport layer that carries these frames is a later PR). */
export const ALPN = '/jeliya/control/1';

/** The v1 protocol version the browser offers. */
export const PROTOCOL_VERSION_V1 = 1;

/** The companion-enforced minimum-safe version floor the browser expects. */
export const MIN_SAFE_VERSION = 1;

/** The Noise protocol name (informational; the handshake hardcodes it). */
export const NOISE_PROTOCOL_NAME = 'Noise_XX_25519_AESGCM_SHA256';
