/** The Jeliya companion control-wire library (browser side).
 *
 *  A dependency-free, WebCrypto-only implementation of ADR #2's control
 *  protocol — the same wire the Rust companion enforces
 *  (crates/jeliya-{protocol,control}), pinned to the same conformance corpus.
 *  The browser generates a non-extractable X25519 control key, runs the
 *  `Noise_XX_25519_AESGCM_SHA256` handshake as the initiator, confirms the SAS,
 *  and drives scoped RPCs — all over an abstract {@link FrameChannel}. The
 *  real browser↔companion transport is a later PR (gated on relay-auth #49);
 *  everything here is transport-agnostic and exercised in-process. */

export { ProtoError, Reader, Writer, toHex, fromHex, bytesEqual } from './codec';
export type { ProtoErrorKind } from './codec';
export { Frame, FrameType, MAX_FRAME_LEN } from './frame';
export { ClientHello, ServerHello, SessionKind, MAGIC, MAX_VERSIONS, ZERO_NONCE } from './hello';
export {
  method,
  scope,
  reject,
  error,
  ALL_METHODS,
  MAX_TIMELINE_LIMIT,
  errorName,
  scopeForMethod,
  encodeMsg,
  decodeMsg,
  errorResponse,
  decodeErrorBody,
  encodeMethodCall,
  decodeMethodCall,
  clampCall,
  methodIdFor,
  roomIdOf,
} from './messages';
export type { Msg, MethodCall } from './messages';
export {
  AeadError,
  Keypair,
  sha256,
  hmacSha256,
  noiseHkdf,
  aeadSeal,
  aeadOpen,
  sasFromHandshakeHash,
  companionFingerprint,
  HASHLEN,
  DHLEN,
  TAGLEN,
} from './crypto';
export { HandshakeState, TransportState, NoiseError } from './noise';
export type { NoiseErrorKind } from './noise';
export { Initiator, SessionError } from './session';
export type { InitiatorOptions, SessionErrorKind } from './session';
export { ChannelClosedError, createDuplexPair } from './channel';
export type { FrameChannel } from './channel';
export {
  ControlKey,
  InMemoryControlKeyStore,
  IndexedDbControlKeyStore,
} from './controlKey';
export type { ControlKeyStore } from './controlKey';
export {
  ALPN,
  PROTOCOL_VERSION_V1,
  MIN_SAFE_VERSION,
  NOISE_PROTOCOL_NAME,
} from './constants';
