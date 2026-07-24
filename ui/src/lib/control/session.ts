/** The browser-side control session state machine — the exact mirror of the
 *  Rust reference `Initiator` (crates/jeliya-control/src/session.rs). It drives
 *  the plaintext hellos, the three Noise handshake messages, the SAS gate, and
 *  the AEAD transport phase (pairing confirmation or scoped RPCs).
 *
 *  The companion static key is pinned per the spec: on a first pairing the
 *  browser verifies the learned key against the QR/link fingerprint before the
 *  SAS (an early abort; the SAS ceremony is the real MITM authority) and then
 *  stores the full key; on a control (reconnect) session it verifies the full
 *  stored key, so a substituted companion aborts the handshake. */

import { bytesEqual } from './codec';
import { Keypair, TAGLEN, companionFingerprint, sasFromHandshakeHash } from './crypto';
import { HandshakeState, TransportState } from './noise';
import { Frame, FrameType, MAX_FRAME_LEN } from './frame';
import { ClientHello, ServerHello, SessionKind, ZERO_NONCE } from './hello';
import {
  clampCall,
  decodeMsg,
  encodeMethodCall,
  encodeMsg,
  methodIdFor,
  type MethodCall,
  type Msg,
} from './messages';
import { PROTOCOL_VERSION_V1 } from './constants';

export type SessionErrorKind =
  | 'unexpected'
  | 'incompatible'
  | 'fingerprint_mismatch'
  | 'pin_mismatch'
  | 'missing_pin'
  | 'request_in_flight'
  | 'frame_too_large'
  | 'no_transport'
  | 'no_companion_key';

export class SessionError extends Error {
  readonly kind: SessionErrorKind;
  constructor(kind: SessionErrorKind, detail?: string) {
    super(detail ? `${kind}: ${detail}` : kind);
    this.name = 'SessionError';
    this.kind = kind;
  }
}

/** Options for opening a session. */
export interface InitiatorOptions {
  /** The browser's long-lived static control key. */
  staticKey: Keypair;
  kind: SessionKind;
  /** The rendezvous nonce from the QR/link (pairing only); omit for control. */
  pairingNonce?: Uint8Array;
  /** The full companion static key to pin on a control (reconnect) session
   *  (from what was stored at pairing). Omit on a first pairing. */
  expectedCompanionKey?: Uint8Array;
  /** The companion fingerprint from the QR/link to check on a first pairing,
   *  before the SAS is shown. Omit if unavailable (the SAS still authenticates). */
  expectedFingerprint?: Uint8Array;
}

export class Initiator {
  private readonly staticKey: Keypair;
  private readonly kind: SessionKind;
  private readonly expectedCompanionKey: Uint8Array | null;
  private readonly expectedFingerprint: Uint8Array | null;
  private readonly clientHelloBytes: Uint8Array;
  private companionKeyValue: Uint8Array | null = null;
  private handshake: HandshakeState | null = null;
  private transport: TransportState | null = null;
  private sasValue: string | null = null;
  private nextNonce = 1n;
  /** The nonce of the request awaiting its response, or `null` when none is
   *  outstanding. The v1 wire is single-in-flight (a companion tears the session
   *  down if a second request arrives before the first is answered), so the
   *  browser enforces it too. */
  private pendingNonce: bigint | null = null;

  private constructor(opts: InitiatorOptions, clientHelloBytes: Uint8Array) {
    this.staticKey = opts.staticKey;
    this.kind = opts.kind;
    this.expectedCompanionKey = opts.expectedCompanionKey ?? null;
    this.expectedFingerprint = opts.expectedFingerprint ?? null;
    this.clientHelloBytes = clientHelloBytes;
  }

  /** Build the initiator and its opening `ClientHello` frame. A control
   *  (reconnect) session MUST carry the companion key pinned at pairing — it has
   *  no SAS ceremony, so the full-key pin is its only companion authentication;
   *  constructing one without a pin is a fail-closed error, never a silent
   *  first-pairing fallback. */
  static create(opts: InitiatorOptions): { initiator: Initiator; clientHello: Frame } {
    if (opts.kind === SessionKind.Control && opts.expectedCompanionKey === undefined) {
      throw new SessionError('missing_pin', 'a control session requires the pinned companion key');
    }
    const nonce =
      opts.kind === SessionKind.Pairing ? (opts.pairingNonce ?? ZERO_NONCE) : ZERO_NONCE;
    const hello = new ClientHello([PROTOCOL_VERSION_V1], opts.kind, nonce);
    const frame = hello.toFrame();
    const initiator = new Initiator(opts, frame.encode());
    return { initiator, clientHello: frame };
  }

  /** The companion static key learned during the handshake, to store after a
   *  first pairing and pin on later control sessions. */
  companionKey(): Uint8Array | null {
    return this.companionKeyValue;
  }

  /** The SAS to compare against the companion's display (available after
   *  {@link onHandshake2}). */
  sas(): string | null {
    return this.sasValue;
  }

  /** Consume the companion's `ServerHello`, returning the `Handshake1` frame. */
  async onServerHello(frame: Frame): Promise<Frame> {
    if (frame.frameType !== FrameType.ServerHello) {
      throw new SessionError('unexpected', 'expected ServerHello');
    }
    const sh = ServerHello.decodeBody(frame.body);
    // v1 is the only defined version and the only one the browser offered. Reject
    // a version 0 ("no compatible version"), any other selection the browser did
    // not offer (e.g. a companion claiming v2), and a below-floor pair where the
    // companion's own minimum exceeds the selected version — before building the
    // prologue and entering Noise.
    if (
      sh.isIncompatible() ||
      sh.version !== PROTOCOL_VERSION_V1 ||
      sh.version < sh.minVersion
    ) {
      throw new SessionError('incompatible', `version ${sh.version}, min ${sh.minVersion}`);
    }
    // Prologue = the exact ClientHello frame bytes ‖ the exact ServerHello frame
    // bytes (a canonical re-encode), so any middle-party edit breaks the DH.
    const shFrame = new ServerHello(sh.version, sh.minVersion).toFrame();
    const prologue = new Uint8Array(this.clientHelloBytes.length + shFrame.encode().length);
    prologue.set(this.clientHelloBytes);
    prologue.set(shFrame.encode(), this.clientHelloBytes.length);

    const hs = await HandshakeState.newInitiator(this.staticKey, prologue);
    const m1 = await hs.writeMessage1();
    this.handshake = hs;
    return new Frame(FrameType.Handshake1, m1);
  }

  /** Consume `Handshake2`, returning the `Handshake3` frame and completing the
   *  handshake. Pins/learns the companion key; the SAS is available afterward. */
  async onHandshake2(frame: Frame): Promise<Frame> {
    if (frame.frameType !== FrameType.Handshake2) {
      throw new SessionError('unexpected', 'expected Handshake2');
    }
    const hs = this.handshake;
    if (hs === null) throw new SessionError('unexpected', 'no handshake');
    await hs.readMessage2(frame.body);
    const learned = hs.remoteStatic();
    if (learned === null) throw new SessionError('no_companion_key');

    // Early fingerprint abort (pairing): a substituted companion whose static
    // key does not match the QR/link fingerprint is rejected before the SAS.
    if (this.expectedFingerprint !== null) {
      const fp = await companionFingerprint(learned);
      if (!bytesEqual(fp, this.expectedFingerprint)) {
        throw new SessionError('fingerprint_mismatch');
      }
    }
    // Full-key pin (control/reconnect): abort if the companion is not the one
    // stored at pairing.
    if (this.expectedCompanionKey !== null && !bytesEqual(learned, this.expectedCompanionKey)) {
      throw new SessionError('pin_mismatch');
    }
    this.companionKeyValue = learned;

    const { msg: m3, transport, handshakeHash } = await hs.writeMessage3();
    this.sasValue = await sasFromHandshakeHash(handshakeHash);
    this.transport = transport;
    this.handshake = null;
    return new Frame(FrameType.Handshake3, m3);
  }

  /** Build a `PairConfirm` transport frame (the browser user confirmed the
   *  SAS). Only meaningful on a pairing session. */
  pairConfirm(): Promise<Frame> {
    void this.kind;
    return this.seal({ type: 'pair_confirm' });
  }

  /** Build a scoped `Request` transport frame with the next session nonce. The
   *  call's wire-bounded fields are clamped (a `room.timeline` limit) before
   *  encoding, matching what the companion would clamp on receipt.
   *
   *  Single-in-flight: throws `request_in_flight` if a prior request has not yet
   *  been answered by {@link read}, rather than emitting a second request the
   *  companion would reject by tearing down the session. The caller awaits each
   *  response before the next request (or serializes its own queue). The nonce
   *  and the outstanding marker advance only once the frame is actually sealed,
   *  so a failed seal (e.g. an oversized record) leaves the session reusable. */
  async request(call: MethodCall): Promise<Frame> {
    if (this.pendingNonce !== null) {
      throw new SessionError('request_in_flight', 'await the previous response first');
    }
    const nonce = this.nextNonce;
    const clamped = clampCall(call);
    const frame = await this.seal({
      type: 'request',
      nonce,
      method: methodIdFor(clamped),
      params: encodeMethodCall(clamped),
    });
    this.nextNonce += 1n;
    this.pendingNonce = nonce;
    return frame;
  }

  /** Decrypt and decode a transport frame from the companion. A `Response`
   *  clears the outstanding-request marker, freeing the next {@link request}. */
  async read(frame: Frame): Promise<Msg> {
    if (frame.frameType !== FrameType.Transport) {
      throw new SessionError('unexpected', 'expected Transport');
    }
    if (this.transport === null) throw new SessionError('no_transport');
    const pt = await this.transport.decrypt(frame.body);
    const msg = decodeMsg(pt);
    if (msg.type === 'response') this.pendingNonce = null;
    return msg;
  }

  private async seal(msg: Msg): Promise<Frame> {
    if (this.transport === null) throw new SessionError('no_transport');
    const plaintext = encodeMsg(msg);
    // Preflight the sealed size BEFORE encrypting: the AEAD adds a 16-byte tag,
    // so a plaintext near the u16 blob limit would seal into a frame body larger
    // than MAX_FRAME_LEN. Rejecting here — before the send cipher's nonce
    // advances — keeps the session usable, instead of producing an unencodable
    // frame that fails later with the counter already consumed.
    if (plaintext.length + TAGLEN > MAX_FRAME_LEN) {
      throw new SessionError('frame_too_large', `record ${plaintext.length + TAGLEN} > ${MAX_FRAME_LEN}`);
    }
    const ct = await this.transport.encrypt(plaintext);
    return new Frame(FrameType.Transport, ct);
  }
}
