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
import { Keypair, companionFingerprint, sasFromHandshakeHash } from './crypto';
import { HandshakeState, TransportState } from './noise';
import { Frame, FrameType } from './frame';
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

  private constructor(opts: InitiatorOptions, clientHelloBytes: Uint8Array) {
    this.staticKey = opts.staticKey;
    this.kind = opts.kind;
    this.expectedCompanionKey = opts.expectedCompanionKey ?? null;
    this.expectedFingerprint = opts.expectedFingerprint ?? null;
    this.clientHelloBytes = clientHelloBytes;
  }

  /** Build the initiator and its opening `ClientHello` frame. */
  static create(opts: InitiatorOptions): { initiator: Initiator; clientHello: Frame } {
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
    if (sh.isIncompatible()) throw new SessionError('incompatible');
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
   *  encoding, matching what the companion would clamp on receipt. */
  request(call: MethodCall): Promise<Frame> {
    const nonce = this.nextNonce;
    this.nextNonce += 1n;
    const clamped = clampCall(call);
    return this.seal({
      type: 'request',
      nonce,
      method: methodIdFor(clamped),
      params: encodeMethodCall(clamped),
    });
  }

  /** Decrypt and decode a transport frame from the companion. */
  async read(frame: Frame): Promise<Msg> {
    if (frame.frameType !== FrameType.Transport) {
      throw new SessionError('unexpected', 'expected Transport');
    }
    if (this.transport === null) throw new SessionError('no_transport');
    const pt = await this.transport.decrypt(frame.body);
    return decodeMsg(pt);
  }

  private async seal(msg: Msg): Promise<Frame> {
    if (this.transport === null) throw new SessionError('no_transport');
    const ct = await this.transport.encrypt(encodeMsg(msg));
    return new Frame(FrameType.Transport, ct);
  }
}
