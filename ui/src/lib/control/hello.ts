/** The plaintext version/capability hellos (deliverable D6) — the only frames
 *  sent in the clear. They carry no capability detail, just offered versions,
 *  the session kind, and (for pairing) the rendezvous nonce. Their exact bytes
 *  become the Noise prologue, so any middle-party edit breaks the handshake
 *  rather than silently downgrading it. Mirror of `jeliya-protocol::hello`. */

import { ProtoError, Reader, Writer, bytesEqual } from './codec';
import { Frame, FrameType } from './frame';

/** The 4-byte magic prefixing both hellos: `JCTL`. */
export const MAGIC = new Uint8Array([0x4a, 0x43, 0x54, 0x4c]);

/** The maximum number of versions a client may offer. */
export const MAX_VERSIONS = 8;

/** The all-zero pairing nonce a control (already-paired) session must send. */
export const ZERO_NONCE = new Uint8Array(16);

/** Why a session is being opened. */
export enum SessionKind {
  /** Enroll a new control key (carries a live rendezvous nonce). */
  Pairing = 1,
  /** Exercise an already-installed control key (nonce field is all-zero). */
  Control = 2,
}

function sessionKindFromTag(tag: number): SessionKind {
  if (tag !== SessionKind.Pairing && tag !== SessionKind.Control) {
    throw new ProtoError('bad_enum', 'session_kind');
  }
  return tag;
}

/** The browser's opening offer. */
export class ClientHello {
  constructor(
    readonly versions: number[],
    readonly sessionKind: SessionKind,
    /** 16-byte rendezvous nonce from the QR/link for a pairing session;
     *  all-zero for a control session (validated on decode). */
    readonly pairingNonce: Uint8Array,
  ) {}

  encodeBody(): Uint8Array {
    if (this.versions.length === 0 || this.versions.length > MAX_VERSIONS) {
      throw new ProtoError('bad_count', 'versions');
    }
    if (this.sessionKind === SessionKind.Control && !bytesEqual(this.pairingNonce, ZERO_NONCE)) {
      throw new ProtoError('bad_enum', 'pairing_nonce');
    }
    if (this.pairingNonce.length !== 16) throw new ProtoError('bad_count', 'pairing_nonce');
    const w = new Writer();
    w.putBytes(MAGIC);
    w.putU8(this.versions.length);
    for (const v of this.versions) w.putU16(v);
    w.putU8(this.sessionKind);
    w.putBytes(this.pairingNonce);
    return w.intoBytes();
  }

  static decodeBody(buf: Uint8Array): ClientHello {
    const r = new Reader(buf);
    if (!bytesEqual(r.readArray(4), MAGIC)) throw new ProtoError('bad_magic');
    const count = r.readU8();
    if (count === 0 || count > MAX_VERSIONS) throw new ProtoError('bad_count', 'versions');
    const versions: number[] = [];
    for (let i = 0; i < count; i++) versions.push(r.readU16());
    const sessionKind = sessionKindFromTag(r.readU8());
    const pairingNonce = r.readArray(16);
    r.finish();
    if (sessionKind === SessionKind.Control && !bytesEqual(pairingNonce, ZERO_NONCE)) {
      throw new ProtoError('bad_enum', 'pairing_nonce');
    }
    return new ClientHello(versions, sessionKind, pairingNonce);
  }

  toFrame(): Frame {
    return new Frame(FrameType.ClientHello, this.encodeBody());
  }
}

/** The companion's version selection and minimum-safe floor. */
export class ServerHello {
  constructor(
    /** The chosen version, or `0` to mean "no compatible version". */
    readonly version: number,
    /** The companion-enforced minimum-safe protocol version. */
    readonly minVersion: number,
  ) {}

  encodeBody(): Uint8Array {
    const w = new Writer();
    w.putBytes(MAGIC);
    w.putU16(this.version);
    w.putU16(this.minVersion);
    return w.intoBytes();
  }

  static decodeBody(buf: Uint8Array): ServerHello {
    const r = new Reader(buf);
    if (!bytesEqual(r.readArray(4), MAGIC)) throw new ProtoError('bad_magic');
    const version = r.readU16();
    const minVersion = r.readU16();
    r.finish();
    return new ServerHello(version, minVersion);
  }

  toFrame(): Frame {
    return new Frame(FrameType.ServerHello, this.encodeBody());
  }

  /** Whether the companion found a compatible version. */
  isIncompatible(): boolean {
    return this.version === 0;
  }
}
