/** The outer frame: `u32 length ‖ u8 frame_type ‖ body`. Mirrors the Rust
 *  `jeliya-protocol::frame`. Framing is deliberately dumb — it does not
 *  interpret the body — so the same reader serves plaintext hellos, the three
 *  Noise handshake messages, and the AEAD transport records alike. */

import { ProtoError, Reader, Writer } from './codec';

/** The maximum body size a single frame may declare (mirrors
 *  `jeliya_protocol::MAX_FRAME_LEN`). */
export const MAX_FRAME_LEN = 65_536;

/** The frame-type tag. Unknown tags are a protocol error at the transport layer
 *  (the receiver closes the connection). */
export enum FrameType {
  /** `0x01` browser → companion, plaintext (version/capability offer). */
  ClientHello = 0x01,
  /** `0x02` companion → browser, plaintext (version selection + floor). */
  ServerHello = 0x02,
  /** `0x03` browser → companion, Noise message 1 (`e`). */
  Handshake1 = 0x03,
  /** `0x04` companion → browser, Noise message 2 (`e, ee, s, es`). */
  Handshake2 = 0x04,
  /** `0x05` browser → companion, Noise message 3 (`s, se`). */
  Handshake3 = 0x05,
  /** `0x10` either direction, one AEAD transport record. */
  Transport = 0x10,
}

const KNOWN_TAGS = new Set<number>([0x01, 0x02, 0x03, 0x04, 0x05, 0x10]);

function frameTypeFromTag(tag: number): FrameType {
  if (!KNOWN_TAGS.has(tag)) throw new ProtoError('bad_enum', 'frame_type');
  return tag as FrameType;
}

/** One frame. The `body` is uninterpreted bytes. */
export class Frame {
  constructor(
    readonly frameType: FrameType,
    readonly body: Uint8Array,
  ) {}

  /** Encode the full frame bytes (`length ‖ type ‖ body`). Throws
   *  `frame_too_large` if the body exceeds {@link MAX_FRAME_LEN}. */
  encode(): Uint8Array {
    if (this.body.length > MAX_FRAME_LEN) throw new ProtoError('frame_too_large');
    const w = new Writer();
    // `length` counts the body only; `frame_type` is a separate byte after it.
    w.putU32(this.body.length);
    w.putU8(this.frameType);
    w.putBytes(this.body);
    return w.intoBytes();
  }

  /** Decode exactly one frame from the front of `buf`, returning the frame and
   *  the number of bytes consumed. Enforces {@link MAX_FRAME_LEN} before slicing
   *  the body, so a hostile length prefix cannot force a large read. */
  static decodePrefix(buf: Uint8Array): { frame: Frame; consumed: number } {
    const r = new Reader(buf);
    const len = r.readU32();
    if (len > MAX_FRAME_LEN) throw new ProtoError('frame_too_large');
    const tag = r.readU8();
    const frameType = frameTypeFromTag(tag);
    const body = r.readTake(len);
    return { frame: new Frame(frameType, body), consumed: 5 + len };
  }

  /** Decode exactly one frame that fills `buf` completely (no trailing bytes). */
  static decodeExact(buf: Uint8Array): Frame {
    const { frame, consumed } = Frame.decodePrefix(buf);
    if (consumed !== buf.length) throw new ProtoError('trailing_bytes');
    return frame;
  }
}
