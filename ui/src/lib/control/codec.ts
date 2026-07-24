/** Big-endian, length-prefixed primitive codec — the exact mirror of the Rust
 *  `jeliya-protocol::codec` (see crates/jeliya-protocol/src/codec.ts's Rust
 *  twin). All integers are big-endian; all strings are UTF-8 with a `u16`
 *  byte-length prefix. The reader is strict: it never over-reads, and a
 *  well-formed decode must consume its input exactly (`finish`), so a frame with
 *  trailing bytes is rejected rather than silently truncated.
 *
 *  This wire is pinned by the conformance corpus in
 *  `crates/jeliya-protocol/src/tests.rs`; the tests here reproduce the same
 *  golden bytes. */

/** A wire decode/encode error. Every kind is a fail-closed outcome: the caller
 *  drops the frame (and, at the transport layer, the connection). The `kind`
 *  strings mirror the Rust `ProtoError` variants. */
export type ProtoErrorKind =
  | 'short_input'
  | 'trailing_bytes'
  | 'frame_too_large'
  | 'string_too_long'
  | 'bad_magic'
  | 'bad_utf8'
  | 'bad_enum'
  | 'bad_count';

export class ProtoError extends Error {
  readonly kind: ProtoErrorKind;
  /** For `bad_enum`/`bad_count`, which field (mirrors the Rust `&'static str`). */
  readonly field?: string;

  constructor(kind: ProtoErrorKind, field?: string) {
    super(field ? `${kind}(${field})` : kind);
    this.name = 'ProtoError';
    this.kind = kind;
    this.field = field;
  }
}

const UTF8_ENCODER = new TextEncoder();
// `fatal` rejects invalid UTF-8 (like Rust's `from_utf8`); `ignoreBOM: true`
// keeps a leading U+FEFF as an ordinary character instead of silently stripping
// it — Rust does no BOM handling, so stripping would decode the same wire bytes
// to a different string and break cross-impl agreement.
const UTF8_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** A cursor over an input byte slice. Reads advance the position; every read
 *  checks bounds and throws {@link ProtoError} `short_input` rather than
 *  returning a truncated value. */
export class Reader {
  private readonly view: DataView;
  private pos = 0;

  constructor(private readonly buf: Uint8Array) {
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }

  remaining(): number {
    return this.buf.length - this.pos;
  }

  private take(n: number): Uint8Array {
    if (this.remaining() < n) throw new ProtoError('short_input');
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  readU8(): number {
    if (this.remaining() < 1) throw new ProtoError('short_input');
    return this.view.getUint8(this.pos++);
  }

  readU16(): number {
    if (this.remaining() < 2) throw new ProtoError('short_input');
    const v = this.view.getUint16(this.pos, false);
    this.pos += 2;
    return v;
  }

  readU32(): number {
    if (this.remaining() < 4) throw new ProtoError('short_input');
    const v = this.view.getUint32(this.pos, false);
    this.pos += 4;
    return v;
  }

  readU64(): bigint {
    if (this.remaining() < 8) throw new ProtoError('short_input');
    const v = this.view.getBigUint64(this.pos, false);
    this.pos += 8;
    return v;
  }

  /** Read a fixed `n`-byte array (copied out). */
  readArray(n: number): Uint8Array {
    return this.take(n).slice();
  }

  /** Read exactly `n` bytes, returning a view into the input. */
  readTake(n: number): Uint8Array {
    return this.take(n).slice();
  }

  /** Read a `u16`-length-prefixed byte blob (not UTF-8-checked). */
  readBlob(): Uint8Array {
    const len = this.readU16();
    return this.take(len).slice();
  }

  /** Read a `u16`-length-prefixed UTF-8 string. Throws `bad_utf8` on invalid
   *  UTF-8 (the decoder is fatal). */
  readString(): string {
    const bytes = this.readBlob();
    try {
      return UTF8_DECODER.decode(bytes);
    } catch {
      throw new ProtoError('bad_utf8');
    }
  }

  /** Consume the reader, throwing `trailing_bytes` if any input remains. */
  finish(): void {
    if (this.remaining() !== 0) throw new ProtoError('trailing_bytes');
  }
}

/** An append-only big-endian writer. */
export class Writer {
  private chunks: number[] = [];

  putU8(v: number): void {
    this.chunks.push(v & 0xff);
  }

  putU16(v: number): void {
    this.chunks.push((v >>> 8) & 0xff, v & 0xff);
  }

  putU32(v: number): void {
    this.chunks.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff);
  }

  putU64(v: bigint): void {
    const buf = new Uint8Array(8);
    new DataView(buf.buffer).setBigUint64(0, v, false);
    this.putBytes(buf);
  }

  putBytes(v: Uint8Array): void {
    for (const b of v) this.chunks.push(b);
  }

  /** Write a `u16`-length-prefixed byte blob. Throws `string_too_long` if the
   *  blob would exceed `u16::MAX`. */
  putBlob(v: Uint8Array): void {
    if (v.length > 0xffff) throw new ProtoError('string_too_long');
    this.putU16(v.length);
    this.putBytes(v);
  }

  /** Write a `u16`-length-prefixed UTF-8 string. */
  putString(v: string): void {
    this.putBlob(UTF8_ENCODER.encode(v));
  }

  intoBytes(): Uint8Array {
    return Uint8Array.from(this.chunks);
  }
}

/** Lowercase-hex a byte array (test/QR helper; mirrors the Rust `hex`). */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** Parse a lowercase/uppercase hex string into bytes. Throws on odd length or a
 *  non-hex character. (`parseInt` would accept e.g. "1g" as 1, so validate the
 *  alphabet explicitly.) */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('hex: odd length');
  if (!/^[0-9a-fA-F]*$/.test(hex)) throw new Error('hex: non-hex character');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Constant-length equality for two byte arrays (not constant-time; used for
 *  wire-value comparisons, never secrets). */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
