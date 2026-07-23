/** The cryptographic primitives the control wire's Noise handshake and SAS are
 *  built from, implemented entirely on the platform WebCrypto (`crypto.subtle`)
 *  — no third-party crypto dependency enters this security-critical path:
 *
 *    - X25519 for the Diffie-Hellman (the static control key is a
 *      **non-extractable** `CryptoKey`; its private half never leaves WebCrypto),
 *    - AES-256-GCM for the AEAD (Noise's 96-bit nonce = 32 zero bits ‖ 64-bit
 *      big-endian counter),
 *    - SHA-256 and HMAC-SHA-256 as the hash and MAC.
 *
 *  HMAC-SHA-256 and the Noise HKDF are composed here from `subtle` HMAC exactly
 *  as the Rust side hand-rolls them over `sha2` (crates/jeliya-control/src/
 *  crypto.rs); the RFC-4231 / Noise-chain vectors in crypto.test.ts pin the
 *  construction. Browser support floor: WebCrypto X25519 (Chrome/Edge 133+,
 *  Safari 17+, Firefox 132+) and Node 18+. */

export const HASHLEN = 32;
export const TAGLEN = 16;
export const DHLEN = 32;

const subtle = globalThis.crypto.subtle;

/** Copy into a fresh ArrayBuffer-backed view. WebCrypto's `BufferSource` param
 *  type wants `Uint8Array<ArrayBuffer>`, but slices/subarrays of our byte
 *  buffers widen to `Uint8Array<ArrayBufferLike>` under TS's strict typed
 *  arrays; a tiny copy at the WebCrypto boundary keeps the types honest without
 *  an `as` cast. All inputs here are small (keys, nonces, handshake messages). */
function ab(u: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(u.length);
  copy.set(u);
  return copy;
}

/** An AEAD authentication failure (wrong key, tampered ciphertext, wrong nonce
 *  or associated data) — the only error the AEAD surfaces to the Noise layer. */
export class AeadError extends Error {
  constructor() {
    super('aead');
    this.name = 'AeadError';
  }
}

/** SHA-256 of `data`. */
export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle.digest('SHA-256', ab(data)));
}

/** HMAC-SHA-256 (RFC 2104) of `msg` under `key`. WebCrypto handles a key longer
 *  than the block internally, matching the Rust construction. */
export async function hmacSha256(key: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', ab(key), { name: 'HMAC', hash: 'SHA-256' }, false, [
    'sign',
  ]);
  return new Uint8Array(await subtle.sign('HMAC', k, ab(msg)));
}

/** The Noise HKDF: `temp = HMAC(ck, ikm)`, `out1 = HMAC(temp, 0x01)`,
 *  `out2 = HMAC(temp, out1 ‖ 0x02)`, `out3 = HMAC(temp, out2 ‖ 0x03)`. Returns
 *  2 or 3 outputs of {@link HASHLEN} bytes. */
export async function noiseHkdf(
  chainingKey: Uint8Array,
  ikm: Uint8Array,
  numOutputs: 2 | 3,
): Promise<Uint8Array[]> {
  const tempKey = await hmacSha256(chainingKey, ikm);
  const out1 = await hmacSha256(tempKey, new Uint8Array([0x01]));
  const in2 = new Uint8Array(HASHLEN + 1);
  in2.set(out1);
  in2[HASHLEN] = 0x02;
  const out2 = await hmacSha256(tempKey, in2);
  const outputs = [out1, out2];
  if (numOutputs === 3) {
    const in3 = new Uint8Array(HASHLEN + 1);
    in3.set(out2);
    in3[HASHLEN] = 0x03;
    outputs.push(await hmacSha256(tempKey, in3));
  }
  return outputs;
}

/** The Noise AES-GCM nonce: 4 zero bytes ‖ 64-bit big-endian `counter`. */
function noiseNonce(counter: bigint): Uint8Array<ArrayBuffer> {
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setBigUint64(4, counter, false);
  return nonce;
}

/** AES-256-GCM encrypt with the Noise nonce construction, returning
 *  `ciphertext ‖ tag`. */
export async function aeadSeal(
  key: Uint8Array,
  counter: bigint,
  ad: Uint8Array,
  plaintext: Uint8Array,
): Promise<Uint8Array> {
  const k = await subtle.importKey('raw', ab(key), 'AES-GCM', false, ['encrypt']);
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv: noiseNonce(counter), additionalData: ab(ad), tagLength: 128 },
    k,
    ab(plaintext),
  );
  return new Uint8Array(ct);
}

/** AES-256-GCM decrypt of `ciphertext ‖ tag`. Throws {@link AeadError} on any
 *  authentication failure. */
export async function aeadOpen(
  key: Uint8Array,
  counter: bigint,
  ad: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  if (data.length < TAGLEN) throw new AeadError();
  const k = await subtle.importKey('raw', ab(key), 'AES-GCM', false, ['decrypt']);
  try {
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv: noiseNonce(counter), additionalData: ab(ad), tagLength: 128 },
      k,
      ab(data),
    );
    return new Uint8Array(pt);
  } catch {
    throw new AeadError();
  }
}

// ---- X25519 -------------------------------------------------------------

/** The DER OneAsymmetricKey (PKCS#8) prefix for an X25519 private key: the
 *  16-byte header before the 32-byte raw scalar. Used only to import a fixed
 *  scalar for deterministic test vectors — production keys are generated
 *  non-extractably and never touch a raw scalar. */
const X25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);

/** The X25519 base point (`u = 9`), used to derive a public key from a private
 *  one via `deriveBits(private, base) = X25519(scalar, 9)`. */
const X25519_BASE_POINT = (() => {
  const b = new Uint8Array(32);
  b[0] = 9;
  return b;
})();

async function importX25519Public(raw: Uint8Array): Promise<CryptoKey> {
  return subtle.importKey('raw', ab(raw), { name: 'X25519' }, false, []);
}

async function deriveShared(priv: CryptoKey, theirPublicRaw: Uint8Array): Promise<Uint8Array> {
  const pub = await importX25519Public(theirPublicRaw);
  const bits = await subtle.deriveBits({ name: 'X25519', public: pub }, priv, 256);
  return new Uint8Array(bits);
}

function isAllZero(bytes: Uint8Array): boolean {
  for (const b of bytes) if (b !== 0) return false;
  return true;
}

/** An X25519 keypair. The private half is a `CryptoKey` (non-extractable for
 *  production control keys); the public half is the 32 raw bytes. */
export class Keypair {
  private constructor(
    readonly privateKey: CryptoKey,
    readonly publicRaw: Uint8Array,
  ) {}

  /** Generate a fresh keypair. `extractable` governs only the private half; a
   *  production control key passes `false` so its scalar can never be exported.
   *  Ephemerals pass `false` too (they are used once and discarded). */
  static async generate(extractable = false): Promise<Keypair> {
    const pair = (await subtle.generateKey({ name: 'X25519' }, extractable, [
      'deriveBits',
    ])) as CryptoKeyPair;
    const publicRaw = new Uint8Array(await subtle.exportKey('raw', pair.publicKey));
    return new Keypair(pair.privateKey, publicRaw);
  }

  /** Import a keypair from a fixed 32-byte scalar. **Test-only**: it goes
   *  through an extractable PKCS#8 import, which a non-extractable production key
   *  never does. Used to reproduce the deterministic cross-impl handshake
   *  vector. */
  static async fromScalarForTest(scalar: Uint8Array): Promise<Keypair> {
    if (scalar.length !== 32) throw new Error('x25519 scalar must be 32 bytes');
    const pkcs8 = new Uint8Array(X25519_PKCS8_PREFIX.length + 32);
    pkcs8.set(X25519_PKCS8_PREFIX);
    pkcs8.set(scalar, X25519_PKCS8_PREFIX.length);
    const priv = await subtle.importKey('pkcs8', ab(pkcs8), { name: 'X25519' }, false, [
      'deriveBits',
    ]);
    const publicRaw = await deriveShared(priv, X25519_BASE_POINT);
    return new Keypair(priv, publicRaw);
  }

  /** Adopt an already-imported non-extractable private `CryptoKey` (e.g. one
   *  loaded from IndexedDB) together with its known raw public key. */
  static fromCryptoKey(privateKey: CryptoKey, publicRaw: Uint8Array): Keypair {
    return new Keypair(privateKey, publicRaw);
  }

  /** X25519 Diffie-Hellman against `theirPublicRaw`. Returns the 32-byte shared
   *  secret, or `null` for a non-contributory / low-order peer key — which the
   *  Noise layer treats as a handshake abort. Two shapes map to `null`: an
   *  all-zero shared secret (the Rust `dh` return), and a `deriveBits` that
   *  *throws* (some WebCrypto backends reject a low-order point at derivation
   *  time instead of yielding the zero output). Both are the same fail-closed
   *  outcome. */
  async dh(theirPublicRaw: Uint8Array): Promise<Uint8Array | null> {
    let shared: Uint8Array;
    try {
      shared = await deriveShared(this.privateKey, theirPublicRaw);
    } catch {
      return null;
    }
    return isAllZero(shared) ? null : shared;
  }
}

// ---- SAS + fingerprint --------------------------------------------------

const SAS_LABEL = new TextEncoder().encode('jeliya/control/sas/v1');

/** Derive the SAS display string `"ddddd-ddddd"` from a completed 32-byte
 *  handshake hash (mirror of `sas_from_handshake_hash`). Both parties compute it
 *  from the same `h`, so both display the same string; the user compares them. */
export async function sasFromHandshakeHash(handshakeHash: Uint8Array): Promise<string> {
  const mac = await hmacSha256(handshakeHash, SAS_LABEL);
  const group1 = (mac[0] << 8) | mac[1];
  const group2 = (mac[2] << 8) | mac[3];
  return `${String(group1).padStart(5, '0')}-${String(group2).padStart(5, '0')}`;
}

/** The companion static-key fingerprint: `SHA-256(static)[0..8]` (8 bytes),
 *  the value pinned in the QR/link and checked before the SAS. */
export async function companionFingerprint(staticPublic: Uint8Array): Promise<Uint8Array> {
  return (await sha256(staticPublic)).slice(0, 8);
}
