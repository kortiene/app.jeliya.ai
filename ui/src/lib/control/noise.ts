/** `Noise_XX_25519_AESGCM_SHA256` (Noise rev 34) — the mutually-authenticated,
 *  forward-secret, initiator-identity-hiding handshake ADR #2 decision 2
 *  specifies, ported to WebCrypto as the exact mirror of the Rust responder in
 *  `crates/jeliya-control/src/noise.rs`. The initiator here is the browser; the
 *  responder is included for in-process interop tests (the live companion is the
 *  Rust responder). Payloads are empty in v1 (still authenticated), so message
 *  sizes are fixed: msg1 = 32 bytes, msg2 = 96 bytes, msg3 = 64 bytes.
 *
 *  Every method is async because WebCrypto's hash/HMAC/DH/AEAD are async. */

import {
  AeadError,
  DHLEN,
  HASHLEN,
  Keypair,
  TAGLEN,
  aeadOpen,
  aeadSeal,
  noiseHkdf,
  sha256,
} from './crypto';

const PROTOCOL_NAME = new TextEncoder().encode('Noise_XX_25519_AESGCM_SHA256'); // 28 bytes
const ENC_STATIC_LEN = DHLEN + TAGLEN; // 48
const EMPTY_PAYLOAD_CT = TAGLEN; // 16
const U64_MAX = (1n << 64n) - 1n;
const EMPTY = new Uint8Array(0);

/** A handshake failure. Every kind aborts the handshake and (at the transport
 *  layer) closes the connection. Mirrors the Rust `NoiseError`. */
export type NoiseErrorKind = 'aead' | 'bad_message' | 'non_contributory_key' | 'nonce_exhausted';

export class NoiseError extends Error {
  readonly kind: NoiseErrorKind;
  constructor(kind: NoiseErrorKind) {
    super(kind);
    this.name = 'NoiseError';
    this.kind = kind;
  }
}

function concat(...parts: Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/** A minimal async mutex: runs operations one at a time, in call order. It
 *  restores the serialization the Rust `CipherState` gets for free from
 *  `&mut self` — critical here because the AEAD is async, so without it two
 *  overlapping `encryptWithAd` calls would both read the counter before either
 *  incremented it and reuse an AES-GCM nonce (catastrophic: keystream reuse +
 *  GHASH-key recovery). Each `CipherState` owns one. */
class Mutex {
  private tail: Promise<unknown> = Promise.resolve();

  runExclusive<T>(fn: () => Promise<T>): Promise<T> {
    // Queue behind whatever is already running (regardless of its outcome), so
    // this operation's read-modify-write of the nonce cannot interleave.
    const run = this.tail.then(fn, fn);
    this.tail = run.then(
      () => undefined,
      () => undefined,
    );
    return run;
  }
}

/** A keyed AES-GCM cipherstate with a strictly-incrementing 64-bit nonce (Noise
 *  §5.1). An unkeyed cipherstate is a passthrough (the pre-first-`mix_key`
 *  phase). Every read-modify-write of the nonce runs under {@link Mutex}, so the
 *  counter advances exactly once per record even under concurrent callers — the
 *  nonce is never reused. `decrypt` advances the counter only on a successful
 *  open (a failed open aborts the session), matching the Rust semantics. */
class CipherState {
  private nonce = 0n;
  private readonly lock = new Mutex();
  constructor(private readonly key: Uint8Array | null) {}

  static empty(): CipherState {
    return new CipherState(null);
  }

  static keyed(key: Uint8Array): CipherState {
    return new CipherState(key);
  }

  encryptWithAd(ad: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
    return this.lock.runExclusive(async () => {
      if (this.key === null) return plaintext.slice();
      if (this.nonce === U64_MAX) throw new NoiseError('nonce_exhausted');
      const ct = await aeadSeal(this.key, this.nonce, ad, plaintext);
      this.nonce += 1n;
      return ct;
    });
  }

  decryptWithAd(ad: Uint8Array, ciphertext: Uint8Array): Promise<Uint8Array> {
    return this.lock.runExclusive(async () => {
      if (this.key === null) return ciphertext.slice();
      if (this.nonce === U64_MAX) throw new NoiseError('nonce_exhausted');
      let pt: Uint8Array;
      try {
        pt = await aeadOpen(this.key, this.nonce, ad, ciphertext);
      } catch (err) {
        if (err instanceof AeadError) throw new NoiseError('aead');
        throw err;
      }
      this.nonce += 1n;
      return pt;
    });
  }
}

/** The Noise symmetric state: chaining key, handshake hash, and the current
 *  handshake cipherstate. */
class SymmetricState {
  private constructor(
    private ck: Uint8Array,
    public h: Uint8Array,
    private cs: CipherState,
  ) {}

  static async initialize(prologue: Uint8Array): Promise<SymmetricState> {
    // protocol_name is 28 bytes < HASHLEN, so h = name ‖ zeros.
    const h = new Uint8Array(HASHLEN);
    h.set(PROTOCOL_NAME);
    const sym = new SymmetricState(h.slice(), h, CipherState.empty());
    await sym.mixHash(prologue);
    return sym;
  }

  async mixHash(data: Uint8Array): Promise<void> {
    this.h = await sha256(concat(this.h, data));
  }

  async mixKey(ikm: Uint8Array): Promise<void> {
    const out = await noiseHkdf(this.ck, ikm, 2);
    this.ck = out[0];
    this.cs = CipherState.keyed(out[1]);
  }

  async encryptAndHash(plaintext: Uint8Array): Promise<Uint8Array> {
    const ct = await this.cs.encryptWithAd(this.h, plaintext);
    await this.mixHash(ct);
    return ct;
  }

  async decryptAndHash(ciphertext: Uint8Array): Promise<Uint8Array> {
    const pt = await this.cs.decryptWithAd(this.h, ciphertext);
    await this.mixHash(ciphertext);
    return pt;
  }

  async split(): Promise<[CipherState, CipherState]> {
    const out = await noiseHkdf(this.ck, EMPTY, 2);
    return [CipherState.keyed(out[0]), CipherState.keyed(out[1])];
  }
}

/** The post-handshake transport state: two cipherstates, one per direction. */
export class TransportState {
  private constructor(
    private readonly send: CipherState,
    private readonly recv: CipherState,
  ) {}

  static fromSplit(split: [CipherState, CipherState], initiator: boolean): TransportState {
    const [cs1, cs2] = split;
    return initiator ? new TransportState(cs1, cs2) : new TransportState(cs2, cs1);
  }

  /** Encrypt an outbound transport message (associated data is empty). */
  encrypt(plaintext: Uint8Array): Promise<Uint8Array> {
    return this.send.encryptWithAd(EMPTY, plaintext);
  }

  /** Decrypt an inbound transport message. A frame that fails here (tamper,
   *  reorder, replay, truncation) aborts the session. */
  decrypt(ciphertext: Uint8Array): Promise<Uint8Array> {
    return this.recv.decryptWithAd(EMPTY, ciphertext);
  }
}

/** The XX handshake state for one party. */
export class HandshakeState {
  private constructor(
    private readonly sym: SymmetricState,
    private readonly s: Keypair,
    private e: Keypair | null = null,
    private rs: Uint8Array | null = null,
    private re: Uint8Array | null = null,
  ) {}

  static async newInitiator(s: Keypair, prologue: Uint8Array): Promise<HandshakeState> {
    return new HandshakeState(await SymmetricState.initialize(prologue), s);
  }

  static async newResponder(s: Keypair, prologue: Uint8Array): Promise<HandshakeState> {
    return new HandshakeState(await SymmetricState.initialize(prologue), s);
  }

  /** The remote static public key learned during the handshake. `null` before
   *  it is received. */
  remoteStatic(): Uint8Array | null {
    return this.rs;
  }

  /** Inject a fixed ephemeral before the first message. **Test-only**: it
   *  reproduces the deterministic cross-impl handshake vector. */
  presetEphemeralForTest(e: Keypair): void {
    this.e = e;
  }

  private async ephemeral(): Promise<Keypair> {
    if (this.e === null) this.e = await Keypair.generate(false);
    return this.e;
  }

  // ---- Initiator --------------------------------------------------------

  /** Initiator writes message 1 (`e`). */
  async writeMessage1(): Promise<Uint8Array> {
    const epub = (await this.ephemeral()).publicRaw;
    await this.sym.mixHash(epub);
    return concat(epub, await this.sym.encryptAndHash(EMPTY));
  }

  /** Initiator reads message 2 (`e, ee, s, es`). */
  async readMessage2(msg: Uint8Array): Promise<void> {
    if (msg.length !== DHLEN + ENC_STATIC_LEN + EMPTY_PAYLOAD_CT) {
      throw new NoiseError('bad_message');
    }
    const re = msg.slice(0, DHLEN);
    await this.sym.mixHash(re);
    this.re = re;
    const e = this.e;
    if (e === null) throw new NoiseError('bad_message');
    const ee = await e.dh(re);
    if (ee === null) throw new NoiseError('non_contributory_key');
    await this.sym.mixKey(ee);
    const rsPt = await this.sym.decryptAndHash(msg.slice(DHLEN, DHLEN + ENC_STATIC_LEN));
    if (rsPt.length !== DHLEN) throw new NoiseError('bad_message');
    this.rs = rsPt;
    const es = await e.dh(rsPt);
    if (es === null) throw new NoiseError('non_contributory_key');
    await this.sym.mixKey(es);
    const payload = await this.sym.decryptAndHash(msg.slice(DHLEN + ENC_STATIC_LEN));
    if (payload.length !== 0) throw new NoiseError('bad_message');
  }

  /** Initiator writes message 3 (`s, se`) and completes, returning the message,
   *  the transport state, and the handshake hash (the SAS input). */
  async writeMessage3(): Promise<{ msg: Uint8Array; transport: TransportState; handshakeHash: Uint8Array }> {
    const re = this.re;
    if (re === null) throw new NoiseError('bad_message');
    const encStatic = await this.sym.encryptAndHash(this.s.publicRaw);
    const se = await this.s.dh(re);
    if (se === null) throw new NoiseError('non_contributory_key');
    await this.sym.mixKey(se);
    const encPayload = await this.sym.encryptAndHash(EMPTY);
    const handshakeHash = this.sym.h.slice();
    const transport = TransportState.fromSplit(await this.sym.split(), true);
    return { msg: concat(encStatic, encPayload), transport, handshakeHash };
  }

  // ---- Responder (test interop) ----------------------------------------

  /** Responder reads message 1 (`e`). */
  async readMessage1(msg: Uint8Array): Promise<void> {
    if (msg.length !== DHLEN) throw new NoiseError('bad_message');
    const re = msg.slice(0, DHLEN);
    await this.sym.mixHash(re);
    this.re = re;
    const payload = await this.sym.decryptAndHash(msg.slice(DHLEN));
    if (payload.length !== 0) throw new NoiseError('bad_message');
  }

  /** Responder writes message 2 (`e, ee, s, es`). */
  async writeMessage2(): Promise<Uint8Array> {
    const re = this.re;
    if (re === null) throw new NoiseError('bad_message');
    const epub = (await this.ephemeral()).publicRaw;
    await this.sym.mixHash(epub);
    const e = this.e;
    if (e === null) throw new NoiseError('bad_message');
    const ee = await e.dh(re);
    if (ee === null) throw new NoiseError('non_contributory_key');
    await this.sym.mixKey(ee);
    const encStatic = await this.sym.encryptAndHash(this.s.publicRaw);
    const es = await this.s.dh(re);
    if (es === null) throw new NoiseError('non_contributory_key');
    await this.sym.mixKey(es);
    const encPayload = await this.sym.encryptAndHash(EMPTY);
    return concat(epub, encStatic, encPayload);
  }

  /** Responder reads message 3 (`s, se`) and completes, returning the transport
   *  state, the learned initiator static key, and the handshake hash. */
  async readMessage3(
    msg: Uint8Array,
  ): Promise<{ transport: TransportState; learnedStatic: Uint8Array; handshakeHash: Uint8Array }> {
    if (msg.length !== ENC_STATIC_LEN + EMPTY_PAYLOAD_CT) throw new NoiseError('bad_message');
    const rsPt = await this.sym.decryptAndHash(msg.slice(0, ENC_STATIC_LEN));
    if (rsPt.length !== DHLEN) throw new NoiseError('bad_message');
    this.rs = rsPt;
    const e = this.e;
    if (e === null) throw new NoiseError('bad_message');
    const se = await e.dh(rsPt);
    if (se === null) throw new NoiseError('non_contributory_key');
    await this.sym.mixKey(se);
    const payload = await this.sym.decryptAndHash(msg.slice(ENC_STATIC_LEN));
    if (payload.length !== 0) throw new NoiseError('bad_message');
    const handshakeHash = this.sym.h.slice();
    const transport = TransportState.fromSplit(await this.sym.split(), false);
    return { transport, learnedStatic: rsPt, handshakeHash };
  }
}
