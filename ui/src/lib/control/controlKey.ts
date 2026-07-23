/** The browser's long-lived control key and its persistence.
 *
 *  The control key is a **non-extractable** X25519 `CryptoKey`: its private
 *  scalar never leaves WebCrypto and can never be serialized, so a stolen
 *  storage snapshot yields no usable key. Persistence therefore stores the
 *  `CryptoKey` object itself (structured-clonable) rather than any bytes — only
 *  IndexedDB can do that, so storage is abstracted behind {@link ControlKeyStore}
 *  with an IndexedDB implementation for the browser and an in-memory one for
 *  tests (and for a memory-only, re-pair-every-load posture). */

import { toHex } from './codec';
import { Keypair, companionFingerprint } from './crypto';

/** The browser's control identity: the non-extractable keypair plus its
 *  QR/link fingerprint. */
export class ControlKey {
  private constructor(
    readonly keypair: Keypair,
    /** `SHA-256(publicRaw)[0..8]` — the value a companion would pin. */
    readonly fingerprint: Uint8Array,
  ) {}

  get publicRaw(): Uint8Array {
    return this.keypair.publicRaw;
  }

  get fingerprintHex(): string {
    return toHex(this.fingerprint);
  }

  /** Generate a fresh, non-extractable control key. */
  static async generate(): Promise<ControlKey> {
    const keypair = await Keypair.generate(false);
    return new ControlKey(keypair, await companionFingerprint(keypair.publicRaw));
  }

  /** Reconstruct from a persisted non-extractable private key + its raw public. */
  static async fromStored(privateKey: CryptoKey, publicRaw: Uint8Array): Promise<ControlKey> {
    const keypair = Keypair.fromCryptoKey(privateKey, publicRaw);
    return new ControlKey(keypair, await companionFingerprint(publicRaw));
  }
}

/** Persistence for the control key and the companion keys it has pinned. A pin
 *  maps a companion fingerprint (hex) to the full companion public key (hex)
 *  learned at pairing; a later control session verifies the full key against it. */
export interface ControlKeyStore {
  saveControlKey(privateKey: CryptoKey, publicRaw: Uint8Array): Promise<void>;
  loadControlKey(): Promise<{ privateKey: CryptoKey; publicRaw: Uint8Array } | null>;
  savePin(companionFingerprintHex: string, companionPublicHex: string): Promise<void>;
  loadPin(companionFingerprintHex: string): Promise<string | null>;
  clear(): Promise<void>;
}

/** An in-memory store — for tests and for a deliberately non-persistent posture
 *  (the control key is re-generated and the browser re-pairs every load). */
export class InMemoryControlKeyStore implements ControlKeyStore {
  private controlKey: { privateKey: CryptoKey; publicRaw: Uint8Array } | null = null;
  private readonly pins = new Map<string, string>();

  saveControlKey(privateKey: CryptoKey, publicRaw: Uint8Array): Promise<void> {
    this.controlKey = { privateKey, publicRaw: publicRaw.slice() };
    return Promise.resolve();
  }

  loadControlKey(): Promise<{ privateKey: CryptoKey; publicRaw: Uint8Array } | null> {
    return Promise.resolve(this.controlKey);
  }

  savePin(companionFingerprintHex: string, companionPublicHex: string): Promise<void> {
    this.pins.set(companionFingerprintHex, companionPublicHex);
    return Promise.resolve();
  }

  loadPin(companionFingerprintHex: string): Promise<string | null> {
    return Promise.resolve(this.pins.get(companionFingerprintHex) ?? null);
  }

  clear(): Promise<void> {
    this.controlKey = null;
    this.pins.clear();
    return Promise.resolve();
  }
}

const DB_NAME = 'jeliya-control';
const DB_VERSION = 1;
const STORE = 'control';
const CONTROL_KEY_ID = 'control-key';
const PIN_PREFIX = 'pin:';

/** IndexedDB-backed store for the browser. Stores the non-extractable
 *  `CryptoKey` object directly (structured clone preserves non-extractability),
 *  so nothing key-bearing is ever serialized to bytes. Thin glue over the async
 *  IndexedDB API; the protocol logic it serves is covered by the in-memory
 *  store's tests. */
export class IndexedDbControlKeyStore implements ControlKeyStore {
  static isAvailable(): boolean {
    return typeof indexedDB !== 'undefined';
  }

  private open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }

  private async tx<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest): Promise<T> {
    const db = await this.open();
    try {
      return await new Promise<T>((resolve, reject) => {
        const request = run(db.transaction(STORE, mode).objectStore(STORE));
        request.onsuccess = () => resolve(request.result as T);
        request.onerror = () => reject(request.error);
      });
    } finally {
      db.close();
    }
  }

  async saveControlKey(privateKey: CryptoKey, publicRaw: Uint8Array): Promise<void> {
    await this.tx('readwrite', (s) => s.put({ privateKey, publicRaw: publicRaw.slice() }, CONTROL_KEY_ID));
  }

  async loadControlKey(): Promise<{ privateKey: CryptoKey; publicRaw: Uint8Array } | null> {
    const row = await this.tx<{ privateKey: CryptoKey; publicRaw: Uint8Array } | undefined>(
      'readonly',
      (s) => s.get(CONTROL_KEY_ID),
    );
    return row ?? null;
  }

  async savePin(companionFingerprintHex: string, companionPublicHex: string): Promise<void> {
    await this.tx('readwrite', (s) => s.put(companionPublicHex, PIN_PREFIX + companionFingerprintHex));
  }

  async loadPin(companionFingerprintHex: string): Promise<string | null> {
    const row = await this.tx<string | undefined>('readonly', (s) =>
      s.get(PIN_PREFIX + companionFingerprintHex),
    );
    return row ?? null;
  }

  async clear(): Promise<void> {
    await this.tx('readwrite', (s) => s.clear());
  }
}
