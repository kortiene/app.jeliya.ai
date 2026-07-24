/** Crypto-primitive conformance: each WebCrypto-backed primitive is pinned to a
 *  published standard vector — the same standards the Rust side
 *  (crates/jeliya-control/src/crypto.rs) is pinned to — so a construction bug
 *  (endianness, HKDF ordering, nonce layout) fails here rather than "wrong but
 *  self-consistent" on the wire. */

import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from './codec';
import {
  Keypair,
  aeadOpen,
  aeadSeal,
  companionFingerprint,
  hmacSha256,
  noiseHkdf,
  sasFromHandshakeHash,
  sha256,
} from './crypto';

const enc = (s: string) => new TextEncoder().encode(s);

describe('SHA-256', () => {
  it('matches the empty-string and "abc" vectors', async () => {
    expect(toHex(await sha256(enc('')))).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(toHex(await sha256(enc('abc')))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});

describe('HMAC-SHA-256 (RFC 4231)', () => {
  it('test case 1', async () => {
    const mac = await hmacSha256(new Uint8Array(20).fill(0x0b), enc('Hi There'));
    expect(toHex(mac)).toBe('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
  });

  it('test case 2', async () => {
    const mac = await hmacSha256(enc('Jefe'), enc('what do ya want for nothing?'));
    expect(toHex(mac)).toBe('5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  });
});

describe('Noise HKDF', () => {
  it('is the documented HMAC chain, recomputed independently', async () => {
    // temp = HMAC(ck, ikm); out1 = HMAC(temp, 0x01);
    // out2 = HMAC(temp, out1 ‖ 0x02); out3 = HMAC(temp, out2 ‖ 0x03).
    const ck = new Uint8Array(32).fill(0x0b);
    const ikm = new Uint8Array(8).fill(0x42);
    const temp = await hmacSha256(ck, ikm);
    const want1 = await hmacSha256(temp, new Uint8Array([0x01]));
    const want2 = await hmacSha256(temp, new Uint8Array([...want1, 0x02]));
    const want3 = await hmacSha256(temp, new Uint8Array([...want2, 0x03]));

    const outs = await noiseHkdf(ck, ikm, 3);
    expect(outs).toHaveLength(3);
    expect(toHex(outs[0])).toBe(toHex(want1));
    expect(toHex(outs[1])).toBe(toHex(want2));
    expect(toHex(outs[2])).toBe(toHex(want3));
  });
});

describe('X25519 (RFC 7748 §5.2 vectors)', () => {
  it('reproduces the RFC 7748 §5.2 scalar-multiplication known answer', async () => {
    // X25519(scalar, u) — clamping is part of X25519, so DH against the u-point
    // yields the RFC output exactly.
    const scalar = fromHex('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4');
    const u = fromHex('e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c');
    const shared = await (await Keypair.fromScalarForTest(scalar)).dh(u);
    expect(shared).not.toBeNull();
    expect(toHex(shared!)).toBe('c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552');
  });

  it('DH agrees in both directions and rejects the all-zero peer key', async () => {
    const a = await Keypair.generate(true);
    const b = await Keypair.generate(true);
    const ab = await a.dh(b.publicRaw);
    const ba = await b.dh(a.publicRaw);
    expect(ab).not.toBeNull();
    expect(toHex(ab!)).toBe(toHex(ba!));
    expect(await a.dh(new Uint8Array(32))).toBeNull();
  });

  it('the fixed cross-vector static scalars produce the reference public keys', async () => {
    const initS = await Keypair.fromScalarForTest(new Uint8Array(32).fill(0x01));
    const respS = await Keypair.fromScalarForTest(new Uint8Array(32).fill(0x02));
    expect(toHex(initS.publicRaw)).toBe(
      'a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209',
    );
    expect(toHex(respS.publicRaw)).toBe(
      'ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59',
    );
  });
});

describe('AES-256-GCM (Noise nonce)', () => {
  it('round-trips and fails closed on wrong counter/ad/tamper', async () => {
    const key = new Uint8Array(32).fill(7);
    const ct = await aeadSeal(key, 3n, enc('ad'), enc('secret'));
    expect(new TextDecoder().decode(await aeadOpen(key, 3n, enc('ad'), ct))).toBe('secret');
    await expect(aeadOpen(key, 4n, enc('ad'), ct)).rejects.toThrow();
    await expect(aeadOpen(key, 3n, enc('AD'), ct)).rejects.toThrow();
    const bad = ct.slice();
    bad[0] ^= 1;
    await expect(aeadOpen(key, 3n, enc('ad'), bad)).rejects.toThrow();
    await expect(aeadOpen(key, 3n, enc('ad'), ct.slice(0, 8))).rejects.toThrow();
  });
});

describe('SAS + fingerprint', () => {
  it('formats two five-digit groups and is transcript-sensitive', async () => {
    const sas = await sasFromHandshakeHash(new Uint8Array(32).fill(0x11));
    expect(sas).toMatch(/^\d{5}-\d{5}$/);
    const other = await sasFromHandshakeHash(new Uint8Array(32).fill(0x12));
    expect(sas).not.toBe(other);
  });

  it('matches the cross-vector SAS', async () => {
    const hh = fromHex('0a6f21a6d31c3b20293c0bf26373a91cec3fbd52ac33e5e9786885566ece0655');
    expect(await sasFromHandshakeHash(hh)).toBe('17824-34733');
  });

  it('fingerprint is the first eight bytes of SHA-256(static)', async () => {
    const fp = await companionFingerprint(new Uint8Array(32).fill(0x11));
    expect(fp).toHaveLength(8);
    const full = await sha256(new Uint8Array(32).fill(0x11));
    expect(toHex(fp)).toBe(toHex(full.slice(0, 8)));
  });
});
