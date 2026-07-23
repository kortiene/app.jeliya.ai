/** Noise XX handshake conformance: self-interop (initiator ↔ responder) mirrors
 *  the Rust noise tests, and the deterministic fixed-scalar vector cross-checks
 *  the WebCrypto initiator against the Rust reference byte-for-byte. */

import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from './codec';
import { Keypair, sasFromHandshakeHash } from './crypto';
import { HandshakeState, NoiseError } from './noise';
import vector from './conformance/noise-cross-vector.json';

const enc = (s: string) => new TextEncoder().encode(s);

async function runHandshake(prologue: Uint8Array) {
  const init = await HandshakeState.newInitiator(await Keypair.generate(true), prologue);
  const resp = await HandshakeState.newResponder(await Keypair.generate(true), prologue);
  const m1 = await init.writeMessage1();
  await resp.readMessage1(m1);
  const m2 = await resp.writeMessage2();
  await init.readMessage2(m2);
  const { msg: m3, transport: initT, handshakeHash: ihh } = await init.writeMessage3();
  const { transport: respT, handshakeHash: rhh, learnedStatic } = await resp.readMessage3(m3);
  return { init, resp, initT, respT, ihh, rhh, learnedStatic, m1, m2, m3 };
}

describe('self-interop', () => {
  it('completes with agreeing handshake hashes', async () => {
    const { ihh, rhh } = await runHandshake(enc('prologue'));
    expect(toHex(ihh)).toBe(toHex(rhh));
  });

  it('the responder learns the initiator control key', async () => {
    const initStatic = await Keypair.generate(true);
    const init = await HandshakeState.newInitiator(initStatic, enc('p'));
    const resp = await HandshakeState.newResponder(await Keypair.generate(true), enc('p'));
    await resp.readMessage1(await init.writeMessage1());
    await init.readMessage2(await resp.writeMessage2());
    const { msg: m3 } = await init.writeMessage3();
    const { learnedStatic } = await resp.readMessage3(m3);
    expect(toHex(learnedStatic)).toBe(toHex(initStatic.publicRaw));
  });

  it('transport messages flow both ways', async () => {
    const { initT, respT } = await runHandshake(enc('p'));
    const ct = await initT.encrypt(enc('ping'));
    expect(new TextDecoder().decode(await respT.decrypt(ct))).toBe('ping');
    const ct2 = await respT.encrypt(enc('pong'));
    expect(new TextDecoder().decode(await initT.decrypt(ct2))).toBe('pong');
  });

  it('fixed message sizes: 32 / 96 / 64', async () => {
    const init = await HandshakeState.newInitiator(await Keypair.generate(true), enc('p'));
    const resp = await HandshakeState.newResponder(await Keypair.generate(true), enc('p'));
    const m1 = await init.writeMessage1();
    expect(m1).toHaveLength(32);
    await resp.readMessage1(m1);
    const m2 = await resp.writeMessage2();
    expect(m2).toHaveLength(96);
    await init.readMessage2(m2);
    const { msg: m3 } = await init.writeMessage3();
    expect(m3).toHaveLength(64);
  });

  it('a tampered message 2 fails authentication', async () => {
    const init = await HandshakeState.newInitiator(await Keypair.generate(true), enc('p'));
    const resp = await HandshakeState.newResponder(await Keypair.generate(true), enc('p'));
    await resp.readMessage1(await init.writeMessage1());
    const m2 = await resp.writeMessage2();
    m2[40] ^= 1; // flip a bit in the encrypted static key field
    await expect(init.readMessage2(m2)).rejects.toMatchObject({ kind: 'aead' });
  });

  it('different prologues break the handshake', async () => {
    const init = await HandshakeState.newInitiator(await Keypair.generate(true), enc('client-offer-A'));
    const resp = await HandshakeState.newResponder(await Keypair.generate(true), enc('client-offer-B'));
    await resp.readMessage1(await init.writeMessage1());
    const m2 = await resp.writeMessage2();
    await expect(init.readMessage2(m2)).rejects.toBeInstanceOf(NoiseError);
  });

  it('an out-of-order transport frame fails', async () => {
    const { initT, respT } = await runHandshake(enc('p'));
    const c1 = await initT.encrypt(enc('one'));
    const c2 = await initT.encrypt(enc('two'));
    await expect(respT.decrypt(c2)).rejects.toMatchObject({ kind: 'aead' });
    void c1;
  });

  it('concurrent encrypts never reuse an AES-GCM nonce', async () => {
    const { initT, respT } = await runHandshake(enc('p'));
    // Fire many encrypts WITHOUT awaiting between them (the Promise.all idiom).
    // If the counter were read-before-await/incremented-after, several would
    // seal under the same nonce and the in-order decrypts below would fail.
    const plaintexts = Array.from({ length: 8 }, (_, i) => enc(`msg-${i}`));
    const cts = await Promise.all(plaintexts.map((p) => initT.encrypt(p)));
    // All ciphertexts are distinct (same key + distinct nonce + distinct/likely
    // plaintext) — a reused nonce on identical-length messages would collide the
    // keystream.
    expect(new Set(cts.map(toHex)).size).toBe(cts.length);
    // And the receiver decrypts them in counter order, proving the nonces were
    // 0,1,2,… exactly once each.
    for (let i = 0; i < cts.length; i++) {
      expect(new TextDecoder().decode(await respT.decrypt(cts[i]))).toBe(`msg-${i}`);
    }
  });
});

describe('cross-impl vector (against the Rust reference)', () => {
  it('reproduces m1/m3/hash/SAS and interoperates with the Rust transcript', async () => {
    const initStatic = await Keypair.fromScalarForTest(fromHex(vector.init_static_scalar));
    const initEphemeral = await Keypair.fromScalarForTest(fromHex(vector.init_ephemeral_scalar));
    const prologue = fromHex(vector.prologue);

    const init = await HandshakeState.newInitiator(initStatic, prologue);
    init.presetEphemeralForTest(initEphemeral);

    // msg1 the initiator writes must equal the Rust reference byte-for-byte.
    const m1 = await init.writeMessage1();
    expect(toHex(m1)).toBe(vector.m1);

    // The initiator consumes the Rust responder's msg2…
    await init.readMessage2(fromHex(vector.m2));
    // …learns the reference companion static key…
    expect(toHex(init.remoteStatic()!)).toBe(vector.resp_static_public);

    // …emits the exact msg3, and derives the same hash + SAS as the reference.
    const { msg: m3, transport, handshakeHash } = await init.writeMessage3();
    expect(toHex(m3)).toBe(vector.m3);
    expect(toHex(handshakeHash)).toBe(vector.handshake_hash);
    expect(await sasFromHandshakeHash(handshakeHash)).toBe(vector.sas);

    // Transport interop: the initiator's ciphertext matches the reference, and
    // it decrypts the reference responder→initiator message.
    const outbound = await transport.encrypt(enc(vector.transport_init_to_resp_plaintext));
    expect(toHex(outbound)).toBe(vector.transport_init_to_resp);
    const inbound = await transport.decrypt(fromHex(vector.transport_resp_to_init));
    expect(new TextDecoder().decode(inbound)).toBe(vector.transport_resp_to_init_plaintext);
  });
});
