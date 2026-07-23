/** End-to-end control sessions: the browser {@link Initiator} driven over an
 *  in-memory duplex against a test companion that plays the responder side of
 *  the wire (the Rust companion's happy path). Exercises pairing (SAS + key
 *  learning + fingerprint pin), a reconnect control session (full-key pin +
 *  scoped RPC), and the fail-closed aborts. */

import { describe, expect, it } from 'vitest';
import { toHex } from './codec';
import { Keypair, companionFingerprint, sasFromHandshakeHash } from './crypto';
import { Frame, FrameType } from './frame';
import { ClientHello, ServerHello, SessionKind } from './hello';
import { HandshakeState } from './noise';
import {
  ALL_METHODS,
  decodeMethodCall,
  decodeMsg,
  encodeMsg,
  method,
  scope,
  type MethodCall,
  type Msg,
} from './messages';
import { Initiator } from './session';
import { createDuplexPair, type FrameChannel } from './channel';
import { ControlKey, InMemoryControlKeyStore } from './controlKey';

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

interface Grant {
  scopes: number[];
  rooms: string[];
  expiresAtMs: bigint;
}

interface CompanionResult {
  sas: string;
  learnedStatic: Uint8Array;
  companionPublic: Uint8Array;
  received?: Msg;
}

/** The test companion: the responder half of the wire. */
async function runCompanion(
  ch: FrameChannel,
  companionStatic: Keypair,
  mode: 'pairing' | 'control',
  grant: Grant,
): Promise<CompanionResult> {
  const clientHelloFrame = await ch.readFrame();
  ClientHello.decodeBody(clientHelloFrame.body); // validate shape
  const serverHello = new ServerHello(1, 1);
  await ch.writeFrame(serverHello.toFrame());

  const prologue = concat(clientHelloFrame.encode(), serverHello.toFrame().encode());
  const resp = await HandshakeState.newResponder(companionStatic, prologue);
  await resp.readMessage1((await ch.readFrame()).body);
  await ch.writeFrame(new Frame(FrameType.Handshake2, await resp.writeMessage2()));
  const { transport, learnedStatic, handshakeHash } = await resp.readMessage3(
    (await ch.readFrame()).body,
  );
  const sas = await sasFromHandshakeHash(handshakeHash);
  const base = { sas, learnedStatic, companionPublic: companionStatic.publicRaw };

  if (mode === 'pairing') {
    const confirm = decodeMsg(await transport.decrypt((await ch.readFrame()).body));
    const result: Msg = {
      type: 'pair_result',
      installed: true,
      scopes: grant.scopes,
      rooms: grant.rooms,
      expiresAtMs: grant.expiresAtMs,
    };
    await ch.writeFrame(new Frame(FrameType.Transport, await transport.encrypt(encodeMsg(result))));
    return { ...base, received: confirm };
  }

  const accept: Msg = { type: 'session_accept', methods: [...ALL_METHODS], expiresAtMs: grant.expiresAtMs };
  await ch.writeFrame(new Frame(FrameType.Transport, await transport.encrypt(encodeMsg(accept))));
  const request = decodeMsg(await transport.decrypt((await ch.readFrame()).body));
  if (request.type !== 'request') throw new Error('expected a request');
  const call = decodeMethodCall(request.method, request.params);
  const body = new TextEncoder().encode(JSON.stringify({ echoed: call.type }));
  const response: Msg = { type: 'response', nonce: request.nonce, ok: true, body };
  await ch.writeFrame(new Frame(FrameType.Transport, await transport.encrypt(encodeMsg(response))));
  return { ...base, received: request };
}

/** Drive the browser through the plaintext hellos and the three handshake
 *  messages, leaving it ready for the transport phase. */
async function driveHandshake(ch: FrameChannel, initiator: Initiator, clientHello: Frame): Promise<void> {
  await ch.writeFrame(clientHello);
  const h1 = await initiator.onServerHello(await ch.readFrame());
  await ch.writeFrame(h1);
  const h3 = await initiator.onHandshake2(await ch.readFrame());
  await ch.writeFrame(h3);
}

describe('pairing session end-to-end', () => {
  it('learns and pins the companion key, agrees on the SAS, and installs a grant', async () => {
    const companionStatic = await Keypair.generate(true);
    const fp = await companionFingerprint(companionStatic.publicRaw);
    const controlKey = await ControlKey.generate();
    const [browser, companion] = createDuplexPair();

    const { initiator, clientHello } = Initiator.create({
      staticKey: controlKey.keypair,
      kind: SessionKind.Pairing,
      pairingNonce: new Uint8Array(16).fill(0x11),
      expectedFingerprint: fp,
    });

    const grant: Grant = {
      scopes: [scope.ROOM_READ, scope.MESSAGE_SEND],
      rooms: ['room-a'],
      expiresAtMs: 1_700_000_000_000n,
    };
    const companionTask = runCompanion(companion, companionStatic, 'pairing', grant);

    await driveHandshake(browser, initiator, clientHello);
    const pairResult = await (async () => {
      await browser.writeFrame(await initiator.pairConfirm());
      return initiator.read(await browser.readFrame());
    })();
    const companionResult = await companionTask;

    // Both sides derived the same SAS from the live transcript.
    expect(initiator.sas()).toBe(companionResult.sas);
    // The companion learned the browser control key…
    expect(toHex(companionResult.learnedStatic)).toBe(toHex(controlKey.publicRaw));
    // …and the browser learned + fingerprint-checked the companion key.
    expect(toHex(initiator.companionKey()!)).toBe(toHex(companionStatic.publicRaw));
    // The grant installed.
    expect(pairResult).toMatchObject({ type: 'pair_result', installed: true, rooms: ['room-a'] });
    // The companion saw exactly the browser's PairConfirm.
    expect(companionResult.received).toEqual({ type: 'pair_confirm' });
  });

  it('aborts before the SAS when the companion fingerprint does not match', async () => {
    const companionStatic = await Keypair.generate(true);
    const controlKey = await ControlKey.generate();
    const [browser, companion] = createDuplexPair();

    const { initiator, clientHello } = Initiator.create({
      staticKey: controlKey.keypair,
      kind: SessionKind.Pairing,
      pairingNonce: new Uint8Array(16).fill(0x22),
      expectedFingerprint: new Uint8Array(8).fill(0xff), // wrong pin
    });
    const grant: Grant = { scopes: [scope.ROOM_READ], rooms: [], expiresAtMs: 1n };
    const companionTask = runCompanion(companion, companionStatic, 'pairing', grant).catch(() => undefined);

    await browser.writeFrame(clientHello);
    const h1 = await initiator.onServerHello(await browser.readFrame());
    await browser.writeFrame(h1);
    await expect(initiator.onHandshake2(await browser.readFrame())).rejects.toMatchObject({
      kind: 'fingerprint_mismatch',
    });
    await browser.close();
    await companionTask;
  });
});

describe('control (reconnect) session end-to-end', () => {
  it('pins the stored companion key and drives a scoped send', async () => {
    const companionStatic = await Keypair.generate(true);
    const controlKey = await ControlKey.generate();
    const [browser, companion] = createDuplexPair();

    const { initiator, clientHello } = Initiator.create({
      staticKey: controlKey.keypair,
      kind: SessionKind.Control,
      expectedCompanionKey: companionStatic.publicRaw, // pinned from pairing
    });
    const grant: Grant = { scopes: [], rooms: [], expiresAtMs: 1_800_000_000_000n };
    const companionTask = runCompanion(companion, companionStatic, 'control', grant);

    await driveHandshake(browser, initiator, clientHello);
    const accept = await initiator.read(await browser.readFrame());
    expect(accept).toMatchObject({ type: 'session_accept' });
    expect((accept as { methods: number[] }).methods).toEqual([...ALL_METHODS]);

    const call: MethodCall = { type: 'message_send', roomId: 'room-a', body: 'hi', clientMsgId: 'c1' };
    await browser.writeFrame(await initiator.request(call));
    const response = await initiator.read(await browser.readFrame());
    expect(response).toMatchObject({ type: 'response', ok: true });

    const companionResult = await companionTask;
    expect(companionResult.received).toMatchObject({ type: 'request', method: method.MESSAGE_SEND });
  });

  it('aborts the handshake when the stored companion key does not match', async () => {
    const companionStatic = await Keypair.generate(true);
    const wrongKey = await Keypair.generate(true);
    const controlKey = await ControlKey.generate();
    const [browser, companion] = createDuplexPair();

    const { initiator, clientHello } = Initiator.create({
      staticKey: controlKey.keypair,
      kind: SessionKind.Control,
      expectedCompanionKey: wrongKey.publicRaw, // not the real companion
    });
    const grant: Grant = { scopes: [], rooms: [], expiresAtMs: 1n };
    const companionTask = runCompanion(companion, companionStatic, 'control', grant).catch(() => undefined);

    await browser.writeFrame(clientHello);
    const h1 = await initiator.onServerHello(await browser.readFrame());
    await browser.writeFrame(h1);
    await expect(initiator.onHandshake2(await browser.readFrame())).rejects.toMatchObject({
      kind: 'pin_mismatch',
    });
    await browser.close();
    await companionTask;
  });
});

describe('version negotiation', () => {
  it('aborts when the companion offers no compatible version (ServerHello v0)', async () => {
    const controlKey = await ControlKey.generate();
    const { initiator, clientHello } = Initiator.create({
      staticKey: controlKey.keypair,
      kind: SessionKind.Control,
    });
    void clientHello;
    const incompatible = new ServerHello(0, 2).toFrame();
    await expect(initiator.onServerHello(incompatible)).rejects.toMatchObject({
      kind: 'incompatible',
    });
  });

  it('rejects a wrong frame type at each step', async () => {
    const controlKey = await ControlKey.generate();
    const { initiator } = Initiator.create({
      staticKey: controlKey.keypair,
      kind: SessionKind.Control,
    });
    // onServerHello expects a ServerHello, not a Handshake2.
    await expect(
      initiator.onServerHello(new Frame(FrameType.Handshake2, new Uint8Array())),
    ).rejects.toMatchObject({ kind: 'unexpected' });
  });
});

describe('control-key storage', () => {
  it('generates a non-extractable key and round-trips it through the store', async () => {
    const key = await ControlKey.generate();
    expect(key.keypair.privateKey.extractable).toBe(false);
    expect(key.publicRaw).toHaveLength(32);
    expect(key.fingerprint).toHaveLength(8);

    const store = new InMemoryControlKeyStore();
    await store.saveControlKey(key.keypair.privateKey, key.publicRaw);
    const loaded = await store.loadControlKey();
    expect(loaded).not.toBeNull();
    const restored = await ControlKey.fromStored(loaded!.privateKey, loaded!.publicRaw);
    expect(toHex(restored.publicRaw)).toBe(toHex(key.publicRaw));
    expect(restored.fingerprintHex).toBe(key.fingerprintHex);

    // A restored non-extractable key still performs DH (it is usable, just not
    // exportable).
    const peer = await Keypair.generate(true);
    expect(await restored.keypair.dh(peer.publicRaw)).not.toBeNull();
  });

  it('stores and reads back a companion pin', async () => {
    const store = new InMemoryControlKeyStore();
    await store.savePin('0011223344556677', 'aabb');
    expect(await store.loadPin('0011223344556677')).toBe('aabb');
    expect(await store.loadPin('ffffffffffffffff')).toBeNull();
    await store.clear();
    expect(await store.loadPin('0011223344556677')).toBeNull();
  });
});
