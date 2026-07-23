/** The control-wire conformance corpus, reproduced in TypeScript. Every golden
 *  hex here is copied from `crates/jeliya-protocol/src/tests.rs` — the browser
 *  controller re-implements this wire and must produce the same bytes. If a
 *  re-encode changes the bytes, this fails here rather than silently on the
 *  wire. */

import { describe, expect, it } from 'vitest';
import { ProtoError, fromHex, toHex } from './codec';
import { Frame, FrameType } from './frame';
import { ClientHello, ServerHello, SessionKind } from './hello';
import {
  MAX_TIMELINE_LIMIT,
  clampCall,
  decodeErrorBody,
  decodeMethodCall,
  decodeMsg,
  encodeMethodCall,
  encodeMsg,
  error,
  errorName,
  errorResponse,
  method,
  reject,
  scope,
  scopeForMethod,
  ALL_METHODS,
  type Msg,
  type MethodCall,
} from './messages';

describe('golden fixtures (byte-for-byte with the Rust corpus)', () => {
  it('client_hello_golden', () => {
    const hello = new ClientHello([1], SessionKind.Pairing, new Uint8Array(16).fill(0x11));
    const expected = '4a43544c0100010111111111111111111111111111111111';
    expect(toHex(hello.encodeBody())).toBe(expected);
    const decoded = ClientHello.decodeBody(fromHex(expected));
    expect(decoded.versions).toEqual([1]);
    expect(decoded.sessionKind).toBe(SessionKind.Pairing);
    expect(toHex(decoded.pairingNonce)).toBe('11'.repeat(16));
  });

  it('server_hello_golden', () => {
    const hello = new ServerHello(1, 1);
    const expected = '4a43544c00010001';
    expect(toHex(hello.encodeBody())).toBe(expected);
    const decoded = ServerHello.decodeBody(fromHex(expected));
    expect(decoded.version).toBe(1);
    expect(decoded.minVersion).toBe(1);
  });

  it('request_golden', () => {
    const params = encodeMethodCall({
      type: 'message_send',
      roomId: 'r1',
      body: 'hi',
      clientMsgId: 'c1',
    });
    expect(toHex(params)).toBe('000272310002686900026331');
    const req: Msg = { type: 'request', nonce: 1n, method: method.MESSAGE_SEND, params };
    const expected = '1000000000000000010003000c000272310002686900026331';
    expect(toHex(encodeMsg(req))).toBe(expected);
    expect(decodeMsg(fromHex(expected))).toEqual(req);
  });

  it('frame_wraps_length_and_type', () => {
    const body = new Uint8Array([0xaa, 0xbb, 0xcc]);
    const frame = new Frame(FrameType.Transport, body);
    expect(toHex(frame.encode())).toBe('0000000310aabbcc');
    const { frame: decoded, consumed } = Frame.decodePrefix(frame.encode());
    expect(decoded.frameType).toBe(FrameType.Transport);
    expect(toHex(decoded.body)).toBe('aabbcc');
    expect(consumed).toBe(8);
  });
});

describe('every message round-trips', () => {
  const cases: Msg[] = [
    { type: 'session_accept', methods: [...ALL_METHODS], expiresAtMs: 1_700_000_000_000n },
    { type: 'session_reject', reason: reject.REVOKED },
    { type: 'pair_confirm' },
    {
      type: 'pair_result',
      installed: true,
      scopes: [scope.ROOM_READ, scope.MESSAGE_SEND],
      rooms: ['room-1', 'room-2'],
      expiresAtMs: 42n,
    },
    { type: 'request', nonce: 7n, method: method.ROOM_TIMELINE, params: new Uint8Array([1, 2, 3]) },
    { type: 'response', nonce: 7n, ok: true, body: new Uint8Array([9, 9]) },
  ];
  for (const original of cases) {
    it(`round-trips ${original.type}`, () => {
      expect(decodeMsg(encodeMsg(original))).toEqual(original);
    });
  }
});

describe('method calls round-trip', () => {
  const cases: MethodCall[] = [
    { type: 'room_timeline', roomId: 'r', limit: null, after: null },
    { type: 'room_timeline', roomId: 'r', limit: 50, after: 'ev-123' },
    { type: 'room_members', roomId: 'r' },
    { type: 'message_send', roomId: 'r', body: 'hello', clientMsgId: 'c' },
  ];
  for (const call of cases) {
    it(`round-trips ${call.type}`, () => {
      const decoded = decodeMethodCall(
        call.type === 'room_timeline'
          ? method.ROOM_TIMELINE
          : call.type === 'room_members'
            ? method.ROOM_MEMBERS
            : method.MESSAGE_SEND,
        encodeMethodCall(call),
      );
      expect(decoded).toEqual(call);
    });
  }

  it('non-ASCII strings survive UTF-8 round-trip', () => {
    const call: MethodCall = { type: 'message_send', roomId: 'salón', body: '日本語 🎉', clientMsgId: 'ç' };
    const decoded = decodeMethodCall(method.MESSAGE_SEND, encodeMethodCall(call));
    expect(decoded).toEqual(call);
  });

  it('a leading U+FEFF (BOM) is preserved, not stripped', () => {
    // Rust from_utf8 keeps a leading BOM as an ordinary character; the browser
    // decoder must agree or the two sides read the same bytes as different
    // strings. The wire bytes for '﻿hi' start ef bb bf.
    const call: MethodCall = { type: 'message_send', roomId: '﻿hi', body: 'x', clientMsgId: 'c' };
    const encoded = encodeMethodCall(call);
    expect(toHex(encoded).startsWith('0005efbbbf6869')).toBe(true);
    expect(decodeMethodCall(method.MESSAGE_SEND, encoded)).toEqual(call);
  });
});

describe('strict-parse negatives', () => {
  it('trailing bytes are rejected', () => {
    const good = new ServerHello(1, 1).encodeBody();
    const withTrailing = new Uint8Array([...good, 0x00]);
    expect(() => ServerHello.decodeBody(withTrailing)).toThrow(ProtoError);
  });

  it('a control ClientHello with a non-zero nonce is rejected', () => {
    const w = new Uint8Array([
      0x4a, 0x43, 0x54, 0x4c, // JCTL
      0x01, 0x00, 0x01, // 1 version = 1
      0x02, // control
      ...new Uint8Array(16).fill(1), // non-zero nonce
    ]);
    expect(() => ClientHello.decodeBody(w)).toThrow(ProtoError);
  });

  it('an unknown frame type is rejected', () => {
    // len=1, type=0x99, body=1 byte
    expect(() => Frame.decodeExact(fromHex('0000000199aa'))).toThrow(ProtoError);
  });

  it('a bad hello magic is rejected', () => {
    expect(() => ServerHello.decodeBody(fromHex('deadbeef00010001'))).toThrow(ProtoError);
  });

  it('a short input is rejected', () => {
    expect(() => ServerHello.decodeBody(fromHex('4a43544c00'))).toThrow(ProtoError);
  });

  it('an over-large frame length is rejected before allocation', () => {
    // length = 0x00020000 (131072 > MAX_FRAME_LEN), type 0x10
    expect(() => Frame.decodePrefix(fromHex('0002000010'))).toThrow(ProtoError);
  });

  it('an empty version list is rejected', () => {
    // JCTL | count=0 | kind ...
    expect(() => ClientHello.decodeBody(fromHex('4a43544c0001' + '00'.repeat(16)))).toThrow(
      ProtoError,
    );
  });

  it('a bool byte other than 0/1 is rejected', () => {
    // Response: type 0x11 | nonce(8) | ok=0x02 (invalid) | blob(len=0)
    expect(() => decodeMsg(fromHex('1100000000000000010' + '2' + '0000'))).toThrow(ProtoError);
  });

  it('fromHex rejects a non-hex character parseInt would silently accept', () => {
    expect(() => fromHex('1g')).toThrow();
    expect(() => fromHex('abc')).toThrow(); // odd length
  });
});

describe('registry, error, and clamp helpers', () => {
  it('maps every method to its required scope and rejects unknown', () => {
    expect(scopeForMethod(method.ROOM_TIMELINE)).toBe(scope.ROOM_READ);
    expect(scopeForMethod(method.ROOM_MEMBERS)).toBe(scope.ROOM_READ);
    expect(scopeForMethod(method.MESSAGE_SEND)).toBe(scope.MESSAGE_SEND);
    expect(() => scopeForMethod(0xbeef)).toThrow(ProtoError);
  });

  it('names error codes and round-trips an error response body', () => {
    expect(errorName(error.DENIED_ROOM)).toBe('denied_room');
    expect(errorName(error.ENGINE_ERROR)).toBe('engine_error');
    expect(errorName(0xffff)).toBe('unknown');
    const resp = errorResponse(9n, error.DENIED_SCOPE, 'nope');
    expect(resp).toMatchObject({ type: 'response', nonce: 9n, ok: false });
    if (resp.type === 'response') {
      expect(decodeErrorBody(resp.body)).toEqual({ code: error.DENIED_SCOPE, message: 'nope' });
    }
  });

  it('clamps a room.timeline limit at the v1 maximum and leaves other calls alone', () => {
    const clamped = clampCall({ type: 'room_timeline', roomId: 'r', limit: 100_000, after: null });
    expect(clamped).toMatchObject({ limit: MAX_TIMELINE_LIMIT });
    const atMax = clampCall({ type: 'room_timeline', roomId: 'r', limit: MAX_TIMELINE_LIMIT, after: null });
    expect(atMax).toMatchObject({ limit: MAX_TIMELINE_LIMIT });
    const nullLimit = clampCall({ type: 'room_timeline', roomId: 'r', limit: null, after: null });
    expect(nullLimit).toMatchObject({ limit: null });
    const send: MethodCall = { type: 'message_send', roomId: 'r', body: 'b', clientMsgId: 'c' };
    expect(clampCall(send)).toEqual(send);
  });
});
