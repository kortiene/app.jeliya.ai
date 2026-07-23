/** The v1 registries and the transport-phase messages carried inside AEAD
 *  frames. The plaintext of a `Transport` frame is `u8 msg_type ‖ msg_body`;
 *  this module encodes and decodes that plaintext and the method-call params.
 *  Mirror of `jeliya-protocol::{registry, message}`. It never touches
 *  ciphertext — sealing/opening is the Noise layer's job in `noise.ts`. */

import { ProtoError, Reader, Writer } from './codec';

/** Method registry ids (`Request.method`, `SessionAccept.methods`). These are
 *  the only methods the wire can express; everything else is unrepresentable. */
export const method = {
  ROOM_TIMELINE: 0x0001,
  ROOM_MEMBERS: 0x0002,
  MESSAGE_SEND: 0x0003,
} as const;

export const ALL_METHODS: readonly number[] = [
  method.ROOM_TIMELINE,
  method.ROOM_MEMBERS,
  method.MESSAGE_SEND,
];

/** Scope registry ids (`PairResult.scopes`). */
export const scope = {
  ROOM_READ: 0x0001,
  MESSAGE_SEND: 0x0002,
} as const;

/** `SessionReject.reason` codes. */
export const reject = {
  UNKNOWN_KEY: 1,
  REVOKED: 2,
  EXPIRED: 3,
  BUSY: 4,
  INCOMPATIBLE: 5,
} as const;

/** `Response` error codes (`ok = false`). */
export const error = {
  DENIED_UNKNOWN_KEY: 0x0001,
  DENIED_REVOKED: 0x0002,
  DENIED_EXPIRED: 0x0003,
  DENIED_SCOPE: 0x0004,
  DENIED_ROOM: 0x0005,
  DENIED_REPLAY: 0x0006,
  DENIED_RATE_LIMITED: 0x0007,
  METHOD_UNKNOWN: 0x0008,
  PARAMS_INVALID: 0x0009,
  ENGINE_ERROR: 0x000a,
} as const;

const ERROR_NAMES: Record<number, string> = {
  [error.DENIED_UNKNOWN_KEY]: 'denied_unknown_key',
  [error.DENIED_REVOKED]: 'denied_revoked',
  [error.DENIED_EXPIRED]: 'denied_expired',
  [error.DENIED_SCOPE]: 'denied_scope',
  [error.DENIED_ROOM]: 'denied_room',
  [error.DENIED_REPLAY]: 'denied_replay',
  [error.DENIED_RATE_LIMITED]: 'denied_rate_limited',
  [error.METHOD_UNKNOWN]: 'method_unknown',
  [error.PARAMS_INVALID]: 'params_invalid',
  [error.ENGINE_ERROR]: 'engine_error',
};

/** The registry error name for a `Response` error code (for logging/tests). */
export function errorName(code: number): string {
  return ERROR_NAMES[code] ?? 'unknown';
}

/** Which scope a method requires. Throws for an unknown method id so the caller
 *  fails closed before any scope evaluation. */
export function scopeForMethod(methodId: number): number {
  switch (methodId) {
    case method.ROOM_TIMELINE:
    case method.ROOM_MEMBERS:
      return scope.ROOM_READ;
    case method.MESSAGE_SEND:
      return scope.MESSAGE_SEND;
    default:
      throw new ProtoError('bad_enum', 'method');
  }
}

// ---- Transport messages -------------------------------------------------

const T_SESSION_ACCEPT = 0x01;
const T_SESSION_REJECT = 0x02;
const T_PAIR_CONFIRM = 0x03;
const T_PAIR_RESULT = 0x04;
const T_REQUEST = 0x10;
const T_RESPONSE = 0x11;

/** The maximum entries in any bounded count field (methods, scopes, rooms). */
const MAX_LIST = 256;

/** A decoded transport message (discriminated on `type`). */
export type Msg =
  | { type: 'session_accept'; methods: number[]; expiresAtMs: bigint }
  | { type: 'session_reject'; reason: number }
  | { type: 'pair_confirm' }
  | { type: 'pair_result'; installed: boolean; scopes: number[]; rooms: string[]; expiresAtMs: bigint }
  | { type: 'request'; nonce: bigint; method: number; params: Uint8Array }
  | { type: 'response'; nonce: bigint; ok: boolean; body: Uint8Array };

function putU16List(w: Writer, list: number[], what: string): void {
  if (list.length > MAX_LIST) throw new ProtoError('bad_count', what);
  w.putU16(list.length);
  for (const v of list) w.putU16(v);
}

function readU16List(r: Reader, what: string): number[] {
  const count = r.readU16();
  if (count > MAX_LIST) throw new ProtoError('bad_count', what);
  const out: number[] = [];
  for (let i = 0; i < count; i++) out.push(r.readU16());
  return out;
}

function readBool(r: Reader): boolean {
  const v = r.readU8();
  if (v === 0) return false;
  if (v === 1) return true;
  throw new ProtoError('bad_enum', 'bool');
}

export function encodeMsg(msg: Msg): Uint8Array {
  const w = new Writer();
  switch (msg.type) {
    case 'session_accept':
      w.putU8(T_SESSION_ACCEPT);
      putU16List(w, msg.methods, 'methods');
      w.putU64(msg.expiresAtMs);
      break;
    case 'session_reject':
      w.putU8(T_SESSION_REJECT);
      w.putU16(msg.reason);
      break;
    case 'pair_confirm':
      w.putU8(T_PAIR_CONFIRM);
      break;
    case 'pair_result':
      w.putU8(T_PAIR_RESULT);
      w.putU8(msg.installed ? 1 : 0);
      putU16List(w, msg.scopes, 'scopes');
      if (msg.rooms.length > MAX_LIST) throw new ProtoError('bad_count', 'rooms');
      w.putU16(msg.rooms.length);
      for (const room of msg.rooms) w.putString(room);
      w.putU64(msg.expiresAtMs);
      break;
    case 'request':
      w.putU8(T_REQUEST);
      w.putU64(msg.nonce);
      w.putU16(msg.method);
      w.putBlob(msg.params);
      break;
    case 'response':
      w.putU8(T_RESPONSE);
      w.putU64(msg.nonce);
      w.putU8(msg.ok ? 1 : 0);
      w.putBlob(msg.body);
      break;
  }
  return w.intoBytes();
}

export function decodeMsg(buf: Uint8Array): Msg {
  const r = new Reader(buf);
  const msgType = r.readU8();
  let msg: Msg;
  switch (msgType) {
    case T_SESSION_ACCEPT: {
      const methods = readU16List(r, 'methods');
      const expiresAtMs = r.readU64();
      msg = { type: 'session_accept', methods, expiresAtMs };
      break;
    }
    case T_SESSION_REJECT:
      msg = { type: 'session_reject', reason: r.readU16() };
      break;
    case T_PAIR_CONFIRM:
      msg = { type: 'pair_confirm' };
      break;
    case T_PAIR_RESULT: {
      const installed = readBool(r);
      const scopes = readU16List(r, 'scopes');
      const roomCount = r.readU16();
      if (roomCount > MAX_LIST) throw new ProtoError('bad_count', 'rooms');
      const rooms: string[] = [];
      for (let i = 0; i < roomCount; i++) rooms.push(r.readString());
      const expiresAtMs = r.readU64();
      msg = { type: 'pair_result', installed, scopes, rooms, expiresAtMs };
      break;
    }
    case T_REQUEST:
      msg = {
        type: 'request',
        nonce: r.readU64(),
        method: r.readU16(),
        params: r.readBlob(),
      };
      break;
    case T_RESPONSE:
      msg = {
        type: 'response',
        nonce: r.readU64(),
        ok: readBool(r),
        body: r.readBlob(),
      };
      break;
    default:
      throw new ProtoError('bad_enum', 'msg_type');
  }
  r.finish();
  return msg;
}

/** Build an error `Response` carrying a registry error code and message. */
export function errorResponse(nonce: bigint, code: number, message: string): Msg {
  const w = new Writer();
  w.putU16(code);
  w.putString(message);
  return { type: 'response', nonce, ok: false, body: w.intoBytes() };
}

/** Decode an error `Response.body` into `{ code, message }`. */
export function decodeErrorBody(body: Uint8Array): { code: number; message: string } {
  const r = new Reader(body);
  const code = r.readU16();
  const message = r.readString();
  r.finish();
  return { code, message };
}

// ---- Method-call params -------------------------------------------------

/** The decoded, method-specific parameters of a `Request`. */
export type MethodCall =
  | { type: 'room_timeline'; roomId: string; limit: number | null; after: string | null }
  | { type: 'room_members'; roomId: string }
  | { type: 'message_send'; roomId: string; body: string; clientMsgId: string };

/** The v1 `room.timeline` `limit` cap (mirrors `MAX_TIMELINE_LIMIT`). */
export const MAX_TIMELINE_LIMIT = 500;

/** The method id for a decoded call. */
export function methodIdFor(call: MethodCall): number {
  switch (call.type) {
    case 'room_timeline':
      return method.ROOM_TIMELINE;
    case 'room_members':
      return method.ROOM_MEMBERS;
    case 'message_send':
      return method.MESSAGE_SEND;
  }
}

/** The room id this call names (every v1 method is room-scoped). */
export function roomIdOf(call: MethodCall): string {
  return call.roomId;
}

/** Return the call with any wire-bounded field clamped to its v1 maximum. A
 *  `room.timeline` `limit` is capped at {@link MAX_TIMELINE_LIMIT}. */
export function clampCall(call: MethodCall): MethodCall {
  if (call.type === 'room_timeline' && call.limit !== null) {
    return { ...call, limit: Math.min(call.limit, MAX_TIMELINE_LIMIT) };
  }
  return call;
}

export function encodeMethodCall(call: MethodCall): Uint8Array {
  const w = new Writer();
  switch (call.type) {
    case 'room_timeline':
      w.putString(call.roomId);
      if (call.limit !== null) {
        w.putU8(1);
        w.putU32(call.limit);
      } else {
        w.putU8(0);
      }
      if (call.after !== null) {
        w.putU8(1);
        w.putString(call.after);
      } else {
        w.putU8(0);
      }
      break;
    case 'room_members':
      w.putString(call.roomId);
      break;
    case 'message_send':
      w.putString(call.roomId);
      w.putString(call.body);
      w.putString(call.clientMsgId);
      break;
  }
  return w.intoBytes();
}

/** Decode the params blob for a method id. An unknown method id is the caller's
 *  responsibility to reject *before* calling this; this throws `bad_enum` for
 *  one as a guard. */
export function decodeMethodCall(methodId: number, params: Uint8Array): MethodCall {
  const r = new Reader(params);
  let call: MethodCall;
  switch (methodId) {
    case method.ROOM_TIMELINE: {
      const roomId = r.readString();
      const limit = readBool(r) ? r.readU32() : null;
      const after = readBool(r) ? r.readString() : null;
      call = { type: 'room_timeline', roomId, limit, after };
      break;
    }
    case method.ROOM_MEMBERS:
      call = { type: 'room_members', roomId: r.readString() };
      break;
    case method.MESSAGE_SEND:
      call = {
        type: 'message_send',
        roomId: r.readString(),
        body: r.readString(),
        clientMsgId: r.readString(),
      };
      break;
    default:
      throw new ProtoError('bad_enum', 'method');
  }
  r.finish();
  return call;
}
