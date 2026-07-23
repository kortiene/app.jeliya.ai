import { describe, expect, it } from 'vitest';
import {
  buildCombinedInvite,
  EXPIRY_PRESETS,
  inviteState,
  isIdentityId,
  splitInvite,
  type InviteState,
} from './invite';
import fixtures from './conformance/invite-lifecycle.fixtures.json';

describe('splitInvite', () => {
  it('splits a combined invite and prefers an explicit address', () => {
    expect(splitInvite('roomtkt1abc#ep@h:1', '')).toEqual({ ticket: 'roomtkt1abc', peerAddr: 'ep@h:1' });
    expect(splitInvite('roomtkt1abc#ep@h:1', 'other@h:2')).toEqual({ ticket: 'roomtkt1abc', peerAddr: 'other@h:2' });
  });
});

describe('EXPIRY_PRESETS', () => {
  it('offers only time-boxed presets with the right seconds', () => {
    // No "never" preset: every invite is time-boxed — an omitted expiry gets
    // the daemon's 24-hour default (Phase 1 D4), so a no-expiry label would lie.
    expect(EXPIRY_PRESETS.map((p) => p.key)).toEqual(['1h', '24h', '7d']);
    expect(EXPIRY_PRESETS.map((p) => p.seconds)).toEqual([3600, 86400, 604800]);
    expect(EXPIRY_PRESETS.every((p) => p.seconds !== null)).toBe(true);
  });
});

// The shared corpus: identity validation, the combined invite, and the
// lifecycle derivation all pinned from ONE source (issue #66).
describe('shared invite-lifecycle fixtures', () => {
  for (const c of fixtures.identity as Array<{ value: string; valid: boolean }>) {
    it(`identity ${JSON.stringify(c.value)} → ${c.valid}`, () => {
      expect(isIdentityId(c.value)).toBe(c.valid);
    });
  }

  for (const c of fixtures.combined as Array<{ ticket: string; addr: string; combined: string }>) {
    it(`combined ${c.ticket}+${JSON.stringify(c.addr)}`, () => {
      expect(buildCombinedInvite(c.ticket, c.addr)).toBe(c.combined);
    });
  }

  for (const c of fixtures.lifecycle as Array<{
    name: string;
    identity_id: string;
    expires_at_ms: number | null;
    members: { identity_id: string; status: string }[];
    now_ms: number;
    state: InviteState;
  }>) {
    it(`lifecycle: ${c.name}`, () => {
      expect(
        inviteState({ identityId: c.identity_id, expiresAtMs: c.expires_at_ms }, c.members, c.now_ms),
      ).toBe(c.state);
    });
  }
});
