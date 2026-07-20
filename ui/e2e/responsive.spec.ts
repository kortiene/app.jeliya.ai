import { expect, test, MOCK_ROOMS, shellForWidth } from './fixtures';
import type { Page } from '@playwright/test';

// The responsive contract (docs/room-workbench.md, decision 3; issue #62).
//
// The four viewport projects fix one size each; this spec walks the widths the
// contract actually names — 360, 899, 900, 920, 1280 — inside one project, so
// the boundaries are pinned rather than sampled. It runs on the wide project
// only: every case sets its own viewport, so running the same assertions again
// under three more projects would just be the same test four times.
//
// On text scaling: the design sizes text in px, so the browser-faithful model
// of "the user made everything bigger" is page zoom, and page zoom is
// mathematically a narrower viewport. WCAG 1.4.10 fixes the target at 320 CSS
// px — which is 1280 at 400% — so the 320 cases below ARE the zoom coverage.
// OS-level text scaling (textScale 2.0) is not exposed to a browser page, so
// it has no equivalent here; docs/accessibility-checklist.md records the gap.

test.skip(({ viewport }) => (viewport?.width ?? 0) !== 1440, 'viewport-driven: one project is enough');

const WIDTHS = [360, 899, 900, 920, 1280] as const;

/** iPhone-class insets. The app reads every inset through these custom
 *  properties, so overriding them exercises the real mechanism — headless
 *  Chromium reports no insets of its own. */
async function withSafeAreas(page: Page): Promise<void> {
  await page.addStyleTag({
    content: ':root { --safe-top: 44px; --safe-bottom: 34px; --safe-left: 12px; --safe-right: 12px; }',
  });
}

async function hasHorizontalOverflow(page: Page): Promise<boolean> {
  return page.evaluate(() => document.documentElement.scrollWidth > document.documentElement.clientWidth + 1);
}

test.describe('the shell each width renders', () => {
  for (const width of WIDTHS) {
    const shell = shellForWidth(width);

    test(`${width}px is the ${shell} shell`, async ({ app, page }) => {
      await page.setViewportSize({ width, height: 800 });
      await app.gotoPopulated();

      // The room rail: a pane of its own on compact (hidden while in a room),
      // always present beside the workspace above it.
      if (shell === 'compact') {
        await expect(app.sidebar).toBeHidden();
        await expect(app.center).toBeVisible();
      } else {
        await expect(app.sidebar).toBeVisible();
        await expect(app.center).toBeVisible();
      }

      // The inspector is closed on Activity at every width — that is what
      // `activity` means (decision 3).
      await expect(app.rightPanel).toBeHidden();
    });
  }
});

test.describe('the workspace is never squeezed', () => {
  for (const width of WIDTHS) {
    test(`${width}px leaves the workspace usable`, async ({ app, page }) => {
      await page.setViewportSize({ width, height: 800 });
      await app.gotoPopulated();

      // The regression this band exists to prevent: at 901px the old grid
      // (232 rail + 1fr + 300 inspector) left the workspace 369px — narrower
      // than the phone layout it had just graduated from.
      const centerWidth = await app.center.evaluate((el) => el.getBoundingClientRect().width);
      expect(centerWidth).toBeGreaterThan(340);

      await expect(app.timeline).toBeVisible();
      await expect(app.composerTextarea).toBeVisible();
      expect(await hasHorizontalOverflow(page)).toBe(false);
    });
  }
});

test('medium floats the inspector over the workspace; wide gives it a column', async ({ app, page }) => {
  // 920: medium. The inspector must not take a column from a workspace this
  // narrow, so it floats — and the workspace keeps its width while it is open.
  await page.setViewportSize({ width: 920, height: 800 });
  await app.gotoPopulated();
  const centerBefore = await app.center.evaluate((el) => el.getBoundingClientRect().width);

  await app.goToRoomDest('People');
  const centerAfter = await app.center.evaluate((el) => el.getBoundingClientRect().width);
  expect(centerAfter).toBe(centerBefore);
  const drawer = await app.rightPanel.evaluate((el) => el.getBoundingClientRect());
  const centerBox = await app.center.evaluate((el) => el.getBoundingClientRect());
  // A drawer: it overlaps the workspace and pins to its right edge.
  expect(Math.round(drawer.right)).toBe(Math.round(centerBox.right));
  expect(drawer.left).toBeLessThan(centerBox.right);
  expect(drawer.left).toBeGreaterThan(centerBox.left);

  // 1280: wide. The inspector stops overlapping and takes its own column,
  // which the workspace pays for.
  await page.setViewportSize({ width: 1280, height: 800 });
  await expect(app.rightPanel).toBeVisible();
  const wideCenter = await app.center.evaluate((el) => el.getBoundingClientRect());
  const wideInspector = await app.rightPanel.evaluate((el) => el.getBoundingClientRect());
  expect(Math.round(wideInspector.left)).toBeGreaterThanOrEqual(Math.round(wideCenter.right) - 1);
  expect(await hasHorizontalOverflow(page)).toBe(false);
});

test('the inspector is collapsible, and collapsing it is navigating to Activity', async ({ app, page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await app.gotoPopulated();

  await app.goToRoomDest('Files');
  await expect(page).toHaveURL(/\/rooms\/[^/]+\/files$/);

  await page.getByRole('button', { name: 'Close inspector' }).click();
  await expect(app.rightPanel).toBeHidden();
  // The inspector's openness is not a second state: it IS the route.
  await expect(page).toHaveURL(/\/rooms\/[^/]+\/activity$/);
});

test('selecting a room tool preserves the timeline position', async ({ app, page }) => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await app.gotoPopulated();
  await expect(app.timeline).toBeVisible();

  // The backlog has to be in before a reading position means anything: the
  // timeline renders while room.open is still in flight, and the room opens
  // pinned to its newest event only once the backlog is really there.
  await expect(app.timeline.locator('.timeline-row').last()).toBeInViewport();
  await expect.poll(() => app.timelineBottomOffset()).toBeLessThanOrEqual(140);

  // The reading position is WHICH row sits at the top of the scrollport — not
  // an offset derived from scrollHeight, which grows every time the mock's
  // live-event timers append a row below the viewport (issue #61: the flake
  // was exactly one appended row's height). Anchor on a mid-history row:
  // neither reset can imitate it — a fresh mount pins to the newest event and
  // a scroller that lost its state starts back at 0, so either failure of
  // decision 3 (panes hide, they do not unmount) moves this anchor by
  // hundreds of pixels.
  const rows = app.timeline.locator('.timeline-row');
  const anchor = rows.nth(Math.floor((await rows.count()) / 2));
  await anchor.evaluate((el) => {
    const scroller = el.closest('.timeline')!;
    scroller.scrollTop += el.getBoundingClientRect().top - scroller.getBoundingClientRect().top;
  });
  const anchorOffset = () =>
    anchor.evaluate((el) => {
      const scroller = el.closest('.timeline')!;
      return el.getBoundingClientRect().top - scroller.getBoundingClientRect().top;
    });

  // Let the scroll settle before capturing the baseline: two consecutive
  // identical reads, never a value captured mid-scroll.
  let previous = Number.NaN;
  await expect
    .poll(async () => {
      const current = await anchorOffset();
      const settled = current === previous;
      previous = current;
      return settled;
    })
    .toBe(true);
  const before = previous;
  // Genuinely mid-history: away from both the top and the stick-to-bottom band.
  expect(await app.timeline.evaluate((el) => el.scrollTop)).toBeGreaterThan(0);
  expect(await app.timelineBottomOffset()).toBeGreaterThan(140);

  // Open and close the inspector. Panes hide, they do not unmount (decision
  // 3) — the reading position is the user's, and toggling a side panel is not
  // a request to move it.
  await app.goToRoomDest('People');
  await app.goToRoomDest('Activity');
  await expect(app.timeline).toBeVisible();

  // The same row is back at the same place in the scrollport. ±2px: the
  // inspector column narrows and re-widens the timeline, and the browser's
  // scroll anchoring restores the position across each reflow in device-pixel
  // steps — sub-pixel residue, not position loss. Either unmount reset sits
  // hundreds of pixels away, far outside this bound.
  await expect.poll(async () => Math.abs((await anchorOffset()) - before)).toBeLessThanOrEqual(2);
});

test.describe('safe areas', () => {
  for (const width of [360, 320] as const) {
    test(`${width}px reserves the insets without clipping`, async ({ app, page }) => {
      await page.setViewportSize({ width, height: 568 });
      await app.gotoPopulated();
      await withSafeAreas(page);

      // Inside a room the bottom bar is gone, so the composer owes the home
      // indicator its inset and nothing else.
      await expect(app.composerTextarea).toBeVisible();
      expect(await hasHorizontalOverflow(page)).toBe(false);

      const composer = await app.composerTextarea.evaluate((el) => el.getBoundingClientRect());
      expect(composer.bottom).toBeLessThanOrEqual(568);

      // The rooms pane owes the tab bar its height plus the inset, so that its
      // last row is never hidden behind the bottom chrome. Asserted on the
      // pane's own last element rather than on a room row: the room list is a
      // scroller, and a row below its fold is legitimately off-screen.
      await app.navigate('Rooms');
      await expect(app.roomItem(MOCK_ROOMS.main)).toBeVisible();
      expect(await hasHorizontalOverflow(page)).toBe(false);

      const bar = await app.tabBar.evaluate((el) => el.getBoundingClientRect());
      const paneEnd = await app.sidebar.evaluate((el) => {
        const style = getComputedStyle(el);
        return el.getBoundingClientRect().bottom - parseFloat(style.paddingBottom);
      });
      expect(paneEnd).toBeLessThanOrEqual(bar.top + 1);
    });
  }
});

test('the connection banner reserves space instead of covering the room', async ({ app, page }) => {
  await page.setViewportSize({ width: 360, height: 640 });
  // Hold room.open long enough to still be reconnecting-free but give the
  // banner a reason to exist: drop the socket after boot.
  await app.gotoPopulated();
  await expect(app.timeline).toBeVisible();

  const backBefore = await page.getByRole('button', { name: 'Back to Rooms' }).evaluate((el) => {
    const r = el.getBoundingClientRect();
    return { top: r.top, left: r.left };
  });

  await page.evaluate(() => window.dispatchEvent(new Event('offline')));
  const banner = page.locator('.conn-banner');
  if (await banner.isVisible()) {
    const back = page.getByRole('button', { name: 'Back to Rooms' });
    // Reserved, not overlaid: the banner pushes the app bar down rather than
    // covering the one control the user needs in order to leave.
    const backAfter = await back.evaluate((el) => el.getBoundingClientRect().top);
    expect(backAfter).toBeGreaterThanOrEqual(backBefore.top);
    const bannerBox = await banner.evaluate((el) => el.getBoundingClientRect());
    const backBox = await back.evaluate((el) => el.getBoundingClientRect());
    expect(bannerBox.bottom).toBeLessThanOrEqual(backBox.top + 1);
    expect(await hasHorizontalOverflow(page)).toBe(false);
  }
});
