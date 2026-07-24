/** The transport-agnostic frame channel the control session runs over. The
 *  session logic never names a socket: it reads and writes {@link Frame}s over
 *  this interface, so the same Initiator drives an in-memory duplex (tests), and
 *  — in a later PR — a real browser↔companion transport (WebTransport over a
 *  relay; the direct Iroh path is not dialable from a browser). */

import { Frame } from './frame';

/** Raised when a channel is read after its peer closed and no frame remains. */
export class ChannelClosedError extends Error {
  constructor() {
    super('channel closed');
    this.name = 'ChannelClosedError';
  }
}

export interface FrameChannel {
  /** Await the next inbound frame. Rejects with {@link ChannelClosedError} once
   *  the peer has closed and the inbound queue is drained. */
  readFrame(): Promise<Frame>;
  /** Send one frame to the peer. */
  writeFrame(frame: Frame): Promise<void>;
  /** Close this side; the peer's pending/next `readFrame` sees the close once it
   *  has consumed everything already sent. */
  close(): Promise<void>;
}

/** A one-directional async frame queue with a close signal. */
class FrameQueue {
  private readonly items: Frame[] = [];
  private readonly waiters: Array<{ resolve: (f: Frame) => void; reject: (e: unknown) => void }> = [];
  private closed = false;

  push(frame: Frame): void {
    const waiter = this.waiters.shift();
    if (waiter) waiter.resolve(frame);
    else this.items.push(frame);
  }

  close(): void {
    this.closed = true;
    // Wake every waiter that will now never receive a frame.
    while (this.waiters.length > 0) this.waiters.shift()!.reject(new ChannelClosedError());
  }

  take(): Promise<Frame> {
    const next = this.items.shift();
    if (next !== undefined) return Promise.resolve(next);
    if (this.closed) return Promise.reject(new ChannelClosedError());
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }
}

class DuplexChannel implements FrameChannel {
  constructor(
    private readonly inbound: FrameQueue,
    private readonly outbound: FrameQueue,
  ) {}

  readFrame(): Promise<Frame> {
    return this.inbound.take();
  }

  writeFrame(frame: Frame): Promise<void> {
    this.outbound.push(frame);
    return Promise.resolve();
  }

  close(): Promise<void> {
    this.outbound.close();
    return Promise.resolve();
  }
}

/** Create a linked pair of in-memory channels: whatever one writes, the other
 *  reads. Used to run the full handshake + control session in-process. */
export function createDuplexPair(): [FrameChannel, FrameChannel] {
  const a = new FrameQueue();
  const b = new FrameQueue();
  return [new DuplexChannel(a, b), new DuplexChannel(b, a)];
}
