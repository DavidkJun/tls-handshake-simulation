import { EventEmitter } from 'node:events';
import { setTimeout as sleep } from 'node:timers/promises';

// Frame: u16 length | u32 message id | u16 fragment index | u16 fragment count | payload
export const FRAME_HEADER = 10;

/**
 * Link layer of a slow radio channel on top of a TCP socket.
 * A message of any size is cut into frames no larger than `mtu`, frames are sent one by one
 * with a delay equal to their airtime, and the receiver reassembles them.
 */
export class RadioLink extends EventEmitter {
  constructor(socket, { mtu, bitrate }) {
    super();
    if (mtu <= FRAME_HEADER) throw new Error(`MTU must be larger than the ${FRAME_HEADER}-byte frame header`);
    this.socket = socket;
    this.mtu = mtu;
    this.bitrate = bitrate;
    this.peer = null;
    this.nextMsgId = 0;
    this.queue = [];
    this.sending = false;
    this.rx = Buffer.alloc(0);
    this.partial = new Map();
    this.stats = { messagesOut: 0, framesOut: 0, bytesOut: 0, messagesIn: 0, framesIn: 0, bytesIn: 0 };
    socket.setNoDelay(true);
    socket.on('data', (chunk) => this.#onData(chunk));
    socket.on('close', () => this.emit('close'));
    // 'close' always follows 'error'; the owner reacts to 'close'.
    socket.on('error', () => {});
  }

  /** Queues a message and returns the number of frames it was split into. */
  send(message) {
    const payloadMax = this.mtu - FRAME_HEADER;
    const count = Math.max(1, Math.ceil(message.length / payloadMax));
    if (count > 0xffff) throw new Error('message is too large for the link');
    this.nextMsgId = (this.nextMsgId + 1) >>> 0;
    for (let i = 0; i < count; i++) {
      const part = message.subarray(i * payloadMax, (i + 1) * payloadMax);
      const frame = Buffer.alloc(FRAME_HEADER + part.length);
      frame.writeUInt16BE(frame.length, 0);
      frame.writeUInt32BE(this.nextMsgId, 2);
      frame.writeUInt16BE(i, 6);
      frame.writeUInt16BE(count, 8);
      part.copy(frame, FRAME_HEADER);
      this.queue.push(frame);
    }
    this.stats.messagesOut++;
    this.#pump();
    return count;
  }

  close() {
    this.socket.destroy();
  }

  async #pump() {
    if (this.sending) return;
    this.sending = true;
    while (this.queue.length && !this.socket.destroyed) {
      const frame = this.queue.shift();
      await sleep((frame.length * 8 * 1000) / this.bitrate);
      if (this.socket.destroyed) break;
      this.socket.write(frame);
      this.stats.framesOut++;
      this.stats.bytesOut += frame.length;
    }
    this.sending = false;
  }

  #onData(chunk) {
    this.rx = Buffer.concat([this.rx, chunk]);
    while (this.rx.length >= 2) {
      const len = this.rx.readUInt16BE(0);
      if (len < FRAME_HEADER || len > this.mtu) {
        this.socket.destroy(new Error(`frame of ${len} bytes violates the ${this.mtu}-byte MTU`));
        return;
      }
      if (this.rx.length < len) break;
      const frame = this.rx.subarray(0, len);
      this.rx = this.rx.subarray(len);
      this.stats.framesIn++;
      this.stats.bytesIn += len;

      const msgId = frame.readUInt32BE(2);
      const index = frame.readUInt16BE(6);
      const count = frame.readUInt16BE(8);
      let entry = this.partial.get(msgId);
      if (!entry) {
        entry = { parts: new Array(count), received: 0 };
        this.partial.set(msgId, entry);
      }
      if (!entry.parts[index]) {
        entry.parts[index] = Buffer.from(frame.subarray(FRAME_HEADER));
        entry.received++;
      }
      if (entry.received === count) {
        this.partial.delete(msgId);
        this.stats.messagesIn++;
        this.emit('message', Buffer.concat(entry.parts));
      }
    }
  }
}
