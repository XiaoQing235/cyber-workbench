import type { Bytes } from "../../core/bytes/ByteSource";

export interface Packet {
  index: number;
  /** Seconds since the epoch. */
  time: number;
  linkType: number;
  data: Bytes;
  originalLength: number;
}

export interface Capture {
  format: "pcap" | "pcapng";
  packets: Packet[];
  warnings: string[];
}

export class CaptureError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CaptureError";
  }
}

const PCAP_MICRO = 0xa1b2c3d4;
const PCAP_NANO = 0xa1b23c4d;
const PCAPNG_SECTION = 0x0a0d0d0a;

export function isCapture(head: Uint8Array): boolean {
  if (head.length < 4) return false;
  const view = new DataView(head.buffer, head.byteOffset, head.byteLength);
  return [view.getUint32(0, true), view.getUint32(0, false)].some((magic) => magic === PCAP_MICRO || magic === PCAP_NANO || magic === PCAPNG_SECTION);
}

export function parseCapture(bytes: Bytes, maxPackets = 2_000_000): Capture {
  if (bytes.length < 4) throw new CaptureError("Too short to be a capture file");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, true) === PCAPNG_SECTION) return parsePcapng(bytes, view, maxPackets);
  const little = view.getUint32(0, true);
  const big = view.getUint32(0, false);
  const littleEndian = little === PCAP_MICRO || little === PCAP_NANO;
  if (!littleEndian && big !== PCAP_MICRO && big !== PCAP_NANO) throw new CaptureError("Not a pcap or pcapng capture");
  if (bytes.length < 24) throw new CaptureError("Truncated pcap header");
  const divisor = (littleEndian ? little : big) === PCAP_NANO ? 1e9 : 1e6;
  // The top bits of the link-type field carry FCS information.
  const linkType = view.getUint32(20, littleEndian) & 0x0fffffff;
  const packets: Packet[] = [];
  const warnings: string[] = [];
  let offset = 24;
  while (offset + 16 <= bytes.length && packets.length < maxPackets) {
    const captured = view.getUint32(offset + 8, littleEndian);
    if (offset + 16 + captured > bytes.length) {
      warnings.push(`Packet ${packets.length + 1} is truncated`);
      break;
    }
    packets.push({
      index: packets.length,
      time: view.getUint32(offset, littleEndian) + view.getUint32(offset + 4, littleEndian) / divisor,
      linkType,
      data: bytes.subarray(offset + 16, offset + 16 + captured),
      originalLength: view.getUint32(offset + 12, littleEndian),
    });
    offset += 16 + captured;
  }
  if (packets.length >= maxPackets) warnings.push(`Stopped after ${maxPackets} packets`);
  return { format: "pcap", packets, warnings };
}

function timestampResolution(view: DataView, start: number, end: number, littleEndian: boolean): number {
  for (let at = start; at + 4 <= end; ) {
    const code = view.getUint16(at, littleEndian);
    const length = view.getUint16(at + 2, littleEndian);
    if (code === 0) break;
    if (code === 9 && length >= 1) {
      const value = view.getUint8(at + 4);
      return value & 0x80 ? 2 ** -(value & 0x7f) : 10 ** -value;
    }
    at += 4 + Math.ceil(length / 4) * 4;
  }
  return 1e-6;
}

function parsePcapng(bytes: Bytes, view: DataView, maxPackets: number): Capture {
  const packets: Packet[] = [];
  const warnings: string[] = [];
  let interfaces: { linkType: number; resolution: number }[] = [];
  let littleEndian = true;
  let offset = 0;
  while (offset + 12 <= bytes.length && packets.length < maxPackets) {
    if (view.getUint32(offset, true) === PCAPNG_SECTION) {
      const order = view.getUint32(offset + 8, true);
      if (order !== 0x1a2b3c4d && order !== 0x4d3c2b1a) throw new CaptureError(`Bad pcapng byte-order magic at offset ${offset}`);
      littleEndian = order === 0x1a2b3c4d;
      interfaces = [];
    }
    const type = view.getUint32(offset, littleEndian);
    const length = view.getUint32(offset + 4, littleEndian);
    if (length < 12 || length % 4 !== 0 || offset + length > bytes.length) {
      warnings.push(`Block at offset ${offset} is truncated or malformed`);
      break;
    }
    const body = offset + 8;
    const bodyEnd = offset + length - 4;
    if (type === 1) {
      interfaces.push({ linkType: view.getUint16(body, littleEndian), resolution: timestampResolution(view, body + 8, bodyEnd, littleEndian) });
    } else if (type === 6 || type === 2) {
      const id = type === 6 ? view.getUint32(body, littleEndian) : view.getUint16(body, littleEndian);
      const captured = view.getUint32(body + 12, littleEndian);
      const info = interfaces[id];
      if (!info || body + 20 + captured > bodyEnd) {
        warnings.push(`Packet block at offset ${offset} is malformed or names an unknown interface`);
      } else {
        packets.push({
          index: packets.length,
          time: (view.getUint32(body + 4, littleEndian) * 2 ** 32 + view.getUint32(body + 8, littleEndian)) * info.resolution,
          linkType: info.linkType,
          data: bytes.subarray(body + 20, body + 20 + captured),
          originalLength: view.getUint32(body + 16, littleEndian),
        });
      }
    } else if (type === 3 && interfaces[0]) {
      const original = view.getUint32(body, littleEndian);
      const captured = Math.min(original, bodyEnd - body - 4);
      packets.push({ index: packets.length, time: 0, linkType: interfaces[0].linkType, data: bytes.subarray(body + 4, body + 4 + captured), originalLength: original });
    }
    offset += length;
  }
  if (packets.length >= maxPackets) warnings.push(`Stopped after ${maxPackets} packets`);
  return { format: "pcapng", packets, warnings };
}
