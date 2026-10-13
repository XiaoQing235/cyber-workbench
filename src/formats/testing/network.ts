import type { Bytes } from "../../core/bytes/ByteSource";
import { concat } from "./fixtures";

/** Test-only builders for capture files and the packets inside them. */

const ascii = (text: string) => new TextEncoder().encode(text);
const u16 = (value: number) => [(value >> 8) & 255, value & 255];
const u32 = (value: number) => [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
const ip = (address: string) => address.split(".").map(Number);

export const ethernet = (payload: Uint8Array, ethertype = 0x0800): Bytes =>
  concat(Uint8Array.of(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, ...u16(ethertype)), payload);

export const ipv4 = (src: string, dst: string, protocol: number, payload: Uint8Array): Bytes =>
  concat(Uint8Array.of(0x45, 0, ...u16(20 + payload.length), 0, 0, 0x40, 0, 64, protocol, 0, 0, ...ip(src), ...ip(dst)), payload);

export const tcp = (srcPort: number, dstPort: number, seq: number, ack: number, flags: number, payload: Uint8Array = new Uint8Array(0)): Bytes =>
  concat(Uint8Array.of(...u16(srcPort), ...u16(dstPort), ...u32(seq), ...u32(ack), 0x50, flags, 0xff, 0xff, 0, 0, 0, 0), payload);

export const udp = (srcPort: number, dstPort: number, payload: Uint8Array): Bytes =>
  concat(Uint8Array.of(...u16(srcPort), ...u16(dstPort), ...u16(8 + payload.length), 0, 0), payload);

export const icmpEcho = (type: number, id: number, seq: number, data: Uint8Array): Bytes =>
  concat(Uint8Array.of(type, 0, 0, 0, ...u16(id), ...u16(seq)), data);

export function dns(id: number, name: string, answer?: string): Bytes {
  const qname = concat(...name.split(".").map((label) => concat(Uint8Array.of(label.length), ascii(label))), Uint8Array.of(0));
  const header = Uint8Array.of(...u16(id), answer ? 0x81 : 0x01, answer ? 0x80 : 0, 0, 1, 0, answer ? 1 : 0, 0, 0, 0, 0);
  const record = answer ? Uint8Array.of(0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, ...ip(answer)) : new Uint8Array(0);
  return concat(header, qname, Uint8Array.of(0, 1, 0, 1), record);
}

export function pcap(linkType: number, frames: readonly Uint8Array[], options: { bigEndian?: boolean; nano?: boolean } = {}): Bytes {
  const le = !options.bigEndian;
  const header = new DataView(new ArrayBuffer(24));
  header.setUint32(0, options.nano ? 0xa1b23c4d : 0xa1b2c3d4, le);
  header.setUint16(4, 2, le);
  header.setUint16(6, 4, le);
  header.setUint32(16, 65535, le);
  header.setUint32(20, linkType, le);
  const records = frames.map((frame, index) => {
    const record = new DataView(new ArrayBuffer(16));
    record.setUint32(0, 1_700_000_000 + index, le);
    record.setUint32(4, options.nano ? 500_000_000 : 500_000, le);
    record.setUint32(8, frame.length, le);
    record.setUint32(12, frame.length, le);
    return concat(new Uint8Array(record.buffer), frame);
  });
  return concat(new Uint8Array(header.buffer), ...records);
}

function block(type: number, body: Uint8Array): Bytes {
  const padded = concat(body, new Uint8Array((4 - (body.length % 4)) % 4));
  const out = new DataView(new ArrayBuffer(12 + padded.length));
  out.setUint32(0, type, true);
  out.setUint32(4, out.byteLength, true);
  new Uint8Array(out.buffer).set(padded, 8);
  out.setUint32(out.byteLength - 4, out.byteLength, true);
  return new Uint8Array(out.buffer);
}

export function pcapng(linkType: number, frames: readonly Uint8Array[]): Bytes {
  const section = new DataView(new ArrayBuffer(16));
  section.setUint32(0, 0x1a2b3c4d, true);
  section.setUint16(4, 1, true);
  section.setBigInt64(8, -1n, true);
  const iface = new DataView(new ArrayBuffer(8));
  iface.setUint16(0, linkType, true);
  iface.setUint32(4, 65535, true);
  const packets = frames.map((frame, index) => {
    const head = new DataView(new ArrayBuffer(20));
    const micros = BigInt(1_700_000_000 + index) * 1_000_000n;
    head.setUint32(4, Number(micros >> 32n), true);
    head.setUint32(8, Number(micros & 0xffffffffn), true);
    head.setUint32(12, frame.length, true);
    head.setUint32(16, frame.length, true);
    return block(6, concat(new Uint8Array(head.buffer), frame));
  });
  return concat(block(0x0a0d0d0a, new Uint8Array(section.buffer)), block(1, new Uint8Array(iface.buffer)), ...packets);
}

/** usbmon (link type 220): a completed interrupt transfer from endpoint 0x81. */
export function usbmon(data: Uint8Array): Bytes {
  const header = new Uint8Array(64);
  header.set([0x43, 1, 0x81, 1], 8);
  new DataView(header.buffer).setUint32(32, data.length, true);
  new DataView(header.buffer).setUint32(36, data.length, true);
  return concat(header, data);
}

/** USBPcap (link type 249): an interrupt transfer completed by the device. */
export function usbpcap(data: Uint8Array): Bytes {
  const header = new Uint8Array(27);
  const view = new DataView(header.buffer);
  view.setUint16(0, 27, true);
  header[16] = 1;
  header[21] = 0x81;
  header[22] = 1;
  view.setUint32(23, data.length, true);
  return concat(header, data);
}

const KEYS: Record<string, [number, boolean]> = { "{": [0x2f, true], "}": [0x30, true], _: [0x2d, true], " ": [0x2c, false], "\n": [0x28, false] };
for (let i = 0; i < 26; i++) {
  KEYS[String.fromCharCode(97 + i)] = [4 + i, false];
  KEYS[String.fromCharCode(65 + i)] = [4 + i, true];
}
[..."1234567890"].forEach((c, i) => (KEYS[c] = [30 + i, false]));

/** Boot-keyboard reports for typing `text`: a press and a release per character; "\b" is Backspace. */
export function keyboardReports(text: string): Bytes[] {
  return [...text].flatMap((char) => {
    const [code, shift] = char === "\b" ? [0x2a, false] : KEYS[char];
    return [Uint8Array.of(shift ? 0x02 : 0, 0, code, 0, 0, 0, 0, 0), new Uint8Array(8)];
  });
}
