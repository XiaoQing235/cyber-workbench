import type { Bytes } from "../../core/bytes/ByteSource";
import type { Packet } from "./capture";

export interface Transport {
  srcPort: number;
  dstPort: number;
  payload: Bytes;
}

export interface TcpSegment extends Transport {
  seq: number;
  ack: number;
  flags: number;
}

export interface DecodedPacket {
  index: number;
  time: number;
  linkType: number;
  ipVersion?: 4 | 6;
  src?: string;
  dst?: string;
  protocol?: number;
  /** IP fragment; only the first fragment's transport header is decoded. */
  fragment?: boolean;
  tcp?: TcpSegment;
  udp?: Transport;
  icmp?: { type: number; code: number; echo: boolean; payload: Bytes };
}

export const TCP_SYN = 0x02;
export const TCP_ACK = 0x10;

export const u16be = (d: Uint8Array, o: number) => (d[o] << 8) | d[o + 1];
export const u32be = (d: Uint8Array, o: number) => ((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0;

export const ipv4 = (d: Uint8Array, o: number) => `${d[o]}.${d[o + 1]}.${d[o + 2]}.${d[o + 3]}`;

export function ipv6(d: Uint8Array, o: number): string {
  const groups = Array.from({ length: 8 }, (_, i) => u16be(d, o + i * 2));
  let bestStart = -1;
  let bestLength = 1;
  for (let i = 0; i < 8; ) {
    let j = i;
    while (j < 8 && groups[j] === 0) j++;
    if (j - i > bestLength) [bestStart, bestLength] = [i, j - i];
    i = j === i ? i + 1 : j;
  }
  const hex = groups.map((group) => group.toString(16));
  return bestStart < 0 ? hex.join(":") : `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLength).join(":")}`;
}

/** Network-layer bytes and their EtherType, for the link types seen in CTF captures. */
function linkPayload(packet: Packet): { bytes: Bytes; ethertype: number } | null {
  const d = packet.data;
  switch (packet.linkType) {
    case 1: {
      if (d.length < 14) return null;
      let type = u16be(d, 12);
      let at = 14;
      while ((type === 0x8100 || type === 0x88a8) && at + 4 <= d.length) {
        type = u16be(d, at + 2);
        at += 4;
      }
      return { bytes: d.subarray(at), ethertype: type };
    }
    case 113:
      return d.length >= 16 ? { bytes: d.subarray(16), ethertype: u16be(d, 14) } : null;
    case 276:
      return d.length >= 20 ? { bytes: d.subarray(20), ethertype: u16be(d, 0) } : null;
    case 0:
    case 108: {
      if (d.length < 4) return null;
      // BSD loopback stores the address family in host byte order.
      const family = d[0] !== 0 ? d[0] : d[3];
      return { bytes: d.subarray(4), ethertype: family === 2 ? 0x0800 : [24, 28, 30].includes(family) ? 0x86dd : 0 };
    }
    case 12:
    case 14:
    case 101:
      return d.length > 0 ? { bytes: d, ethertype: d[0] >> 4 === 6 ? 0x86dd : 0x0800 } : null;
    case 228:
      return { bytes: d, ethertype: 0x0800 };
    case 229:
      return { bytes: d, ethertype: 0x86dd };
    default:
      return null;
  }
}

function transport(protocol: number, d: Bytes, version: 4 | 6): Partial<DecodedPacket> {
  if (protocol === 6 && d.length >= 20) {
    return {
      tcp: { srcPort: u16be(d, 0), dstPort: u16be(d, 2), seq: u32be(d, 4), ack: u32be(d, 8), flags: d[13], payload: d.subarray(Math.min((d[12] >> 4) * 4, d.length)) },
    };
  }
  if (protocol === 17 && d.length >= 8) {
    return { udp: { srcPort: u16be(d, 0), dstPort: u16be(d, 2), payload: d.subarray(8, Math.max(8, Math.min(u16be(d, 4), d.length))) } };
  }
  if ((protocol === 1 && version === 4) || (protocol === 58 && version === 6)) {
    if (d.length < 4) return {};
    const echo = version === 4 ? d[0] === 0 || d[0] === 8 : d[0] === 128 || d[0] === 129;
    return { icmp: { type: d[0], code: d[1], echo, payload: d.subarray(echo ? Math.min(8, d.length) : 4) } };
  }
  return {};
}

export function decodePacket(packet: Packet): DecodedPacket {
  const base: DecodedPacket = { index: packet.index, time: packet.time, linkType: packet.linkType };
  const link = linkPayload(packet);
  if (!link) return base;
  const d = link.bytes;
  if (link.ethertype === 0x0800 && d.length >= 20 && d[0] >> 4 === 4) {
    const headerLength = (d[0] & 15) * 4;
    const end = Math.max(headerLength, Math.min(u16be(d, 2), d.length));
    const fragmentField = u16be(d, 6);
    const ip = { ...base, ipVersion: 4 as const, src: ipv4(d, 12), dst: ipv4(d, 16), protocol: d[9], fragment: (fragmentField & 0x3fff) !== 0 };
    return (fragmentField & 0x1fff) === 0 ? { ...ip, ...transport(d[9], d.subarray(headerLength, end), 4) } : ip;
  }
  if (link.ethertype === 0x86dd && d.length >= 40 && d[0] >> 4 === 6) {
    const end = Math.min(d.length, 40 + u16be(d, 4));
    let next = d[6];
    let at = 40;
    let fragment = false;
    while ((next === 0 || next === 43 || next === 44 || next === 60) && at + 8 <= end) {
      if (next === 44) {
        fragment = true;
        if ((u16be(d, at + 2) & 0xfff8) !== 0) return { ...base, ipVersion: 6, src: ipv6(d, 8), dst: ipv6(d, 24), protocol: d[at], fragment };
        next = d[at];
        at += 8;
      } else {
        const length = (d[at + 1] + 1) * 8;
        next = d[at];
        at += length;
      }
    }
    return { ...base, ipVersion: 6, src: ipv6(d, 8), dst: ipv6(d, 24), protocol: next, fragment, ...transport(next, d.subarray(Math.min(at, end), end), 6) };
  }
  return base;
}

export const endpoint = (address: string, port: number) => (address.includes(":") ? `[${address}]:${port}` : `${address}:${port}`);
