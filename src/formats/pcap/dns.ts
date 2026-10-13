import type { Bytes } from "../../core/bytes/ByteSource";
import { ipv4, ipv6, u16be } from "./decode";

export interface DnsMessage {
  id: number;
  response: boolean;
  rcode: number;
  questions: { name: string; type: string }[];
  answers: { name: string; type: string; data: string }[];
}

const TYPES: Record<number, string> = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY" };
const typeName = (type: number) => TYPES[type] ?? `TYPE${type}`;

function label(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte > 0x20 && byte < 0x7f && byte !== 0x2e && byte !== 0x5c ? String.fromCharCode(byte) : `\\x${byte.toString(16).padStart(2, "0")}`;
  return out;
}

/** A possibly compressed name (RFC 1035 §4.1.4); `next` is where the record continues. */
function readName(d: Uint8Array, start: number): { text: string; next: number } | null {
  const labels: string[] = [];
  let at = start;
  let next = -1;
  for (let jumps = 0; at < d.length; ) {
    const length = d[at];
    if (length === 0) return { text: labels.join("."), next: next < 0 ? at + 1 : next };
    if ((length & 0xc0) === 0xc0) {
      if (at + 1 >= d.length || ++jumps > 32) return null;
      if (next < 0) next = at + 2;
      at = ((length & 0x3f) << 8) | d[at + 1];
      continue;
    }
    if (length > 63 || at + 1 + length > d.length) return null;
    labels.push(label(d.subarray(at + 1, at + 1 + length)));
    at += 1 + length;
  }
  return null;
}

function recordData(d: Uint8Array, type: number, start: number, length: number): string {
  const data = d.subarray(start, start + length);
  if (type === 1 && length === 4) return ipv4(d, start);
  if (type === 28 && length === 16) return ipv6(d, start);
  if (type === 2 || type === 5 || type === 12) return readName(d, start)?.text ?? "";
  if (type === 15 && length >= 3) return `${u16be(d, start)} ${readName(d, start + 2)?.text ?? ""}`;
  if (type === 16) {
    const strings: string[] = [];
    for (let at = 0; at < data.length; at += 1 + data[at]) strings.push(new TextDecoder().decode(data.subarray(at + 1, at + 1 + data[at])));
    return strings.join("");
  }
  return Array.from(data, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function parseDns(d: Bytes): DnsMessage | null {
  if (d.length < 12) return null;
  const flags = u16be(d, 2);
  const questionCount = u16be(d, 4);
  const answerCount = u16be(d, 6);
  if (questionCount > 64 || answerCount > 512) return null;
  const message: DnsMessage = { id: u16be(d, 0), response: (flags & 0x8000) !== 0, rcode: flags & 15, questions: [], answers: [] };
  let at = 12;
  for (let i = 0; i < questionCount; i++) {
    const name = readName(d, at);
    if (!name || name.next + 4 > d.length) return null;
    message.questions.push({ name: name.text, type: typeName(u16be(d, name.next)) });
    at = name.next + 4;
  }
  for (let i = 0; i < answerCount; i++) {
    const name = readName(d, at);
    if (!name || name.next + 10 > d.length) break;
    const type = u16be(d, name.next);
    const length = u16be(d, name.next + 8);
    const start = name.next + 10;
    if (start + length > d.length) break;
    message.answers.push({ name: name.text, type: typeName(type), data: recordData(d, type, start, length) });
    at = start + length;
  }
  return message;
}
