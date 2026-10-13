import type { ByteSource } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";

export const MAX_DEX_BYTES = 64 * 1024 * 1024;

export interface DexReport {
  version: "035";
  bytes: number;
  endianTag: number;
  adler32Valid: true;
  sha1Valid: true;
  firstClassDescriptor: string | null;
  classes: number;
  methods: number;
  strings: number;
  tables: { name: string; count: number; offset: number }[];
  executed: false;
}

function readUleb(bytes: Uint8Array, offset: number): { value: number; next: number } {
  let value = 0;
  for (let index = 0; index < 5; index++) {
    if (offset + index >= bytes.length) throw new Error("DEX string length is truncated");
    const byte = bytes[offset + index];
    value += (byte & 0x7f) * 2 ** (7 * index);
    if (byte < 0x80) return { value, next: offset + index + 1 };
  }
  throw new Error("DEX string length is too long");
}

function asciiDescriptor(bytes: Uint8Array, offset: number): string | null {
  if (offset >= bytes.length) throw new Error("DEX class string offset exceeds the file");
  const { value, next } = readUleb(bytes, offset);
  if (value > 1_024 || next + value >= bytes.length || bytes[next + value] !== 0) throw new Error("DEX class string length or terminator is invalid");
  const valueBytes = bytes.subarray(next, next + value);
  if (valueBytes.some((byte) => byte < 0x20 || byte > 0x7e)) return null;
  const descriptor = new TextDecoder("ascii").decode(valueBytes);
  if (!/^L[^;\[\0]+;$/.test(descriptor)) return null;
  return descriptor;
}

export async function inspectDex(source: ByteSource, signal?: AbortSignal): Promise<DexReport> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < 112 || source.size > MAX_DEX_BYTES) throw new Error("DEX file is outside the 64 MiB inspection budget");
  const bytes = await readAll(source, MAX_DEX_BYTES);
  if (String.fromCharCode(...bytes.subarray(0, 8)) !== "dex\n035\0") throw new Error("Unsupported DEX magic or version (expected 035)");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const fileSize = view.getUint32(32, true);
  const headerSize = view.getUint32(36, true);
  const endianTag = view.getUint32(40, true);
  const mapOffset = view.getUint32(52, true);
  if (fileSize !== source.size || headerSize !== 112 || endianTag !== 0x12345678 || mapOffset < 112 || mapOffset >= fileSize || mapOffset % 4 !== 0) throw new Error("DEX header geometry or endian tag is invalid");
  let first = 1;
  let second = 0;
  for (let index = 12; index < bytes.length; index++) {
    first = (first + bytes[index]) % 65521;
    second = (second + first) % 65521;
  }
  if (((second << 16) | first) >>> 0 !== view.getUint32(8, true)) throw new Error("DEX Adler-32 checksum is invalid");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", bytes.subarray(32)));
  if (!digest.every((byte, index) => byte === bytes[index + 12])) throw new Error("DEX SHA-1 signature is invalid");
  const definitions: [string, number, number][] = [
    ["strings", 56, 4], ["types", 64, 4], ["prototypes", 72, 12], ["fields", 80, 8],
    ["methods", 88, 8], ["classes", 96, 32],
  ];
  const tables = definitions.map(([name, position, width]) => {
    const count = view.getUint32(position, true);
    const offset = view.getUint32(position + 4, true);
    if (count > 1_000_000 || (count === 0 ? offset !== 0 : offset < headerSize || offset % 4 !== 0 || count * width > fileSize - offset)) throw new Error(`DEX ${name} table exceeds the file or item budget`);
    return { name, count, offset };
  });
  const strings = tables[0];
  const types = tables[1];
  const classes = tables[5];
  let firstClassDescriptor: string | null = null;
  if (classes.count > 0) {
    const typeIndex = view.getUint32(classes.offset, true);
    if (typeIndex >= types.count) throw new Error("DEX class type index is invalid");
    const stringIndex = view.getUint32(types.offset + typeIndex * 4, true);
    if (stringIndex >= strings.count) throw new Error("DEX class string index is invalid");
    firstClassDescriptor = asciiDescriptor(bytes, view.getUint32(strings.offset + stringIndex * 4, true));
  }
  if (signal?.aborted) throw signal.reason;
  return { version: "035", bytes: fileSize, endianTag, adler32Valid: true, sha1Valid: true,
    firstClassDescriptor, classes: classes.count, methods: tables[4].count, strings: strings.count, tables, executed: false };
}