import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { MemorySource } from "../core/bytes/sources";
import { crc32 } from "../core/checksum/crc32";
import { Sha256 } from "../core/hash/sha256";

const RAR4_SIGNATURE = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00];
const RAR5_SIGNATURE = [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00];
const SEVEN_Z_SIGNATURE = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const SEVEN_Z_AES = [0x06, 0xf1, 0x07, 0x01];
const MAX_HEADERS = 10_000;
const MAX_HEADER_BYTES = 8 * 1024 * 1024;
const MAX_SEVEN_Z_EXPORT_BYTES = 8 * 1024 * 1024;

export interface Rar7zReport {
  format: "RAR4" | "RAR5" | "7z";
  size: number;
  encryption: "none" | "file-data" | "headers" | "AES-256" | "unknown";
  headers: number;
  entries: { name: string; offset: number; packedSize: number; encrypted: boolean }[];
  issues: string[];
  limited: boolean;
  sevenZip?: {
    version: string;
    startHeaderCrcValid: boolean;
    nextHeaderOffset: number;
    nextHeaderSize: number;
    nextHeaderCrcValid: boolean;
    aesCoderOffset: number | null;
  };
}

function startsWith(bytes: Bytes, signature: number[]): boolean {
  return signature.every((byte, index) => bytes[index] === byte);
}

function dataView(bytes: Bytes): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

async function exact(source: ByteSource, offset: number, length: number): Promise<Bytes | null> {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > source.size) return null;
  const bytes = await source.read(offset, length);
  return bytes.length === length ? bytes : null;
}

function uint64(view: DataView, offset: number): number | null {
  const value = view.getBigUint64(offset, true);
  return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : null;
}

function readVint(bytes: Bytes, offset: number): { value: number; length: number } | null {
  let value = 0;
  let multiplier = 1;
  for (let index = 0; index < 10 && offset + index < bytes.length; index++) {
    const byte = bytes[offset + index];
    value += (byte & 0x7f) * multiplier;
    if (!Number.isSafeInteger(value)) return null;
    if ((byte & 0x80) === 0) return { value, length: index + 1 };
    multiplier *= 128;
  }
  return null;
}

/** Read only the IDs and bounded lengths of RAR5 file-header extras; 1 denotes data encryption. */
function rar5ExtraIds(bytes: Bytes, start: number, length: number): number[] | null {
  const end = start + length;
  if (length < 0 || start < 0 || end > bytes.length) return null;
  const ids: number[] = [];
  let at = start;
  while (at < end) {
    const size = readVint(bytes, at);
    if (!size) return null;
    at += size.length;
    const id = readVint(bytes, at);
    if (!id || size.value < id.length || size.value > end - at) return null;
    ids.push(id.value);
    at += size.value;
    if (ids.length > 64) return null;
  }
  return at === end ? ids : null;
}

class SevenZipCursor {
  offset = 0;

  constructor(readonly bytes: Bytes) {}

  byte(): number {
    if (this.offset >= this.bytes.length) throw new Error("7z header is truncated");
    return this.bytes[this.offset++];
  }

  number(): number {
    const first = this.byte();
    let value = 0;
    for (let index = 0; index < 8; index++) {
      const mask = 0x80 >> index;
      if ((first & mask) === 0) {
        value += (first & (mask - 1)) * 2 ** (8 * index);
        if (!Number.isSafeInteger(value)) throw new Error("7z integer exceeds JavaScript's safe integer range");
        return value;
      }
      value += this.byte() * 2 ** (8 * index);
    }
    if (!Number.isSafeInteger(value)) throw new Error("7z integer exceeds JavaScript's safe integer range");
    return value;
  }

  take(length: number): Bytes {
    if (!Number.isSafeInteger(length) || length < 0 || this.offset + length > this.bytes.length) throw new Error("7z header is truncated");
    const result = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return result;
  }

  uint32(): number {
    const bytes = this.take(4);
    return dataView(bytes).getUint32(0, true);
  }
}

function sevenZipBoolean(cursor: SevenZipCursor, count: number): boolean[] {
  if (cursor.byte() === 1) return new Array<boolean>(count).fill(true);
  const values: boolean[] = [];
  let bits = 0;
  let mask = 0;
  for (let index = 0; index < count; index++) {
    if (mask === 0) {
      bits = cursor.byte();
      mask = 0x80;
    }
    values.push((bits & mask) !== 0);
    mask >>= 1;
  }
  return values;
}

function hex(bytes: Bytes): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export interface SevenZipHashExport {
  hash: string;
  cyclesPower: number;
  saltLength: number;
  ivLength: number;
  crc32: number;
  packedSize: number;
  unpackedSize: number;
}

export interface Rar5HashExport {
  hash: string;
  iterationsPower: number;
  salt: string;
  iv: string;
  passwordCheck: string;
}

export async function exportRar5Hash(source: ByteSource, signal?: AbortSignal): Promise<Rar5HashExport> {
  const signature = await exact(source, 0, RAR5_SIGNATURE.length);
  if (!signature || !startsWith(signature, RAR5_SIGNATURE)) throw new Error("Input is not a RAR5 archive");
  const prefix = await source.read(RAR5_SIGNATURE.length, Math.min(16, source.size - RAR5_SIGNATURE.length));
  if (prefix.length < 7) throw new Error("RAR5 archive-encryption header is truncated");
  const headerSize = readVint(prefix, 4);
  if (!headerSize || headerSize.length > 3) throw new Error("RAR5 archive-encryption header has an invalid size");
  if (headerSize.value > MAX_HEADER_BYTES) throw new Error(`RAR5 archive-encryption header exceeds the ${MAX_HEADER_BYTES}-byte inspection limit`);
  const bodyOffset = 4 + headerSize.length;
  const totalHeader = bodyOffset + headerSize.value;
  const header = await exact(source, RAR5_SIGNATURE.length, totalHeader);
  if (!header) throw new Error("RAR5 archive-encryption header exceeds the archive bounds");
  if (crc32(header.subarray(4)) !== dataView(header).getUint32(0, true)) throw new Error("RAR5 archive-encryption header CRC is invalid");

  let cursor = bodyOffset;
  const type = readVint(header, cursor);
  if (!type || type.value !== 4) throw new Error("RAR5 archive does not begin with an archive-encryption header");
  cursor += type.length;
  const headerFlags = readVint(header, cursor);
  if (!headerFlags || headerFlags.value !== 0) throw new Error("RAR5 archive-encryption header uses unsupported common flags");
  cursor += headerFlags.length;
  const version = readVint(header, cursor);
  if (!version || version.value !== 0) throw new Error("RAR5 archive uses an unsupported encryption version");
  cursor += version.length;
  const encryptionFlags = readVint(header, cursor);
  if (!encryptionFlags || encryptionFlags.value !== 1) throw new Error("RAR5 archive-encryption header has no supported password check");
  cursor += encryptionFlags.length;
  if (cursor >= header.length) throw new Error("RAR5 archive-encryption header is truncated");
  const iterationsPower = header[cursor++];
  if (iterationsPower === 0 || iterationsPower > 24) throw new Error("RAR5 KDF iteration exponent is unsupported");
  if (cursor + 28 !== header.length) throw new Error("RAR5 archive-encryption header has unsupported trailing data");
  const salt = header.slice(cursor, cursor + 16);
  cursor += 16;
  const passwordCheck = header.slice(cursor, cursor + 8);
  cursor += 8;
  const passwordCheckChecksum = header.slice(cursor, cursor + 4);
  const expectedChecksum = new Sha256().update(passwordCheck).digest().subarray(0, 4);
  if (!expectedChecksum.every((byte, index) => byte === passwordCheckChecksum[index])) throw new Error("RAR5 password-check checksum is invalid");
  const iv = await exact(source, RAR5_SIGNATURE.length + totalHeader, 16);
  if (!iv) throw new Error("RAR5 encrypted-header IV is truncated");
  if (signal?.aborted) throw signal.reason;

  const saltHex = hex(salt);
  const ivHex = hex(iv);
  const passwordCheckHex = hex(passwordCheck);
  return {
    hash: `$rar5$16$${saltHex}$${iterationsPower}$${ivHex}$8$${passwordCheckHex}`,
    iterationsPower,
    salt: saltHex,
    iv: ivHex,
    passwordCheck: passwordCheckHex,
  };
}

export async function exportSevenZipHash(source: ByteSource, signal?: AbortSignal): Promise<SevenZipHashExport> {
  const fixed = await exact(source, 0, 32);
  if (!fixed || !startsWith(fixed, SEVEN_Z_SIGNATURE)) throw new Error("Input is not a 7z archive");
  const view = dataView(fixed);
  if (crc32(fixed.subarray(12, 32)) !== view.getUint32(8, true)) throw new Error("7z start-header CRC is invalid");
  const nextOffset = uint64(view, 12);
  const nextSize = uint64(view, 20);
  if (nextOffset === null || nextSize === null) throw new Error("7z next-header extent exceeds JavaScript's safe integer range");
  if (nextSize > MAX_HEADER_BYTES) throw new Error(`7z next header exceeds the ${MAX_HEADER_BYTES}-byte inspection limit`);
  const next = await exact(source, 32 + nextOffset, nextSize);
  if (!next) throw new Error("7z next header exceeds the archive bounds");
  if (crc32(next) !== view.getUint32(28, true)) throw new Error("7z next-header CRC is invalid");
  if (signal?.aborted) throw signal.reason;

  const cursor = new SevenZipCursor(next);
  if (cursor.byte() !== 0x17) throw new Error("7z export currently supports encrypted encoded headers only");
  if (cursor.byte() !== 0x06) throw new Error("7z encoded header has no leading PackInfo");
  const packPosition = cursor.number();
  if (cursor.number() !== 1) throw new Error("7z export currently supports one encrypted header stream");
  if (cursor.byte() !== 0x09) throw new Error("7z encrypted header has no packed size");
  const packedSize = cursor.number();
  if (packedSize === 0 || packedSize % 16 !== 0) throw new Error("7z encrypted header size is not AES block-aligned");
  let packInfoId = cursor.byte();
  let packedCrc: number | null = null;
  if (packInfoId === 0x0a) {
    const defined = sevenZipBoolean(cursor, 1);
    if (defined[0]) packedCrc = cursor.uint32();
    packInfoId = cursor.byte();
  }
  if (packInfoId !== 0x00 || cursor.byte() !== 0x07 || cursor.byte() !== 0x0b) throw new Error("7z encrypted header has unsupported stream metadata");
  if (cursor.number() !== 1 || cursor.byte() !== 0) throw new Error("7z export currently supports one inline folder");
  if (cursor.number() !== 1) throw new Error("7z export currently supports one AES coder");
  const coderFlags = cursor.byte();
  if ((coderFlags & 0xc0) !== 0 || (coderFlags & 0x10) !== 0 || (coderFlags & 0x0f) !== SEVEN_Z_AES.length || (coderFlags & 0x20) === 0) {
    throw new Error("7z encrypted header uses an unsupported coder layout");
  }
  const codec = cursor.take(SEVEN_Z_AES.length);
  if (!startsWith(codec, SEVEN_Z_AES)) throw new Error("7z encoded header is not encrypted with AES-256");
  const properties = cursor.take(cursor.number());
  if (properties.length < 1) throw new Error("7z AES coder properties are missing");
  if (cursor.byte() !== 0x0c) throw new Error("7z encrypted header has no unpack size");
  const unpackedSize = cursor.number();
  if (unpackedSize === 0 || unpackedSize > packedSize) throw new Error("7z encrypted header has an invalid unpack size");
  if (cursor.byte() !== 0x0a) throw new Error("7z encrypted header has no verification CRC");
  const digestDefined = sevenZipBoolean(cursor, 1);
  if (!digestDefined[0]) throw new Error("7z encrypted-header verification CRC is undefined");
  const digest = cursor.uint32();
  if (cursor.byte() !== 0 || cursor.byte() !== 0 || cursor.offset !== next.length) throw new Error("7z encrypted header contains unsupported trailing metadata");

  const firstProperty = properties[0];
  const cyclesPower = firstProperty & 0x3f;
  let saltLength = 0;
  let ivLength = 16;
  let encodedIvLength = 0;
  let propertyOffset = 1;
  if ((firstProperty & 0xc0) !== 0) {
    if (properties.length < 2) throw new Error("7z AES coder length properties are truncated");
    saltLength = ((firstProperty >> 7) & 1) + (properties[1] >> 4);
    encodedIvLength = ((firstProperty >> 6) & 1) + (properties[1] & 0x0f);
    ivLength = encodedIvLength;
    propertyOffset = 2;
  }
  if (saltLength > 16 || encodedIvLength > 16 || propertyOffset + saltLength + encodedIvLength !== properties.length) throw new Error("7z AES coder properties have invalid salt or IV lengths");
  const salt = properties.slice(propertyOffset, propertyOffset + saltLength);
  const rawIv = properties.slice(propertyOffset + saltLength, propertyOffset + saltLength + encodedIvLength);
  const iv = new Uint8Array(16);
  iv.set(rawIv);
  if (packedSize > MAX_SEVEN_Z_EXPORT_BYTES) throw new Error(`7z encrypted header exceeds the ${MAX_SEVEN_Z_EXPORT_BYTES}-byte export limit`);
  const packedOffset = 32 + packPosition;
  if (!Number.isSafeInteger(packedOffset + packedSize) || packedOffset + packedSize > 32 + nextOffset) throw new Error("7z encrypted header data overlaps the next header");
  const encrypted = await exact(source, packedOffset, packedSize);
  if (!encrypted) throw new Error("7z encrypted header data exceeds the archive bounds");
  if (packedCrc !== null && crc32(encrypted) !== packedCrc) throw new Error("7z encrypted-header packed-stream CRC is invalid");
  if (signal?.aborted) throw signal.reason;
  const hash = `$7z$0$${cyclesPower}$${saltLength}$${hex(salt)}$${ivLength}$${hex(iv)}$${digest}$${packedSize}$${unpackedSize}$${hex(encrypted)}`;
  return { hash, cyclesPower, saltLength, ivLength, crc32: digest, packedSize, unpackedSize };
}

async function inspectRar4(source: ByteSource, signal?: AbortSignal): Promise<Rar7zReport> {
  const entries: Rar7zReport["entries"] = [];
  const issues: string[] = [];
  let offset = RAR4_SIGNATURE.length;
  let headers = 0;
  let headerEncryption = false;
  let limited = false;
  while (offset < source.size && headers < MAX_HEADERS) {
    if (signal?.aborted) throw signal.reason;
    const base = await exact(source, offset, 7);
    if (!base) { issues.push(`Truncated RAR4 header at offset ${offset}.`); break; }
    const view = dataView(base);
    const type = base[2];
    const flags = view.getUint16(3, true);
    const headerSize = view.getUint16(5, true);
    if (headerSize < 7 || offset + headerSize > source.size) { issues.push(`Invalid RAR4 header size ${headerSize} at offset ${offset}.`); break; }
    const full = await exact(source, offset, headerSize);
    if (!full) { issues.push(`Truncated RAR4 header at offset ${offset}.`); break; }
    if ((flags & 0x8000) !== 0 && full.length < 11) { issues.push(`RAR4 long block at offset ${offset} has no data size.`); break; }
    if ((crc32(full.subarray(2)) & 0xffff) !== dataView(full).getUint16(0, true)) issues.push(`RAR4 header CRC mismatch at offset ${offset}.`);
    const packedSize = flags & 0x8000 ? dataView(full).getUint32(7, true) : 0;
    headers++;
    if (type === 0x73 && (flags & 0x0080) !== 0) headerEncryption = true;
    if (type === 0x74) {
      if (headerSize < 32) issues.push(`RAR4 file header at offset ${offset} is too short.`);
      else {
        const fileView = dataView(full);
        const large = (flags & 0x0100) !== 0;
        const nameLength = fileView.getUint16(26, true);
        const nameOffset = large ? 40 : 32;
        const nameEnd = nameOffset + nameLength;
        const name = nameEnd <= full.length ? new TextDecoder("windows-1252").decode(full.subarray(nameOffset, nameEnd)) : `<entry ${entries.length}>`;
        if (nameEnd > full.length) issues.push(`RAR4 file name at offset ${offset} exceeds its header.`);
        entries.push({ name, offset, packedSize, encrypted: (flags & 0x0004) !== 0 });
      }
    }
    const next = offset + headerSize + packedSize;
    if (!Number.isSafeInteger(next) || next <= offset || next > source.size) { issues.push(`RAR4 block at offset ${offset} exceeds the archive.`); break; }
    offset = next;
    if (type === 0x7b) break;
  }
  if (headers === MAX_HEADERS && offset < source.size) limited = true;
  return { format: "RAR4", size: source.size, encryption: headerEncryption ? "headers" : entries.some((entry) => entry.encrypted) ? "file-data" : "none", headers, entries, issues, limited };
}

async function inspectRar5(source: ByteSource, signal?: AbortSignal): Promise<Rar7zReport> {
  const issues: string[] = [];
  const entries: Rar7zReport["entries"] = [];
  let offset = RAR5_SIGNATURE.length;
  let headers = 0;
  let headerEncryption = false;
  let limited = false;
  let ended = false;
  while (offset < source.size && headers < MAX_HEADERS) {
    if (signal?.aborted) throw signal.reason;
    const prefix = await source.read(offset, Math.min(14, source.size - offset));
    if (prefix.length < 7) { issues.push(`Truncated RAR5 header at offset ${offset}.`); break; }
    const headerSize = readVint(prefix, 4);
    if (!headerSize) { issues.push(`Invalid RAR5 header-size integer at offset ${offset}.`); break; }
    const bodyOffset = 4 + headerSize.length;
    const totalHeader = bodyOffset + headerSize.value;
    if (headerSize.value > MAX_HEADER_BYTES) { issues.push(`RAR5 header at offset ${offset} exceeds the inspection limit.`); break; }
    const bytes = await exact(source, offset, totalHeader);
    if (!bytes) { issues.push(`RAR5 header at offset ${offset} exceeds the archive bounds.`); break; }
    if (crc32(bytes.subarray(4)) !== dataView(bytes).getUint32(0, true)) issues.push(`RAR5 header CRC mismatch at offset ${offset}.`);
    const type = readVint(bytes, bodyOffset);
    const flags = type && readVint(bytes, bodyOffset + type.length);
    if (!type || !flags) { issues.push(`Invalid RAR5 base header at offset ${offset}.`); break; }
    let cursor = bodyOffset + type.length + flags.length;
    let extraSize = 0;
    if ((flags.value & 1) !== 0) {
      const parsed = readVint(bytes, cursor);
      if (!parsed) { issues.push(`Invalid RAR5 extra-area size at offset ${offset}.`); break; }
      extraSize = parsed.value;
      cursor += parsed.length;
    }
    let payloadSize = 0;
    if ((flags.value & 2) !== 0) {
      const parsed = readVint(bytes, cursor);
      if (!parsed) { issues.push(`Invalid RAR5 data size at offset ${offset}.`); break; }
      payloadSize = parsed.value;
      cursor += parsed.length;
    }
    headers++;
    if (type.value === 4) headerEncryption = true;
    if (type.value === 2 && crc32(bytes.subarray(4)) === dataView(bytes).getUint32(0, true)) {
      const limit = bytes.length - extraSize;
      const nextNumber = (): number => {
        const parsed = readVint(bytes, cursor);
        if (!parsed || cursor + parsed.length > limit) throw new Error("RAR5 file metadata is truncated");
        cursor += parsed.length;
        return parsed.value;
      };
      try {
        const fileFlags = nextNumber();
        nextNumber(); // unpacked size
        nextNumber(); // attributes
        if (fileFlags & 2) nextNumber();
        if (fileFlags & 4) {
          if (cursor + 4 > limit) throw new Error("RAR5 file checksum is truncated");
          cursor += 4;
        }
        const compression = nextNumber();
        nextNumber(); // host OS
        const nameLength = nextNumber();
        if (nameLength < 1 || nameLength > 1024 || cursor + nameLength > limit || extraSize > bytes.length - cursor - nameLength) {
          throw new Error("RAR5 file name exceeds the header");
        }
        const name = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(cursor, cursor + nameLength));
        const extras = rar5ExtraIds(bytes, limit, extraSize);
        if (!extras) throw new Error("RAR5 file extras are malformed");
        const encrypted = extras.includes(1);
        entries.push({ name, offset, packedSize: payloadSize, encrypted });
        if (encrypted || extras.some((id) => id !== 3)) limited = true;
        if (compression !== 0) limited = true;
      } catch { issues.push(`RAR5 file metadata at offset ${offset} is unsupported or truncated.`); }
    }
    const next = offset + totalHeader + payloadSize;
    if (!Number.isSafeInteger(next) || next <= offset || next > source.size) { issues.push(`RAR5 block at offset ${offset} exceeds the archive.`); break; }
    offset = next;
    if (type.value === 5) { ended = true; break; }
  }
  if (headers === MAX_HEADERS && offset < source.size) limited = true;
  const complete = ended && issues.length === 0 && !limited;
  return { format: "RAR5", size: source.size,
    encryption: headerEncryption ? "headers" : entries.some((entry) => entry.encrypted) ? "file-data" : complete ? "none" : "unknown",
    headers, entries, issues, limited };
}

async function inspectSevenZip(source: ByteSource, signal?: AbortSignal): Promise<Rar7zReport> {
  const fixed = await exact(source, 0, 32);
  if (!fixed) throw new Error("7z start header is truncated");
  const view = dataView(fixed);
  const nextOffset = uint64(view, 12);
  const nextSize = uint64(view, 20);
  if (nextOffset === null || nextSize === null) throw new Error("7z next-header extent exceeds JavaScript's safe integer range");
  const absoluteOffset = 32 + nextOffset;
  if (nextSize > MAX_HEADER_BYTES) throw new Error(`7z next header exceeds the ${MAX_HEADER_BYTES}-byte inspection limit`);
  const next = await exact(source, absoluteOffset, nextSize);
  if (!next) throw new Error("7z next header exceeds the archive bounds");
  if (signal?.aborted) throw signal.reason;
  let aesCoderOffset: number | null = null;
  for (let index = 0; index <= next.length - SEVEN_Z_AES.length; index++) {
    if (SEVEN_Z_AES.every((byte, part) => next[index + part] === byte)) { aesCoderOffset = absoluteOffset + index; break; }
  }
  const startHeaderCrcValid = crc32(fixed.subarray(12, 32)) === view.getUint32(8, true);
  const nextHeaderCrcValid = crc32(next) === view.getUint32(28, true);
  return {
    format: "7z",
    size: source.size,
    encryption: aesCoderOffset === null ? "none" : "AES-256",
    headers: 1,
    entries: [],
    issues: [...(!startHeaderCrcValid ? ["7z start-header CRC mismatch"] : []), ...(!nextHeaderCrcValid ? ["7z next-header CRC mismatch"] : [])],
    limited: false,
    sevenZip: {
      version: `${fixed[6]}.${fixed[7]}`,
      startHeaderCrcValid,
      nextHeaderOffset: absoluteOffset,
      nextHeaderSize: nextSize,
      nextHeaderCrcValid,
      aesCoderOffset,
    },
  };
}

export async function inspectRar7z(source: ByteSource, signal?: AbortSignal): Promise<Rar7zReport> {
  const prefix = await source.read(0, Math.min(8, source.size));
  if (startsWith(prefix, RAR5_SIGNATURE)) return inspectRar5(source, signal);
  if (startsWith(prefix, RAR4_SIGNATURE)) return inspectRar4(source, signal);
  if (startsWith(prefix, SEVEN_Z_SIGNATURE)) return inspectSevenZip(source, signal);
  throw new Error("Input is not a RAR4, RAR5, or 7z archive");
}

/** Extract one RAR4 m0 regular file; compressed, encrypted, split and symlink members are unsupported. */
export async function extractRar4Stored(source: ByteSource, entryIndex: number, signal?: AbortSignal): Promise<ByteSource> {
  if (!Number.isSafeInteger(entryIndex) || entryIndex < 0 || entryIndex >= 10_000 || source.size > 64 * 1024 * 1024) {
    throw new Error("RAR4 selected entry or archive exceeds its budget");
  }
  const signature = await exact(source, 0, RAR4_SIGNATURE.length);
  if (!signature || !startsWith(signature, RAR4_SIGNATURE)) throw new Error("Input is not a RAR4 archive");
  let offset = RAR4_SIGNATURE.length;
  let selected = 0;
  for (let index = 0; index < MAX_HEADERS && offset + 7 <= source.size; index++) {
    if (signal?.aborted) throw signal.reason;
    const fixed = await exact(source, offset, 7);
    if (!fixed) throw new Error("RAR4 header is truncated");
    const view = dataView(fixed);
    const type = fixed[2];
    const flags = view.getUint16(3, true);
    const headerBytes = view.getUint16(5, true);
    if (headerBytes < 7 || headerBytes > 4096 || headerBytes > source.size - offset) throw new Error("RAR4 header exceeds its extent or budget");
    const header = await exact(source, offset, headerBytes);
    if (!header || (crc32(header.subarray(2)) & 0xffff) !== dataView(header).getUint16(0, true)) throw new Error("RAR4 header CRC is invalid");
    const record = dataView(header);
    if ((flags & 0x8000) && headerBytes < 11) throw new Error("RAR4 long-block data size is truncated");
    const packedBytes = flags & 0x8000 ? record.getUint32(7, true) : 0;
    const dataOffset = offset + headerBytes;
    if (packedBytes > source.size - dataOffset) throw new Error("RAR4 packed stream exceeds the archive");
    if (type === 0x73 && flags & 0x0080) throw new Error("RAR4 encrypted headers are unsupported");
    if (type === 0x74) {
      if (headerBytes < 32) throw new Error("RAR4 file header is truncated");
      if (selected++ === entryIndex) {
        const nameBytes = record.getUint16(26, true);
        const nameOffset = flags & 0x0100 ? 40 : 32;
        if (nameBytes < 1 || nameBytes > 1024 || nameOffset + nameBytes > headerBytes) throw new Error("RAR4 file name exceeds the header");
        const name = new TextDecoder("windows-1252").decode(header.subarray(nameOffset, nameOffset + nameBytes));
        const size = record.getUint32(11, true);
        const attributes = record.getUint32(28, true);
        const hostOs = header[15];
        if (flags & (0x0001 | 0x0002 | 0x0004 | 0x0100 | 0x0200) || header[25] !== 0x30 ||
          (flags & 0x8000) === 0 || record.getUint32(7, true) !== size ||
          size !== packedBytes || size > 8 * 1024 * 1024 || (hostOs === 3 && (attributes >>> 12 & 0xf) !== 8) ||
          (hostOs === 2 && (attributes & 0x10) !== 0) || ![2, 3].includes(hostOs) ||
          name.startsWith("/") || name.startsWith("\\") || /^[A-Za-z]:/.test(name) ||
          name.split(/[\\/]/).some((part) => !part || part === "." || part === "..")) {
          throw new Error("RAR4 entry is not a bounded unencrypted stored regular file");
        }
        const data = await exact(source, dataOffset, size);
        if (!data || crc32(data) !== record.getUint32(16, true)) throw new Error("RAR4 stored member CRC is invalid");
        return new MemorySource(data);
      }
    }
    offset = dataOffset + packedBytes;
    if (type === 0x7b) break;
  }
  throw new Error("RAR4 selected entry is outside the archive");
}

/** Select one bounded RAR5 stored regular file with a declared CRC; no decompression or link resolution. */
export async function extractRar5Stored(source: ByteSource, entryIndex: number, signal?: AbortSignal): Promise<ByteSource> {
  if (!Number.isSafeInteger(entryIndex) || entryIndex < 0 || entryIndex >= MAX_HEADERS || source.size > 64 * 1024 * 1024) {
    throw new Error("RAR5 selected entry or archive exceeds its budget");
  }
  const signature = await exact(source, 0, RAR5_SIGNATURE.length);
  if (!signature || !startsWith(signature, RAR5_SIGNATURE)) throw new Error("Input is not a RAR5 archive");
  let offset = RAR5_SIGNATURE.length;
  let selected = 0;
  for (let index = 0; index < MAX_HEADERS && offset + 7 <= source.size; index++) {
    if (signal?.aborted) throw signal.reason;
    const prefix = await source.read(offset, Math.min(16, source.size - offset));
    const length = readVint(prefix, 4);
    if (!length || length.value > 4096) throw new Error("RAR5 header size is invalid or exceeds 4096 bytes");
    const bodyAt = 4 + length.length;
    const header = await exact(source, offset, bodyAt + length.value);
    if (!header || crc32(header.subarray(4)) !== dataView(header).getUint32(0, true)) throw new Error("RAR5 header is truncated or its CRC is invalid");
    let cursor = bodyAt;
    const number = () => {
      const value = readVint(header, cursor);
      if (!value) throw new Error("RAR5 file metadata is truncated");
      cursor += value.length;
      return value.value;
    };
    const type = number();
    const flags = number();
    const extraBytes = flags & 1 ? number() : 0;
    const packedBytes = flags & 2 ? number() : 0;
    const extraStart = header.length - extraBytes;
    if (flags & ~7 || extraBytes > header.length - cursor || packedBytes > source.size - offset - header.length) {
      throw new Error("RAR5 header flags or packed extent are invalid");
    }
    if (type === 4) throw new Error("RAR5 encrypted headers are unsupported");
    if (type === 2 && selected++ === entryIndex) {
      const fileFlags = number();
      const unpackedBytes = number();
      const attributes = number();
      if (fileFlags & 2) number(); // optional mtime
      if ((fileFlags & 4) && cursor + 4 > extraStart) throw new Error("RAR5 file CRC field is truncated");
      const storedCrc = fileFlags & 4 ? dataView(header).getUint32(cursor, true) : null;
      if (storedCrc !== null) cursor += 4;
      const compression = number();
      const hostOs = number();
      const nameBytes = number();
      if (nameBytes < 1 || nameBytes > 1024 || cursor + nameBytes > extraStart) throw new Error("RAR5 filename exceeds the header");
      const name = new TextDecoder("utf-8", { fatal: true }).decode(header.subarray(cursor, cursor + nameBytes));
      cursor += nameBytes;
      // Permit only the independently checked 8-byte Unix nanosecond timestamp extra field.
      const timeExtra = extraBytes === 0 || (extraBytes === 11 && header[extraStart] === 10 && header[extraStart + 1] === 3 &&
        header[extraStart + 2] === 0x13);
      const extraIds = rar5ExtraIds(header, extraStart, extraBytes);
      if (flags & 4 || fileFlags & ~6 || storedCrc === null || compression !== 0 || ![0, 1].includes(hostOs) ||
        unpackedBytes !== packedBytes || packedBytes > 8 * 1024 * 1024 ||
        (hostOs === 1 && (attributes >>> 12 & 0xf) !== 8) || (hostOs === 0 && (attributes & 0x10) !== 0) ||
        cursor !== extraStart || !timeExtra || !extraIds || extraIds.some((id) => id !== 3) ||
        name.startsWith("/") || name.startsWith("\\") || /^[A-Za-z]:/.test(name) ||
        name.split(/[\\/]/).some((part) => !part || part === "." || part === "..")) {
        throw new Error("RAR5 entry is not a bounded unencrypted stored regular file");
      }
      const data = await exact(source, offset + header.length, packedBytes);
      if (!data || crc32(data) !== storedCrc) throw new Error("RAR5 stored member CRC is invalid");
      return new MemorySource(data);
    }
    offset += header.length + packedBytes;
    if (type === 5) break;
  }
  throw new Error("RAR5 selected entry is outside the archive");
}
