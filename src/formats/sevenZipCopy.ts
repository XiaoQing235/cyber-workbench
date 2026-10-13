import type { ByteSource } from "../core/bytes/ByteSource";
import { MemorySource } from "../core/bytes/sources";
import { crc32 } from "../core/checksum/crc32";

const SIGNATURE = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];
const MAX_HEADER = 8 * 1024 * 1024;
const MAX_FILES = 128;

export interface SevenZipCopyReport {
  files: { name: string; bytes: number; crc32: string | null; payloadOffset: number; directory: boolean }[];
  payloadOffset: number;
  headerCrcValid: true;
  copyOnly: true;
}

/** Narrow reader for independent, uncompressed, non-solid 7z Copy streams. */
export async function inspectSevenZipCopy(source: ByteSource, signal?: AbortSignal): Promise<SevenZipCopyReport> {
  if (!Number.isSafeInteger(source.size) || source.size < 32 || source.size > 512 * 1024 * 1024) throw new Error("7z Copy archive exceeds its size budget");
  if (signal?.aborted) throw signal.reason;
  const fixed = await source.read(0, 32);
  if (fixed.length !== 32 || !SIGNATURE.every((byte, index) => fixed[index] === byte)) throw new Error("Not a 7z archive");
  const view = new DataView(fixed.buffer, fixed.byteOffset, 32);
  if (crc32(fixed.subarray(12)) !== view.getUint32(8, true)) throw new Error("7z start header CRC mismatch");
  const offset = Number(view.getBigUint64(12, true));
  const size = Number(view.getBigUint64(20, true));
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(size) || size > MAX_HEADER || size < 1 || 32 + offset + size > source.size) {
    throw new Error("7z Copy header extent exceeds its budget");
  }
  const header = await source.read(32 + offset, size);
  if (header.length !== size || crc32(header) !== view.getUint32(28, true)) throw new Error("7z next header CRC mismatch");
  let cursor = 0;
  const byte = () => {
    if (cursor >= header.length) throw new Error("7z Copy metadata is truncated");
    return header[cursor++];
  };
  const integer = (): number => {
    const first = byte();
    let value = 0;
    for (let i = 0; i < 8; i++) {
      const mask = 0x80 >> i;
      if (!(first & mask)) return value + (first & (mask - 1)) * 2 ** (i * 8);
      value += byte() * 2 ** (i * 8);
    }
    return value;
  };
  const boundedInteger = (): number => {
    const value = integer();
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("7z Copy integer exceeds safe bounds");
    return value;
  };
  const need = (expected: number) => {
    if (byte() !== expected) throw new Error(`7z Copy metadata requires marker 0x${expected.toString(16)}`);
  };
  need(0x01);
  let packPosition = 0;
  let count = 0;
  let packedSizes: number[] = [];
  let unpackedSizes: number[] = [];
  let crcValues: number[] = [];
  if (header[cursor] === 0x04) {
    need(0x04); need(0x06);
    packPosition = boundedInteger();
    count = boundedInteger();
    if (count < 1 || count > MAX_FILES) throw new Error("7z Copy packed stream count exceeds its budget");
    need(0x09);
    packedSizes = Array.from({ length: count }, () => boundedInteger());
    if (packedSizes.some((size) => size > 64 * 1024 * 1024) || packedSizes.reduce((sum, size) => sum + size, 0) > 64 * 1024 * 1024) {
      throw new Error("7z Copy stream sizes exceed 64 MiB");
    }
    need(0x00); need(0x07); need(0x0b);
    if (boundedInteger() !== count) throw new Error("7z Copy folder count differs from packed streams");
    for (let index = 0; index < count; index++) {
      if (byte() !== 0 || boundedInteger() !== 1 || byte() !== 1) {
        throw new Error("7z Copy folder has unsupported coders");
      }
    }
    need(0x00); // end of UnpackInfo folder declarations
    need(0x0c);
    unpackedSizes = Array.from({ length: count }, () => boundedInteger());
    if (packedSizes.some((size, index) => size !== unpackedSizes[index])) throw new Error("7z Copy packed and unpacked sizes differ");
    need(0x00); // end of CodersUnpackInfo
    need(0x08); need(0x0a);
    if (byte() !== 1 || cursor + count * 4 > header.length) throw new Error("7z Copy CRC declarations are missing");
    crcValues = Array.from({ length: count }, () => {
      const checksum = new DataView(header.buffer, header.byteOffset + cursor, 4).getUint32(0, true);
      cursor += 4;
      return checksum;
    });
    need(0x00); // end of SubStreamsInfo
    need(0x00); // end of MainStreamsInfo
  }
  need(0x05);
  const fileCount = boundedInteger();
  if (fileCount < Math.max(1, count) || fileCount > MAX_FILES) throw new Error("7z Copy file count exceeds its budget");
  const empty = new Array<boolean>(fileCount).fill(false);
  const directories = new Array<boolean>(fileCount).fill(false);
  if (header[cursor] === 0x0e) {
    cursor++;
    const length = boundedInteger();
    if (length !== Math.ceil(fileCount / 8) || cursor + length > header.length) throw new Error("7z Copy empty-stream bitmap is invalid");
    for (let index = 0; index < fileCount; index++) empty[index] = (header[cursor + (index >> 3)] & (0x80 >> (index & 7))) !== 0;
    cursor += length;
    if (empty.filter(Boolean).length !== fileCount - count) throw new Error("7z Copy empty-stream count disagrees with packed streams");
    const emptyCount = fileCount - count;
    const emptyFiles: boolean[] = [];
    if (header[cursor] === 0x0f) {
      cursor++;
      const emptyLength = boundedInteger();
      if (emptyLength !== Math.ceil(emptyCount / 8) || cursor + emptyLength > header.length) throw new Error("7z Copy empty-file bitmap is invalid");
      for (let index = 0; index < emptyCount; index++) emptyFiles.push((header[cursor + (index >> 3)] & (0x80 >> (index & 7))) !== 0);
      cursor += emptyLength;
    } else {
      emptyFiles.push(...new Array<boolean>(emptyCount).fill(false));
    }
    let emptyIndex = 0;
    for (let index = 0; index < fileCount; index++) {
      if (empty[index]) directories[index] = !emptyFiles[emptyIndex++];
    }
  } else if (fileCount !== count) throw new Error("7z Copy file count differs from streams");
  if (header[cursor] === 0x19) { // Dummy property
    cursor++;
    const size = boundedInteger();
    if (size > header.length - cursor) throw new Error("7z Copy Dummy property exceeds header");
    cursor += size;
  }
  need(0x11);
  const nameLength = boundedInteger();
  if (nameLength < fileCount * 3 || nameLength > fileCount * 2048 || byte() !== 0 || cursor + nameLength - 1 > header.length) {
    throw new Error("7z Copy filename extent is invalid");
  }
  const nameBytes = header.subarray(cursor, cursor + nameLength - 1);
  cursor += nameLength - 1;
  if (nameBytes.length % 2 !== 0 || nameBytes.at(-1) !== 0 || nameBytes.at(-2) !== 0) throw new Error("7z Copy filename is unterminated");
  const names = new TextDecoder("utf-16le", { fatal: true }).decode(nameBytes).split("\0");
  if (names.pop() !== "" || names.length !== fileCount || new Set(names).size !== fileCount || names.some((name) =>
    !name || name.startsWith("/") || name.includes("\\") || /[\x00-\x1f\x7f]/.test(name) || name.split("/").some((part) => !part || part === "." || part === ".."))) {
    throw new Error("7z Copy filenames are missing, duplicated or unsafe");
  }
  // Other file properties (mtime, attributes) are deliberately not interpreted here.
  while (cursor < header.length && header[cursor] !== 0) {
    const property = byte();
    const length = boundedInteger();
    if (![0x12, 0x13, 0x14, 0x15, 0x19].includes(property) || length > header.length - cursor) throw new Error(`7z Copy file property 0x${property.toString(16)} is unsupported`);
    cursor += length;
  }
  need(0x00); need(0x00);
  if (cursor !== header.length) throw new Error("7z Copy header has trailing metadata");
  const payloadOffset = 32 + packPosition;
  if (payloadOffset + packedSizes.reduce((sum, size) => sum + size, 0) > 32 + offset) throw new Error("7z Copy payload overlaps the header");
  let position = payloadOffset;
  let streamIndex = 0;
  const files = names.map((name, index) => {
    const selected = streamIndex;
    if (!empty[index]) streamIndex++;
    const file = { name, bytes: empty[index] ? 0 : unpackedSizes[selected],
      crc32: empty[index] ? directories[index] ? null : "0x00000000" : `0x${crcValues[selected].toString(16).padStart(8, "0")}`,
      payloadOffset: position, directory: directories[index] };
    if (!empty[index]) position += packedSizes[selected];
    return file;
  });
  return { files,
    payloadOffset, headerCrcValid: true, copyOnly: true };
}

export async function extractSevenZipCopy(source: ByteSource, signal?: AbortSignal, entryIndex = 0): Promise<ByteSource> {
  const report = await inspectSevenZipCopy(source, signal);
  if (!Number.isSafeInteger(entryIndex) || entryIndex < 0 || entryIndex >= report.files.length) throw new Error("7z Copy entry index is outside the file list");
  const file = report.files[entryIndex];
  if (file.directory) throw new Error("7z Copy directory is not an extractable file");
  const data = await source.read(file.payloadOffset, file.bytes);
  if (signal?.aborted) throw signal.reason;
  if (data.length !== file.bytes || `0x${crc32(data).toString(16).padStart(8, "0")}` !== file.crc32) {
    throw new Error("7z Copy payload CRC mismatch");
  }
  return new MemorySource(data);
}
