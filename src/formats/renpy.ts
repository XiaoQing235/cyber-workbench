import type { ByteSource } from "../core/bytes/ByteSource";
import { ConcatSource, MemorySource, SliceSource } from "../core/bytes/sources";
import { inflate } from "../core/compression/inflate";

const MAX_INDEX = 4 * 1024 * 1024;
export const MAX_RPA_BYTES = 512 * 1024 * 1024;

export interface RenPyReport {
  version: "RPA-3.0";
  indexOffset: number;
  indexBytes: number;
  key: string;
  indexFormat: "pickle";
  indexExecuted: false;
}

export interface RenPyMember {
  path: string;
  offset: number;
  bytes: number;
  prefixBytes: number;
  prefix: number[];
}

/** Inspect an RPA-3.0 header without unpickling the index. */
export async function inspectRenPy(source: ByteSource, signal?: AbortSignal): Promise<RenPyReport> {
  if (!Number.isSafeInteger(source.size) || source.size < 34 || source.size > MAX_RPA_BYTES) throw new Error("Ren'Py archive exceeds its 512 MiB budget");
  if (signal?.aborted) throw signal.reason;
  const header = await source.read(0, 34);
  if (header.length !== 34) throw new Error("Ren'Py RPA header is truncated");
  const text = new TextDecoder("ascii", { fatal: true }).decode(header);
  const match = /^RPA-3\.0 ([0-9a-fA-F]{16}) ([0-9a-fA-F]{8})\n$/.exec(text);
  if (!match) throw new Error("Not a supported RPA-3.0 archive header");
  const indexOffset = Number.parseInt(match[1], 16);
  if (!Number.isSafeInteger(indexOffset) || indexOffset < 34 || indexOffset >= source.size || source.size - indexOffset > MAX_INDEX) {
    throw new Error("Ren'Py index exceeds its bounded archive extent");
  }
  return { version: "RPA-3.0", indexOffset, indexBytes: source.size - indexOffset,
    key: `0x${match[2].toLowerCase()}`, indexFormat: "pickle", indexExecuted: false };
}

/** Ren'Py v3 indexes are zlib-compressed pickles; unsafe opcodes are never run. */
export async function extractRenPyIndex(source: ByteSource, signal?: AbortSignal): Promise<ByteSource> {
  const report = await inspectRenPy(source, signal);
  if (report.indexBytes > MAX_INDEX) throw new Error("Ren'Py index extraction budget exceeded");
  return new SliceSource(source, report.indexOffset, report.indexBytes);
}

/** Restrictive parser for the simple dict[str, list[(offset, length, prefix)]] pickle shape. */
export async function listRenPyMembers(source: ByteSource, signal?: AbortSignal): Promise<RenPyMember[]> {
  const report = await inspectRenPy(source, signal);
  const compressed = new SliceSource(source, report.indexOffset, report.indexBytes);
  const result = await inflate(compressed, "zlib", { maxOutputBytes: MAX_INDEX, signal });
  if (result.error) throw new Error(`Ren'Py index is corrupt: ${result.error}`);
  const bytes = result.bytes;
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let cursor = 0;
  const take = (count: number): Uint8Array => {
    if (count < 0 || cursor + count > bytes.length) throw new Error("Ren'Py pickle index is truncated");
    const value = bytes.subarray(cursor, cursor + count);
    cursor += count;
    return value;
  };
  const number = (width: 1 | 4): number => {
    const data = take(width);
    return width === 1 ? data[0] : new DataView(data.buffer, data.byteOffset, width).getUint32(0, true);
  };
  // This is deliberately a grammar recognizer, not a generic pickle VM: no GLOBAL/REDUCE or memo references.
  if (number(1) !== 0x80 || ![2, 3, 4, 5].includes(number(1))) throw new Error("Ren'Py index needs a supported pickle protocol");
  if (bytes[cursor] === 0x95) {
    cursor++;
    const frame = take(8);
    const size = new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getBigUint64(0, true);
    if (size !== BigInt(bytes.length - cursor)) throw new Error("Ren'Py pickle frame extent is invalid");
  }
  if (number(1) !== 0x7d) throw new Error("Ren'Py index needs a literal dictionary layout");
  const memo = new Set<number>();
  const skipMemo = (): void => {
    if (bytes[cursor] === 0x94) { cursor++; memo.add(memo.size); }
    else if (bytes[cursor] === 0x71) { cursor++; const index = number(1); if (memo.has(index)) throw new Error("Ren'Py pickle reuses a memo index"); memo.add(index); }
  };
  skipMemo();
  const members: RenPyMember[] = [];
  const seen = new Set<string>();
  const key = Number.parseInt(report.key.slice(2), 16);
  while (cursor < bytes.length && bytes[cursor] !== 0x2e) {
    if (signal?.aborted) throw signal.reason;
    if (members.length >= 10_000) throw new Error("Ren'Py member count exceeds 10,000");
    const opcode = number(1);
    if (opcode !== 0x58 && opcode !== 0x55 && opcode !== 0x8c) throw new Error(`Unsupported Ren'Py pickle opcode 0x${opcode.toString(16)}`);
    const length = opcode === 0x55 || opcode === 0x8c ? number(1) : number(4);
    if (length < 1 || length > 1024) throw new Error("Ren'Py member path exceeds its budget");
    const path = decoder.decode(take(length));
    if (path.startsWith("/") || path.includes("\\") || path.split("/").some((part) => !part || part === "." || part === "..") ||
      /[\0-\x1f\x7f]/.test(path) || seen.has(path)) throw new Error("Ren'Py member path is unsafe or duplicated");
    seen.add(path);
    skipMemo();
    if (number(1) !== 0x5d) throw new Error("Ren'Py member list is unsupported");
    skipMemo();
    const markedTuple = bytes[cursor] === 0x28;
    if (markedTuple) cursor++;
    const integer = (): number => {
      const op = number(1);
      if (op === 0x4b) return number(1);
      if (op === 0x4d) { const data = take(2); return new DataView(data.buffer, data.byteOffset, 2).getUint16(0, true); }
      if (op === 0x4a) return number(4);
      throw new Error(`Unsupported Ren'Py pickle integer opcode 0x${op.toString(16)}`);
    };
    const offset = (integer() ^ key) >>> 0;
    const size = (integer() ^ key) >>> 0;
    const prefixOpcode = number(1);
    let prefix: number[];
    if (prefixOpcode === 0x63) {
      // Protocol-2 Python bytes use GLOBAL _codecs.encode, but never evaluate it: recognize
      // this one exact literal latin1 construction and decode it ourselves.
      const global = take(15);
      if (new TextDecoder("ascii").decode(global) !== "_codecs\nencode\n") throw new Error("Ren'Py pickle global is unsupported");
      skipMemo();
      if (number(1) !== 0x58) throw new Error("Ren'Py protocol-2 byte prefix needs a Unicode literal");
      const length = number(4);
      if (length > 2048) throw new Error("Ren'Py member prefix exceeds its text budget");
      const decoded = decoder.decode(take(length));
      skipMemo();
      if (number(1) !== 0x58 || number(4) !== 6 || decoder.decode(take(6)) !== "latin1") {
        throw new Error("Ren'Py protocol-2 prefix must use literal latin1 encoding");
      }
      skipMemo();
      if (number(1) !== 0x86) throw new Error("Ren'Py protocol-2 prefix tuple is unsupported");
      skipMemo();
      if (number(1) !== 0x52) throw new Error("Ren'Py protocol-2 prefix reduction is unsupported");
      skipMemo();
      prefix = Array.from(decoded, (character) => {
        if (character.charCodeAt(0) > 255) throw new Error("Ren'Py latin1 prefix contains an out-of-range character");
        return character.charCodeAt(0);
      });
    } else {
      if (prefixOpcode !== 0x55 && prefixOpcode !== 0x54 && prefixOpcode !== 0x43 && prefixOpcode !== 0x42) throw new Error("Ren'Py member prefix must be a pickle byte string");
      const prefixLength = prefixOpcode === 0x55 || prefixOpcode === 0x43 ? number(1) : number(4);
      if (prefixLength > 1024) throw new Error("Ren'Py member prefix exceeds 1 KiB");
      prefix = Array.from(take(prefixLength));
      skipMemo();
    }
    if (number(1) !== (markedTuple ? 0x74 : 0x87)) throw new Error("Ren'Py member tuple terminator is unsupported");
    skipMemo();
    if (number(1) !== 0x61 || number(1) !== 0x73) {
      throw new Error("Ren'Py member tuple/list/dict terminator is unsupported");
    }
    if (offset < 34 || offset + size > report.indexOffset) throw new Error("Ren'Py member data exceeds the archive extent");
    members.push({ path, offset, bytes: size + prefix.length, prefixBytes: prefix.length, prefix });
  }
  if (number(1) !== 0x2e || cursor !== bytes.length) throw new Error("Ren'Py pickle index has trailing or incomplete data");
  return members;
}

export async function extractRenPyMember(source: ByteSource, path: string, signal?: AbortSignal): Promise<ByteSource> {
  const members = await listRenPyMembers(source, signal);
  const member = members.find((entry) => entry.path === path);
  if (!member) throw new Error("Ren'Py member path is not present in the supported index");
  if (member.bytes > 64 * 1024 * 1024) throw new Error("Ren'Py member exceeds the extraction budget");
  return new ConcatSource([new MemorySource(Uint8Array.from(member.prefix)),
    new SliceSource(source, member.offset, member.bytes - member.prefixBytes)]);
}
