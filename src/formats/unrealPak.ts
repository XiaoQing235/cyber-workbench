import type { ByteSource } from "../core/bytes/ByteSource";
import { SliceSource } from "../core/bytes/sources";

const MAGIC = 0x5a6f12e1;
const MAX_PAK = 512 * 1024 * 1024;
const MAX_INDEX = 8 * 1024 * 1024;
const FOOTER = 44; // magic + version + index offset + index size + SHA-1 digest

export interface UnrealPakReport {
  version: number;
  footerOffset: number;
  indexOffset: number;
  indexBytes: number;
  indexSha1Verified: boolean;
  indexEncrypted: boolean;
  indexDecoded: false;
  compressionMethods: string[];
}

export interface UnrealPakEntry {
  path: string;
  offset: number;
  dataOffset: number;
  bytes: number;
  sha1: string;
}

export interface UnrealPakIndex {
  mountPoint: string;
  entries: UnrealPakEntry[];
  compression: "none";
  indexSha1Verified: true;
}

/** Inspect legacy Unreal PAK v1–v3 trailing footer, not a complete asset reader. */
export async function inspectUnrealPak(source: ByteSource, signal?: AbortSignal): Promise<UnrealPakReport> {
  if (!Number.isSafeInteger(source.size) || source.size < FOOTER || source.size > MAX_PAK) throw new Error("Unreal PAK exceeds its size budget");
  if (signal?.aborted) throw signal.reason;
  const bytes = await source.read(source.size - FOOTER, FOOTER);
  if (bytes.length !== FOOTER) throw new Error("Unreal PAK footer is truncated");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, true) !== MAGIC) throw new Error("Not a trailing Unreal PAK v1–v3 footer");
  const version = view.getUint32(4, true);
  if (version < 1 || version > 3) throw new Error(`Unreal PAK version ${version} needs a different footer parser`);
  const offset = view.getBigUint64(8, true);
  const size = view.getBigUint64(16, true);
  if (size < 1n || size > BigInt(MAX_INDEX) || offset + size > BigInt(source.size - FOOTER)) throw new Error("Unreal PAK index exceeds its bounded extent");
  const indexOffset = Number(offset);
  const indexBytes = Number(size);
  const index = await source.read(indexOffset, indexBytes);
  if (signal?.aborted) throw signal.reason;
  if (index.length !== indexBytes) throw new Error("Unreal PAK index is truncated");
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", index));
  if (!digest.every((value, position) => value === bytes[24 + position])) throw new Error("Unreal PAK index SHA-1 mismatch");
  return { version, footerOffset: source.size - FOOTER, indexOffset, indexBytes,
    indexSha1Verified: true, indexEncrypted: false, indexDecoded: false, compressionMethods: [] };
}

/** Decode a narrow v3 legacy index of uncompressed entries (no encryption or block table). */
export async function listUnrealPak(source: ByteSource, signal?: AbortSignal): Promise<UnrealPakIndex> {
  const report = await inspectUnrealPak(source, signal);
  if (report.version !== 3) throw new Error("Unreal PAK index supports version 3 only");
  const bytes = await source.read(report.indexOffset, report.indexBytes);
  if (bytes.length !== report.indexBytes) throw new Error("Unreal PAK index changed or is truncated");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let cursor = 0;
  const take = (size: number): number => {
    if (!Number.isSafeInteger(size) || size < 0 || size > bytes.length - cursor) throw new Error("Unreal PAK index is truncated");
    const at = cursor;
    cursor += size;
    return at;
  };
  const u32 = () => view.getUint32(take(4), true);
  const u64 = () => {
    const number = view.getBigUint64(take(8), true);
    if (number > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error("Unreal PAK entry extent exceeds safe integer bounds");
    return Number(number);
  };
  const name = (): string => {
    const length = view.getInt32(take(4), true);
    if (length < 1 || length > 1024) throw new Error("Unreal PAK index string length is unsupported");
    const data = bytes.subarray(take(length), cursor);
    if (data.at(-1) !== 0) throw new Error("Unreal PAK string is unterminated");
    return new TextDecoder("utf-8", { fatal: true }).decode(data.subarray(0, -1));
  };
  const mountPoint = name();
  const count = u32();
  if (count > 10_000) throw new Error("Unreal PAK file count exceeds the budget");
  const entries: UnrealPakEntry[] = [];
  const paths = new Set<string>();
  for (let index = 0; index < count; index++) {
    if (signal?.aborted) throw signal.reason;
    const path = name();
    if (path.startsWith("/") || path.includes("\\") || path.split("/").some((part) => !part || part === "." || part === "..") ||
      /[\x00-\x1f\x7f]/.test(path) || paths.has(path)) throw new Error("Unreal PAK member path is unsafe or duplicated");
    paths.add(path);
    const offset = u64();
    const compressed = u64();
    const bytesCount = u64();
    if (u32() !== 0 || compressed !== bytesCount) throw new Error("Unreal PAK compressed entries are unsupported");
    const sha = bytes.subarray(take(20), cursor);
    const encrypted = bytes[take(1)];
    if (encrypted !== 0) throw new Error("Unreal PAK encrypted entries are unsupported");
    take(4); // compression-block size
    // Legacy v3 offsets point to an on-disk 53-byte FPakEntry header, then file data.
    const dataOffset = offset + 53;
    if (offset >= report.indexOffset || dataOffset > report.indexOffset || bytesCount > report.indexOffset - dataOffset) throw new Error("Unreal PAK entry exceeds the data region");
    entries.push({ path, offset, dataOffset, bytes: bytesCount, sha1: Array.from(sha, (part) => part.toString(16).padStart(2, "0")).join("") });
  }
  if (cursor !== bytes.length) throw new Error("Unreal PAK index contains trailing metadata");
  return { mountPoint, entries, compression: "none", indexSha1Verified: true };
}

export async function extractUnrealPakEntry(source: ByteSource, path: string, signal?: AbortSignal): Promise<ByteSource> {
  const index = await listUnrealPak(source, signal);
  const entry = index.entries.find((item) => item.path === path);
  if (!entry) throw new Error("Unreal PAK member path is not in the supported index");
  if (entry.bytes > 64 * 1024 * 1024) throw new Error("Unreal PAK member exceeds the extraction budget");
  const rawHeader = await source.read(entry.offset, 53);
  if (rawHeader.length !== 53) throw new Error("Unreal PAK local entry header is truncated");
  const local = new DataView(rawHeader.buffer, rawHeader.byteOffset, rawHeader.byteLength);
  if (local.getBigUint64(0, true) !== BigInt(entry.offset) || local.getBigUint64(8, true) !== BigInt(entry.bytes) ||
    local.getBigUint64(16, true) !== BigInt(entry.bytes) || local.getUint32(24, true) !== 0 ||
    rawHeader[48] !== 0 || local.getUint32(49, true) !== 0) throw new Error("Unreal PAK local entry disagrees with the index");
  const localSha = Array.from(rawHeader.subarray(28, 48), (part) => part.toString(16).padStart(2, "0")).join("");
  if (localSha !== entry.sha1) throw new Error("Unreal PAK local entry SHA-1 disagrees with the index");
  const data = new SliceSource(source, entry.dataOffset, entry.bytes);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-1", await data.read(0, data.size)));
  if (!digest.every((part, index) => part.toString(16).padStart(2, "0") === entry.sha1.slice(index * 2, index * 2 + 2))) {
    throw new Error("Unreal PAK member SHA-1 mismatch");
  }
  return data;
}
