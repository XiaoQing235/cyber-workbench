import type { ByteSource } from "../core/bytes/ByteSource";
import { MemorySource } from "../core/bytes/sources";

const MAX_PCK_BYTES = 512 * 1024 * 1024;
const MAX_FILES = 10_000;
const MAX_EXTRACT_BYTES = 64 * 1024 * 1024;

export interface GodotPckFile {
  path: string;
  offset: number;
  size: number;
  md5: string;
  encrypted: boolean;
  removed: boolean;
  delta: boolean;
}

export interface GodotPckReport {
  formatVersion: 4;
  engineVersion: string;
  fileBase: number;
  directoryOffset: number;
  encryptedDirectory: boolean;
  files: GodotPckFile[];
  trailingBytes: number | null;
}

function safeNumber(value: bigint): number {
  const result = Number(value);
  if (!Number.isSafeInteger(result)) throw new Error("Godot PCK offset or size exceeds safe integer bounds");
  return result;
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function safePath(path: string): boolean {
  return path.length > 0 && path.length <= 1_024 && !path.startsWith("/") && !path.includes("\\") &&
    !/[\x00-\x1f\x7f]/.test(path) && path.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

export async function inspectGodotPck(source: ByteSource, signal?: AbortSignal): Promise<GodotPckReport> {
  if (!Number.isSafeInteger(source.size) || source.size < 44 || source.size > MAX_PCK_BYTES) throw new Error("Godot PCK is truncated or exceeds 512 MiB");
  if (signal?.aborted) throw signal.reason;
  const header = await source.read(0, 40);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  if (header.length !== 40 || view.getUint32(0, true) !== 0x43504447) throw new Error("Not a standalone Godot PCK archive");
  if (view.getUint32(4, true) !== 4) throw new Error("Only Godot PCK format V4 is supported");
  const flags = view.getUint32(20, true);
  if (flags & ~3) throw new Error("Godot PCK sparse or unknown pack flags are unsupported");
  const fileBase = safeNumber(view.getBigUint64(24, true));
  const directoryOffset = safeNumber(view.getBigUint64(32, true));
  if (fileBase < 40 || fileBase > directoryOffset || directoryOffset > source.size - 4) throw new Error("Godot PCK file base or directory offset is invalid");
  const report: GodotPckReport = {
    formatVersion: 4,
    engineVersion: `${view.getUint32(8, true)}.${view.getUint32(12, true)}.${view.getUint32(16, true)}`,
    fileBase, directoryOffset, encryptedDirectory: Boolean(flags & 1), files: [], trailingBytes: null,
  };
  if (report.encryptedDirectory) return report;
  const countBytes = await source.read(directoryOffset, 4);
  if (countBytes.length !== 4) throw new Error("Godot PCK directory is truncated");
  const count = new DataView(countBytes.buffer, countBytes.byteOffset, 4).getUint32(0, true);
  if (count > MAX_FILES) throw new Error("Godot PCK directory exceeds its 10,000-entry budget");
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const seen = new Set<string>();
  const extents: { start: number; end: number }[] = [];
  let cursor = directoryOffset + 4;
  for (let index = 0; index < count; index++) {
    if (signal?.aborted) throw signal.reason;
    if (cursor > source.size - 4) throw new Error("Godot PCK directory entry is truncated");
    const pathLengthBytes = await source.read(cursor, 4);
    const pathLength = new DataView(pathLengthBytes.buffer, pathLengthBytes.byteOffset, 4).getUint32(0, true);
    cursor += 4;
    if (pathLength < 1 || pathLength > 1_024 || cursor > source.size - pathLength - 36) throw new Error("Godot PCK directory entry length is invalid");
    const entry = await source.read(cursor, pathLength + 36);
    if (entry.length !== pathLength + 36) throw new Error("Godot PCK directory entry is truncated");
    const path = decoder.decode(entry.subarray(0, pathLength));
    if (!safePath(path) || seen.has(path)) throw new Error(`Godot PCK member path is unsafe or duplicated: ${path}`);
    seen.add(path);
    const fields = new DataView(entry.buffer, entry.byteOffset + pathLength, 36);
    const offset = safeNumber(fields.getBigUint64(0, true));
    const size = safeNumber(fields.getBigUint64(8, true));
    const memberFlags = fields.getUint32(32, true);
    if (memberFlags & ~7) throw new Error(`Godot PCK member ${path} has unknown flags`);
    const removed = Boolean(memberFlags & 2);
    const delta = Boolean(memberFlags & 4);
    if (removed && (size !== 0 || memberFlags & 1)) throw new Error(`Godot PCK removal ${path} declares file data`);
    const absoluteOffset = fileBase + offset;
    if (!Number.isSafeInteger(absoluteOffset) || (!removed && (absoluteOffset < fileBase || size > directoryOffset - absoluteOffset))) {
      throw new Error(`Godot PCK member ${path} exceeds packed file data`);
    }
    if (!removed && size > 0) extents.push({ start: absoluteOffset, end: absoluteOffset + size });
    report.files.push({ path, offset: absoluteOffset, size, md5: hex(entry.subarray(pathLength + 16, pathLength + 32)),
      encrypted: Boolean(memberFlags & 1), removed, delta });
    cursor += entry.length;
  }
  extents.sort((first, second) => first.start - second.start);
  if (extents.some((extent, index) => index > 0 && extent.start < extents[index - 1].end)) throw new Error("Godot PCK member data extents overlap");
  report.trailingBytes = source.size - cursor;
  return report;
}

export async function extractGodotPckFile(source: ByteSource, path: string, signal?: AbortSignal): Promise<{ data: ByteSource; md5Matched: true }> {
  const report = await inspectGodotPck(source, signal);
  if (report.encryptedDirectory) throw new Error("Godot PCK encrypted directory cannot be listed without a key");
  const file = report.files.find((item) => item.path === path);
  if (!file || file.encrypted || file.removed || file.delta) throw new Error("Godot PCK member is missing, encrypted, removed, or a delta");
  if (file.size > MAX_EXTRACT_BYTES) throw new Error("Godot PCK member exceeds the 64 MiB extraction budget");
  if (signal?.aborted) throw signal.reason;
  const bytes = await source.read(file.offset, file.size);
  if (bytes.length !== file.size) throw new Error("Godot PCK member is truncated");
  const { md5 } = await import("@noble/hashes/legacy");
  if (hex(md5(bytes)) !== file.md5) throw new Error(`Godot PCK member ${path} failed its declared MD5 checksum`);
  return { data: new MemorySource(bytes), md5Matched: true };
}
