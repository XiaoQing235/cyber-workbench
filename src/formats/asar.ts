import type { ByteSource } from "../core/bytes/ByteSource";
import { SliceSource } from "../core/bytes/sources";

const MAX_HEADER_BYTES = 4 * 1024 * 1024;
const MAX_ENTRIES = 10_000;
const MAX_EXTRACT_BYTES = 64 * 1024 * 1024;

export interface AsarFile {
  path: string;
  bytes: number;
  offset: number | null;
  link: string | null;
  unpacked: boolean;
  declaredSha256: string | null;
}

export interface AsarReport {
  headerBytes: number;
  dataOffset: number;
  directories: number;
  files: AsarFile[];
  integrityChecked: false;
}

function entryObject(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`ASAR ${label} must be an object`);
  return value as Record<string, unknown>;
}

function filename(value: string): string {
  if (value.length < 1 || value.length > 255 || value === "." || value === ".." || value.includes("/") || value.includes("\\") || /[\0-\x1f\x7f]/.test(value)) throw new Error("ASAR member name is unsafe");
  return value;
}

export async function inspectAsar(source: ByteSource, signal?: AbortSignal): Promise<AsarReport> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < 17) throw new Error("ASAR header is truncated");
  const prefix = await source.read(0, 16);
  if (prefix.length !== 16) throw new Error("ASAR header is truncated");
  const view = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength);
  const outer = view.getUint32(0, true);
  const headerBytes = view.getUint32(4, true);
  const bufferBytes = view.getUint32(8, true);
  const jsonBytes = view.getUint32(12, true);
  const dataOffset = 8 + headerBytes;
  if (outer !== 4 || headerBytes !== bufferBytes + 4 || bufferBytes !== Math.ceil((jsonBytes + 4) / 4) * 4 ||
    jsonBytes < 2 || headerBytes > MAX_HEADER_BYTES || dataOffset > source.size) throw new Error("ASAR header lengths or data extent are invalid");
  const json = await source.read(16, jsonBytes);
  if (json.length !== jsonBytes) throw new Error("ASAR JSON header is truncated");
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(json)); }
  catch { throw new Error("ASAR JSON header is invalid"); }
  const files = entryObject(entryObject(parsed, "header").files, "root files");
  const result: AsarFile[] = [];
  let directories = 0;
  const visit = (tree: Record<string, unknown>, parent: string, depth: number) => {
    if (depth > 32) throw new Error("ASAR directory nesting exceeds 32 levels");
    for (const [rawName, rawEntry] of Object.entries(tree)) {
      if (signal?.aborted) throw signal.reason;
      const path = parent ? `${parent}/${filename(rawName)}` : filename(rawName);
      if (path.length > 1_024 || result.length + directories >= MAX_ENTRIES) throw new Error("ASAR file tree exceeds its entry budget");
      const entry = entryObject(rawEntry, `member ${path}`);
      if (entry.files !== undefined) {
        directories++;
        visit(entryObject(entry.files, `directory ${path}`), path, depth + 1);
        continue;
      }
      const link = entry.link === undefined ? null : entry.link;
      if (link !== null && (typeof link !== "string" || link.length < 1 || link.length > 1_024)) throw new Error("ASAR link target is invalid");
      const unpacked = entry.unpacked === true;
      const bytes = entry.size === undefined && link !== null ? 0 : entry.size;
      if (!Number.isSafeInteger(bytes) || (bytes as number) < 0) throw new Error(`ASAR member ${path} has an invalid size`);
      let offset: number | null = null;
      if (link === null && !unpacked) {
        if (typeof entry.offset !== "string" || !/^\d+$/.test(entry.offset)) throw new Error(`ASAR member ${path} has an invalid offset`);
        offset = Number(entry.offset);
        if (!Number.isSafeInteger(offset) || offset + (bytes as number) > source.size - dataOffset) throw new Error(`ASAR member ${path} exceeds archive data`);
      }
      let declaredSha256: string | null = null;
      if (entry.integrity !== undefined) {
        const integrity = entryObject(entry.integrity, "integrity");
        if (integrity.algorithm !== "SHA256" || typeof integrity.hash !== "string" || !/^[0-9a-f]{64}$/i.test(integrity.hash)) throw new Error(`ASAR member ${path} has unsupported integrity metadata`);
        declaredSha256 = integrity.hash.toLowerCase();
      }
      result.push({ path, bytes: bytes as number, offset, link: link as string | null, unpacked, declaredSha256 });
    }
  };
  visit(files, "", 0);
  return { headerBytes, dataOffset, directories, files: result, integrityChecked: false };
}

export async function extractAsarFile(source: ByteSource, path: string, signal?: AbortSignal): Promise<{ data: ByteSource; integrityVerified: boolean }> {
  const report = await inspectAsar(source, signal);
  const file = report.files.find((item) => item.path === path);
  if (!file || file.offset === null || file.link !== null || file.unpacked) throw new Error("ASAR packed file path is missing or not available inside the archive");
  if (file.bytes > MAX_EXTRACT_BYTES) throw new Error("ASAR file exceeds the 64 MiB extraction budget");
  const data = new SliceSource(source, report.dataOffset + file.offset, file.bytes);
  if (file.declaredSha256) {
    if (signal?.aborted) throw signal.reason;
    const bytes = await data.read(0, file.bytes);
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    const actual = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    if (actual !== file.declaredSha256) throw new Error(`ASAR member ${path} failed its declared SHA-256`);
  }
  return { data, integrityVerified: file.declaredSha256 !== null };
}