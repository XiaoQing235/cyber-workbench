import type { ByteSource } from "../core/bytes/ByteSource";
import { MemorySource, SliceSource } from "../core/bytes/sources";
import { inflate } from "../core/compression/inflate";
import { magicForPythonVersion } from "./pythonBytecode";

const COOKIE = Uint8Array.of(0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e);
const COOKIE_BYTES = 88;
const TOC_HEADER_BYTES = 18;
const MAX_TAIL_BYTES = 4 * 1024 * 1024;
const MAX_TOC_BYTES = 4 * 1024 * 1024;
const MAX_INPUT_BYTES = 512 * 1024 * 1024;
const MAX_EXTRACT_BYTES = 64 * 1024 * 1024;
const MAX_ENTRIES = 10_000;

export interface PyInstallerEntry {
  name: string;
  typecode: string;
  offset: number;
  storedBytes: number;
  unpackedBytes: number;
  compressed: boolean;
}

export interface PyInstallerReport {
  pythonVersion: string;
  pythonLibrary: string;
  archiveOffset: number;
  archiveEnd: number;
  tocBytes: number;
  trailingBytes: number;
  entries: PyInstallerEntry[];
  executed: false;
}

function safeName(name: string): boolean {
  return name.length > 0 && name.length <= 1_024 && !name.startsWith("/") && !name.includes("\\") &&
    !/[\x00-\x1f\x7f]/.test(name) && name.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

export async function inspectPyInstaller(source: ByteSource, signal?: AbortSignal): Promise<PyInstallerReport> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < COOKIE_BYTES || source.size > MAX_INPUT_BYTES) throw new Error("PyInstaller input is truncated or exceeds 512 MiB");
  const tailOffset = Math.max(0, source.size - MAX_TAIL_BYTES);
  const tail = await source.read(tailOffset, source.size - tailOffset);
  if (tail.length !== source.size - tailOffset) throw new Error("PyInstaller trailer is truncated");
  let archiveStart = -1;
  let archiveEnd = 0;
  let tocOffset = 0;
  let tocBytes = 0;
  let pythonVersion = "";
  let pythonLibrary = "";
  const decoder = new TextDecoder("utf-8", { fatal: true });
  for (let index = tail.length - COOKIE_BYTES; index >= 0; index--) {
    if ((index & 0xffff) === 0 && signal?.aborted) throw signal.reason;
    if (tail[index] !== COOKIE[0] || !COOKIE.every((value, at) => tail[index + at] === value)) continue;
    const cookie = new DataView(tail.buffer, tail.byteOffset + index, COOKIE_BYTES);
    const archiveBytes = cookie.getUint32(8, false);
    const listedOffset = cookie.getUint32(12, false);
    const listedBytes = cookie.getUint32(16, false);
    const version = cookie.getUint32(20, false);
    const end = tailOffset + index + COOKIE_BYTES;
    const start = end - archiveBytes;
    const libraryBytes = tail.subarray(index + 24, index + COOKIE_BYTES);
    const nul = libraryBytes.indexOf(0);
    if (start < 0 || archiveBytes < COOKIE_BYTES || listedBytes < TOC_HEADER_BYTES || listedBytes > MAX_TOC_BYTES ||
      listedOffset + listedBytes !== archiveBytes - COOKIE_BYTES || version < 300 || version > 399 || nul < 1) continue;
    archiveStart = start;
    archiveEnd = end;
    tocOffset = listedOffset;
    tocBytes = listedBytes;
    pythonVersion = `${Math.floor(version / 100)}.${version % 100}`;
    pythonLibrary = decoder.decode(libraryBytes.subarray(0, nul));
    break;
  }
  if (archiveStart < 0) throw new Error("No valid PyInstaller CArchive cookie was found in the final 4 MiB");
  const toc = await source.read(archiveStart + tocOffset, tocBytes);
  if (toc.length !== tocBytes) throw new Error("PyInstaller TOC is truncated");
  const view = new DataView(toc.buffer, toc.byteOffset, toc.byteLength);
  const entries: PyInstallerEntry[] = [];
  const seen = new Set<string>();
  let cursor = 0;
  while (cursor < toc.length) {
    if (signal?.aborted) throw signal.reason;
    if (entries.length >= MAX_ENTRIES || cursor + TOC_HEADER_BYTES > toc.length) throw new Error("PyInstaller TOC exceeds its entry budget or is truncated");
    const length = view.getUint32(cursor, false);
    const offset = view.getUint32(cursor + 4, false);
    const storedBytes = view.getUint32(cursor + 8, false);
    const unpackedBytes = view.getUint32(cursor + 12, false);
    const compressed = toc[cursor + 16];
    const typecode = String.fromCharCode(toc[cursor + 17]);
    if (length < TOC_HEADER_BYTES + 1 || length > 4_096 || cursor + length > toc.length ||
      (compressed !== 0 && compressed !== 1) || offset + storedBytes > tocOffset) throw new Error("PyInstaller TOC entry extent or compression flag is invalid");
    const nameBytes = toc.subarray(cursor + TOC_HEADER_BYTES, cursor + length);
    const end = nameBytes.indexOf(0);
    if (end < 1) throw new Error("PyInstaller TOC member name is unterminated");
    const name = decoder.decode(nameBytes.subarray(0, end));
    if (!safeName(name) || (typecode !== "o" && seen.has(name))) throw new Error(`PyInstaller TOC member name is unsafe or duplicated: ${name}`);
    seen.add(name);
    entries.push({ name, typecode, offset: archiveStart + offset, storedBytes, unpackedBytes, compressed: compressed === 1 });
    cursor += length;
  }
  return { pythonVersion, pythonLibrary, archiveOffset: archiveStart, archiveEnd, tocBytes,
    trailingBytes: source.size - archiveEnd, entries, executed: false };
}

export async function extractPyInstallerEntry(source: ByteSource, name: string, signal?: AbortSignal): Promise<{ data: ByteSource; entry: PyInstallerEntry }> {
  const report = await inspectPyInstaller(source, signal);
  const entry = report.entries.find((item) => item.name === name);
  if (!entry) throw new Error(`PyInstaller entry ${name} is not present`);
  if (entry.storedBytes > MAX_EXTRACT_BYTES || entry.unpackedBytes > MAX_EXTRACT_BYTES) throw new Error("PyInstaller entry exceeds the 64 MiB extraction budget");
  const packed = new SliceSource(source, entry.offset, entry.storedBytes);
  if (!entry.compressed) {
    if (entry.storedBytes !== entry.unpackedBytes) throw new Error("PyInstaller uncompressed entry has mismatched sizes");
    return { data: packed, entry };
  }
  const result = await inflate(packed, "zlib", { maxOutputBytes: MAX_EXTRACT_BYTES, signal });
  if (result.error || result.stoppedEarly || result.bytes.length !== entry.unpackedBytes) throw new Error("PyInstaller entry failed bounded zlib decompression or size validation");
  return { data: new MemorySource(result.bytes), entry };
}

export async function extractPyInstallerPyc(source: ByteSource, name: string, signal?: AbortSignal): Promise<{ data: ByteSource; pythonVersion: string; marshalBytes: number }> {
  const report = await inspectPyInstaller(source, signal);
  const entry = report.entries.find((item) => item.name === name);
  if (!entry || !["s", "m", "M"].includes(entry.typecode)) throw new Error("PyInstaller entry is not a marshaled Python script or module");
  const magic = magicForPythonVersion(report.pythonVersion);
  const { data } = await extractPyInstallerEntry(source, name, signal);
  const marshal = await data.read(0, data.size);
  if (marshal.length !== data.size || (marshal[0] & 0x7f) !== 0x63) throw new Error("PyInstaller entry does not contain a complete marshaled code object");
  const pyc = new Uint8Array(16 + marshal.length);
  pyc.set(magic);
  pyc.set(marshal, 16);
  return { data: new MemorySource(pyc), pythonVersion: report.pythonVersion, marshalBytes: marshal.length };
}
