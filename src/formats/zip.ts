import type { Finding } from "../core/analysis/finding";
import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { scanSignatures } from "./signatures";

const LOCAL_HEADER = 0x04034b50;
const CENTRAL_HEADER = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY = 0x06054b50;
const MAX_EOCD_SEARCH = 22 + 0xffff;
const MAX_ENTRIES = 10_000;
const MAX_32 = 0xffffffff;
const MAX_SCAN_BYTES = 1024 * 1024 * 1024;

export interface RecoverableZipRecord {
  offset: number;
  length: number;
  name: string;
  versionNeeded: number;
  flags: number;
  method: number;
  modifiedTime: number;
  modifiedDate: number;
  crc32: number;
  compressedSize: number;
  uncompressedSize: number;
  nameBytes: Bytes;
  extraBytes: Bytes;
}

export interface LocalZipRecordSummary {
  offset: number;
  length: number;
  name: string;
  method: number;
  compressedSize: number;
  uncompressedSize: number;
  encryption: "none" | "ZipCrypto";
}

export interface ZipForensicEntry {
  index: number;
  name: string;
  method: number;
  methodName: string;
  versionNeeded: number;
  modifiedTime: number;
  flags: number;
  encryption: "none" | "ZipCrypto" | "AES";
  crc32: string;
  compressedSize: number;
  uncompressedSize: number;
  centralHeaderOffset: number;
  localHeaderOffset: number;
  dataOffset: number | null;
  dataEnd: number | null;
  passwordCheckByte: number | null;
  aes: null | {
    vendorVersion: number;
    vendorId: string;
    strength: 1 | 2 | 3;
    keyBits: 128 | 192 | 256;
    actualMethod: number;
    saltLength: 8 | 12 | 16;
  };
  consistent: boolean;
  issues: string[];
}

export interface ZipForensicReport {
  format: "ZIP";
  size: number;
  entries: ZipForensicEntry[];
  eocd: null | {
    offset: number;
    disk: number;
    centralDisk: number;
    entriesOnDisk: number;
    entriesTotal: number;
    centralSize: number;
    centralOffset: number;
    comment: string;
  };
  localRecords: LocalZipRecordSummary[];
  findings: Finding[];
  limited: boolean;
}

function methodName(method: number): string {
  return ({ 0: "stored", 8: "deflate", 9: "deflate64", 12: "bzip2", 14: "lzma", 93: "zstd", 99: "AES marker" } as Record<number, string>)[method] ?? `method ${method}`;
}

function view(bytes: Bytes): DataView {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

async function exact(source: ByteSource, offset: number, length: number): Promise<Bytes | null> {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > source.size) return null;
  const bytes = await source.read(offset, length);
  return bytes.length === length ? bytes : null;
}

function decodeName(bytes: Bytes, utf8: boolean): string {
  try {
    return new TextDecoder(utf8 ? "utf-8" : "windows-1252", { fatal: utf8 }).decode(bytes);
  } catch {
    return new TextDecoder("utf-8").decode(bytes);
  }
}

function parseAesExtra(extra: Bytes): ZipForensicEntry["aes"] {
  const data = view(extra);
  for (let at = 0; at + 4 <= extra.length; ) {
    const id = data.getUint16(at, true);
    const length = data.getUint16(at + 2, true);
    if (at + 4 + length > extra.length) return null;
    if (id === 0x9901 && length >= 7) {
      const strength = extra[at + 8];
      if (strength < 1 || strength > 3) return null;
      return {
        vendorVersion: data.getUint16(at + 4, true),
        vendorId: String.fromCharCode(extra[at + 6], extra[at + 7]),
        strength: strength as 1 | 2 | 3,
        keyBits: ({ 1: 128, 2: 192, 3: 256 } as const)[strength as 1 | 2 | 3],
        actualMethod: data.getUint16(at + 9, true),
        saltLength: ({ 1: 8, 2: 12, 3: 16 } as const)[strength as 1 | 2 | 3],
      };
    }
    at += 4 + length;
  }
  return null;
}

export async function discoverRecoverableZipRecords(source: ByteSource, signal?: AbortSignal): Promise<{ records: RecoverableZipRecord[]; limited: boolean }> {
  const scanEnd = Math.min(source.size, MAX_SCAN_BYTES);
  const hits = await scanSignatures(source, { start: 0, end: scanEnd, maxHits: MAX_ENTRIES + 1, signal });
  const records: RecoverableZipRecord[] = [];
  let coveredUntil = -1;
  for (const hit of hits) {
    if (hit.signature.magic[2] !== 0x03 || hit.signature.magic[3] !== 0x04 || hit.offset < coveredUntil) continue;
    const bytes = await exact(source, hit.offset, 30);
    if (!bytes || view(bytes).getUint32(0, true) !== LOCAL_HEADER) continue;
    const header = view(bytes);
    const flags = header.getUint16(6, true);
    // A data descriptor means the local header does not define a trustworthy end.
    if (flags & 0x0008) continue;
    const compressedSize = header.getUint32(18, true);
    const nameLength = header.getUint16(26, true);
    const extraLength = header.getUint16(28, true);
    const variable = await exact(source, hit.offset + 30, nameLength + extraLength);
    if (!variable) continue;
    const length = 30 + nameLength + extraLength + compressedSize;
    if (hit.offset + length > source.size) continue;
    const nameBytes = variable.slice(0, nameLength);
    const extraBytes = variable.slice(nameLength);
    records.push({
      offset: hit.offset,
      length,
      name: decodeName(nameBytes, (flags & 0x0800) !== 0),
      versionNeeded: header.getUint16(4, true),
      flags,
      method: header.getUint16(8, true),
      modifiedTime: header.getUint16(10, true),
      modifiedDate: header.getUint16(12, true),
      crc32: header.getUint32(14, true),
      compressedSize,
      uncompressedSize: header.getUint32(22, true),
      nameBytes,
      extraBytes,
    });
    coveredUntil = hit.offset + length;
    if (records.length >= MAX_ENTRIES) break;
  }
  return { records, limited: source.size > MAX_SCAN_BYTES || hits.length > MAX_ENTRIES };
}

function summarizeLocalRecords(records: readonly RecoverableZipRecord[]): LocalZipRecordSummary[] {
  return records.map((record) => ({
    offset: record.offset,
    length: record.length,
    name: record.name,
    method: record.method,
    compressedSize: record.compressedSize,
    uncompressedSize: record.uncompressedSize,
    encryption: record.flags & 1 ? "ZipCrypto" : "none",
  }));
}

function mismatch(findings: Finding[], entry: ZipForensicEntry, field: string, central: number | string, local: number | string, offset: number, length: number): void {
  entry.consistent = false;
  entry.issues.push(`${field}: central ${central}, local ${local}`);
  findings.push({
    id: `zip.mismatch.${entry.index}.${field}`,
    ruleId: "zip.local-central-consistency",
    severity: "strong",
    message: `${entry.name}: ${field} differs between the central directory (${central}) and local header (${local})`,
    span: { offset, length },
    evidence: [{ kind: "consistency", tier: "strong", detail: `Local value is ${local}`, span: { offset: entry.localHeaderOffset, length: 30 } }],
  });
}

export async function inspectZip(source: ByteSource, signal?: AbortSignal): Promise<ZipForensicReport> {
  const findings: Finding[] = [];
  const entries: ZipForensicEntry[] = [];
  const tailLength = Math.min(source.size, MAX_EOCD_SEARCH);
  const tailOffset = source.size - tailLength;
  const tail = await exact(source, tailOffset, tailLength);
  let eocdAt = -1;
  if (tail) {
    const data = view(tail);
    for (let at = tail.length - 22; at >= 0; at--) {
      if (data.getUint32(at, true) !== END_OF_CENTRAL_DIRECTORY) continue;
      const commentLength = data.getUint16(at + 20, true);
      if (at + 22 + commentLength <= tail.length) {
        eocdAt = tailOffset + at;
        break;
      }
    }
  }
  if (eocdAt < 0) {
    const discovered = await discoverRecoverableZipRecords(source, signal);
    findings.push({
      id: "zip.eocd.missing",
      ruleId: "zip.eocd",
      severity: "strong",
      message: discovered.records.length === 0
        ? "No valid ZIP end-of-central-directory record was found"
        : `No valid ZIP end record was found, but ${discovered.records.length} recoverable local record(s) remain`,
      suggestion: discovered.records.length === 0 ? undefined : { operationId: "archive.zip.rebuild", label: "Rebuild the ZIP directory" },
    });
    return { format: "ZIP", size: source.size, entries, eocd: null, localRecords: summarizeLocalRecords(discovered.records), findings, limited: discovered.limited };
  }

  const endBytes = (await exact(source, eocdAt, 22))!;
  const end = view(endBytes);
  const commentLength = end.getUint16(20, true);
  const commentBytes = (await exact(source, eocdAt + 22, commentLength))!;
  const eocd = {
    offset: eocdAt,
    disk: end.getUint16(4, true),
    centralDisk: end.getUint16(6, true),
    entriesOnDisk: end.getUint16(8, true),
    entriesTotal: end.getUint16(10, true),
    centralSize: end.getUint32(12, true),
    centralOffset: end.getUint32(16, true),
    comment: decodeName(commentBytes, true),
  };
  const archiveEnd = eocdAt + 22 + commentLength;
  if (archiveEnd < source.size) {
    findings.push({
      id: "zip.trailing",
      ruleId: "zip.extent",
      severity: "strong",
      message: `${source.size - archiveEnd} byte(s) follow the ZIP end record`,
      span: { offset: archiveEnd, length: source.size - archiveEnd },
      suggestion: { operationId: "bytes.slice", params: { offset: archiveEnd, length: -1 }, label: "Extract trailing data" },
    });
  }
  if (eocd.disk !== 0 || eocd.centralDisk !== 0 || eocd.entriesOnDisk !== eocd.entriesTotal) {
    findings.push({ id: "zip.multidisk", ruleId: "zip.eocd", severity: "medium", message: "This is a split or multi-disk ZIP archive", span: { offset: eocdAt + 4, length: 8 } });
  }
  if (eocd.entriesTotal === 0xffff || eocd.centralOffset === MAX_32 || eocd.centralSize === MAX_32) {
    findings.push({ id: "zip.zip64", ruleId: "zip.eocd", severity: "medium", message: "ZIP64 metadata is required; ZIP64 entry resolution is not available yet", span: { offset: eocdAt, length: 22 } });
    return { format: "ZIP", size: source.size, entries, eocd, localRecords: [], findings, limited: false };
  }
  if (eocd.centralOffset + eocd.centralSize > eocdAt) {
    findings.push({ id: "zip.central.bounds", ruleId: "zip.central-directory", severity: "strong", message: "The central directory extends into or beyond the end record", span: { offset: eocdAt + 12, length: 8 } });
  }

  const count = Math.min(eocd.entriesTotal, MAX_ENTRIES);
  let centralAt = eocd.centralOffset;
  for (let index = 0; index < count; index++) {
    const fixed = await exact(source, centralAt, 46);
    if (!fixed || view(fixed).getUint32(0, true) !== CENTRAL_HEADER) {
      findings.push({ id: `zip.central.invalid.${index}`, ruleId: "zip.central-directory", severity: "strong", message: `Central directory entry ${index} is missing or truncated`, span: { offset: Math.min(centralAt, source.size), length: Math.min(46, Math.max(0, source.size - centralAt)) } });
      break;
    }
    const central = view(fixed);
    const flags = central.getUint16(8, true);
    const method = central.getUint16(10, true);
    const crc = central.getUint32(16, true);
    const compressedSize = central.getUint32(20, true);
    const uncompressedSize = central.getUint32(24, true);
    const nameLength = central.getUint16(28, true);
    const extraLength = central.getUint16(30, true);
    const commentLengthEntry = central.getUint16(32, true);
    const localHeaderOffset = central.getUint32(42, true);
    const variable = await exact(source, centralAt + 46, nameLength + extraLength + commentLengthEntry);
    if (!variable) {
      findings.push({ id: `zip.central.truncated.${index}`, ruleId: "zip.central-directory", severity: "strong", message: `Central directory entry ${index} has truncated variable fields`, span: { offset: centralAt, length: Math.min(46, source.size - centralAt) } });
      break;
    }
    const nameBytes = variable.slice(0, nameLength);
    const extra = variable.slice(nameLength, nameLength + extraLength);
    const name = decodeName(nameBytes, (flags & 0x0800) !== 0);
    const aes = parseAesExtra(extra);
    const entry: ZipForensicEntry = {
      index,
      name,
      method,
      methodName: methodName(method),
      versionNeeded: central.getUint16(6, true),
      modifiedTime: central.getUint16(12, true),
      flags,
      encryption: aes || method === 99 ? "AES" : flags & 1 ? "ZipCrypto" : "none",
      crc32: `0x${crc.toString(16).padStart(8, "0")}`,
      compressedSize,
      uncompressedSize,
      centralHeaderOffset: centralAt,
      localHeaderOffset,
      dataOffset: null,
      dataEnd: null,
      passwordCheckByte: null,
      aes,
      consistent: true,
      issues: [],
    };
    entries.push(entry);
    if (entry.encryption !== "none") {
      findings.push({ id: `zip.encryption.${index}`, ruleId: "zip.encryption", severity: "medium", message: `${name} is encrypted with ${entry.encryption}`, span: { offset: centralAt + 8, length: 4 } });
    }

    const localBytes = await exact(source, localHeaderOffset, 30);
    if (!localBytes || view(localBytes).getUint32(0, true) !== LOCAL_HEADER) {
      entry.consistent = false;
      entry.issues.push("local header missing or invalid");
      findings.push({ id: `zip.local.invalid.${index}`, ruleId: "zip.local-header", severity: "strong", message: `${name}: local header is missing or invalid at offset ${localHeaderOffset}`, span: { offset: Math.min(localHeaderOffset, source.size), length: Math.min(30, Math.max(0, source.size - localHeaderOffset)) } });
    } else {
      const local = view(localBytes);
      const localFlags = local.getUint16(6, true);
      const localMethod = local.getUint16(8, true);
      const localCrc = local.getUint32(14, true);
      const localCompressed = local.getUint32(18, true);
      const localSize = local.getUint32(22, true);
      const localNameLength = local.getUint16(26, true);
      const localExtraLength = local.getUint16(28, true);
      const localNameBytes = await exact(source, localHeaderOffset + 30, localNameLength);
      const localName = localNameBytes ? decodeName(localNameBytes, (localFlags & 0x0800) !== 0) : "<truncated>";
      entry.dataOffset = localHeaderOffset + 30 + localNameLength + localExtraLength;
      entry.dataEnd = entry.dataOffset + compressedSize;
      entry.passwordCheckByte = flags & 0x0008 ? local.getUint16(10, true) >>> 8 : crc >>> 24;
      if (entry.dataEnd > source.size) {
        entry.consistent = false;
        entry.issues.push("compressed data extends past the archive");
        findings.push({ id: `zip.data.bounds.${index}`, ruleId: "zip.entry-bounds", severity: "strong", message: `${name}: compressed data extends past the end of the input`, span: { offset: localHeaderOffset, length: Math.min(30, source.size - localHeaderOffset) } });
      }
      if (localName !== name) mismatch(findings, entry, "name", JSON.stringify(name), JSON.stringify(localName), centralAt + 46, nameLength);
      if (localFlags !== flags) mismatch(findings, entry, "flags", flags, localFlags, centralAt + 8, 2);
      if (localMethod !== method) mismatch(findings, entry, "method", method, localMethod, centralAt + 10, 2);
      if ((flags & 0x0008) === 0) {
        if (localCrc !== crc) mismatch(findings, entry, "CRC-32", entry.crc32, `0x${localCrc.toString(16).padStart(8, "0")}`, centralAt + 16, 4);
        if (localCompressed !== compressedSize) mismatch(findings, entry, "compressed size", compressedSize, localCompressed, centralAt + 20, 4);
        if (localSize !== uncompressedSize) mismatch(findings, entry, "uncompressed size", uncompressedSize, localSize, centralAt + 24, 4);
      }
    }
    centralAt += 46 + nameLength + extraLength + commentLengthEntry;
  }

  if (eocd.entriesTotal > MAX_ENTRIES) findings.push({ id: "zip.entries.limit", ruleId: "zip.resource-limit", severity: "medium", message: `Only the first ${MAX_ENTRIES} of ${eocd.entriesTotal} entries were inspected` });
  const names = new Map<string, ZipForensicEntry>();
  for (const entry of entries) {
    const previous = names.get(entry.name);
    if (previous) findings.push({ id: `zip.duplicate.${entry.index}`, ruleId: "zip.duplicate-name", severity: "strong", message: `Duplicate entry name ${JSON.stringify(entry.name)} (also entry ${previous.index})`, span: { offset: entry.centralHeaderOffset + 46, length: new TextEncoder().encode(entry.name).length } });
    else names.set(entry.name, entry);
  }
  const extents = entries.filter((entry): entry is ZipForensicEntry & { dataOffset: number; dataEnd: number } => entry.dataOffset !== null && entry.dataEnd !== null).sort((a, b) => a.dataOffset - b.dataOffset);
  for (let index = 1; index < extents.length; index++) {
    const previous = extents[index - 1];
    const current = extents[index];
    if (current.dataOffset < previous.dataEnd) findings.push({ id: `zip.overlap.${current.index}`, ruleId: "zip.overlapping-data", severity: "strong", message: `${current.name} overlaps compressed data belonging to ${previous.name}`, span: { offset: current.dataOffset, length: previous.dataEnd - current.dataOffset } });
  }
  return { format: "ZIP", size: source.size, entries, eocd, localRecords: [], findings, limited: eocd.entriesTotal > MAX_ENTRIES };
}