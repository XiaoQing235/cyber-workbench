import type { ByteSource } from "../core/bytes/ByteSource";
import { SliceSource } from "../core/bytes/sources";

export const MAX_IL2CPP_BYTES = 512 * 1024 * 1024;
const MAX_DIRECTORY_BYTES = 256;

export interface Il2CppReport {
  format: "global-metadata.dat";
  version: number;
  fileBytes: number;
  sections: { index: number; offset: number; bytes: number }[];
  stringLiterals: { offset: number; bytes: number };
  stringLiteralData: { offset: number; bytes: number };
  strings: { offset: number; bytes: number };
  metadataExecuted: false;
  dataDecoded: false;
}

export interface Il2CppLiteral {
  index: number;
  offset: number;
  bytes: number;
  text: string;
}

/** Header inventory for unmodified little-endian Unity IL2CPP global-metadata.dat v24–v31. */
export async function inspectIl2Cpp(source: ByteSource, signal?: AbortSignal): Promise<Il2CppReport> {
  if (!Number.isSafeInteger(source.size) || source.size < MAX_DIRECTORY_BYTES || source.size > MAX_IL2CPP_BYTES) {
    throw new Error("IL2CPP metadata is truncated or exceeds its size budget");
  }
  if (signal?.aborted) throw signal.reason;
  const header = await source.read(0, MAX_DIRECTORY_BYTES);
  if (header.length !== MAX_DIRECTORY_BYTES) throw new Error("IL2CPP metadata directory is truncated");
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  if (view.getUint32(0, true) !== 0xfab11baf) throw new Error("Not a standard IL2CPP metadata file");
  const version = view.getUint32(4, true);
  if (version < 24 || version > 31) throw new Error(`IL2CPP metadata version ${version} is unsupported`);
  const sections: Il2CppReport["sections"] = [];
  for (let index = 0; index < (MAX_DIRECTORY_BYTES - 8) / 8; index++) {
    if (signal?.aborted) throw signal.reason;
    const offset = view.getUint32(8 + index * 8, true);
    const bytes = view.getUint32(12 + index * 8, true);
    if ((offset === 0) !== (bytes === 0) || (bytes !== 0 && (offset < MAX_DIRECTORY_BYTES || offset > source.size - bytes))) {
      throw new Error(`IL2CPP section ${index} exceeds the file or overlaps the directory`);
    }
    sections.push({ index, offset, bytes });
  }
  if (sections[0].bytes === 0 || sections[1].bytes === 0 || sections[2].bytes === 0) {
    throw new Error("IL2CPP string-related metadata sections are missing");
  }
  const occupied = sections.filter((entry) => entry.bytes > 0).sort((a, b) => a.offset - b.offset);
  if (occupied.some((entry, index) => index > 0 && occupied[index - 1].offset + occupied[index - 1].bytes > entry.offset)) {
    throw new Error("IL2CPP metadata sections overlap");
  }
  return { format: "global-metadata.dat", version, fileBytes: source.size, sections,
    stringLiterals: { offset: sections[0].offset, bytes: sections[0].bytes },
    stringLiteralData: { offset: sections[1].offset, bytes: sections[1].bytes },
    strings: { offset: sections[2].offset, bytes: sections[2].bytes }, metadataExecuted: false, dataDecoded: false };
}

/** Decode only bounded UTF-8 literal entries; malformed/opaque binary payloads are not coerced to text. */
export async function readIl2CppStringLiterals(source: ByteSource, maxLiterals: number, signal?: AbortSignal): Promise<{
  total: number; literals: Il2CppLiteral[]; truncated: boolean;
}> {
  if (!Number.isSafeInteger(maxLiterals) || maxLiterals < 1 || maxLiterals > 1024) throw new Error("IL2CPP literal limit is outside 1–1,024");
  const report = await inspectIl2Cpp(source, signal);
  const entries = report.stringLiterals;
  const data = report.stringLiteralData;
  if (entries.bytes % 8 !== 0 || entries.bytes / 8 > 100_000 || data.bytes > 8 * 1024 * 1024) {
    throw new Error("IL2CPP string-literal table exceeds its bounded layout");
  }
  const total = entries.bytes / 8;
  const count = Math.min(total, maxLiterals);
  const directory = await source.read(entries.offset, count * 8);
  if (directory.length !== count * 8) throw new Error("IL2CPP string-literal directory is truncated");
  const view = new DataView(directory.buffer, directory.byteOffset, directory.byteLength);
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const literals: Il2CppLiteral[] = [];
  for (let index = 0; index < count; index++) {
    if (signal?.aborted) throw signal.reason;
    const bytes = view.getUint32(index * 8, true);
    const relative = view.getUint32(index * 8 + 4, true);
    if (bytes > 4096 || relative > data.bytes - bytes) throw new Error(`IL2CPP string literal ${index} exceeds its data section`);
    const value = await source.read(data.offset + relative, bytes);
    if (value.length !== bytes) throw new Error(`IL2CPP string literal ${index} is truncated`);
    literals.push({ index, offset: data.offset + relative, bytes, text: decoder.decode(value) });
  }
  return { total, literals, truncated: total > count };
}

/** Select a literal's original bytes even when they are not valid UTF-8 text. */
export async function extractIl2CppLiteral(source: ByteSource, index: number, signal?: AbortSignal): Promise<ByteSource> {
  if (!Number.isSafeInteger(index) || index < 0 || index >= 100_000) throw new Error("IL2CPP literal index exceeds its budget");
  const report = await inspectIl2Cpp(source, signal);
  if (report.stringLiterals.bytes % 8 !== 0 || index >= report.stringLiterals.bytes / 8) throw new Error("IL2CPP literal index is outside the table");
  const entry = await source.read(report.stringLiterals.offset + index * 8, 8);
  if (entry.length !== 8) throw new Error("IL2CPP literal descriptor is truncated");
  const view = new DataView(entry.buffer, entry.byteOffset, 8);
  const bytes = view.getUint32(0, true);
  const relative = view.getUint32(4, true);
  if (bytes > 64 * 1024 * 1024 || relative > report.stringLiteralData.bytes - bytes) throw new Error("IL2CPP literal bytes exceed their section or budget");
  return new SliceSource(source, report.stringLiteralData.offset + relative, bytes);
}
