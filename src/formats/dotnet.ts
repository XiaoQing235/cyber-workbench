import type { ByteSource } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";

export const MAX_DOTNET_BYTES = 16 * 1024 * 1024;

const TABLE_NAMES = ["Module", "TypeRef", "TypeDef", "FieldPtr", "Field", "MethodPtr", "MethodDef", "ParamPtr", "Param", "InterfaceImpl", "MemberRef", "Constant", "CustomAttribute", "FieldMarshal", "DeclSecurity", "ClassLayout", "FieldLayout", "StandAloneSig", "EventMap", "EventPtr", "Event", "PropertyMap", "PropertyPtr", "Property", "MethodSemantics", "MethodImpl", "ModuleRef", "TypeSpec", "ImplMap", "FieldRVA", "ENCLog", "ENCMap", "Assembly", "AssemblyProcessor", "AssemblyOS", "AssemblyRef", "AssemblyRefProcessor", "AssemblyRefOS", "File", "ExportedType", "ManifestResource", "NestedClass", "GenericParam", "MethodSpec", "GenericParamConstraint"];

export interface DotNetTables {
  stream: "#~" | "#-";
  version: string;
  heapSizes: number;
  validMask: string;
  sortedMask: string;
  rows: { id: number; name: string; count: number }[];
  moduleName: string | null;
  rowsDecoded: false;
}

export interface DotNetReport {
  format: "PE/CLR";
  machine: number;
  pe32Plus: boolean;
  runtime: { major: number; minor: number };
  metadataVersion: string;
  entryPointToken: string;
  streams: { name: string; size: number; offset: number }[];
  metadataOffset: number;
  tables: DotNetTables;
  assemblyExecuted: false;
}

/** Validate PE sections, CLR directory and the BSJB metadata stream inventory without executing code. */
export async function inspectDotNet(source: ByteSource, signal?: AbortSignal): Promise<DotNetReport> {
  if (!Number.isSafeInteger(source.size) || source.size < 512 || source.size > MAX_DOTNET_BYTES) throw new Error(".NET assembly is outside its 16 MiB budget");
  if (signal?.aborted) throw signal.reason;
  const bytes = await readAll(source, MAX_DOTNET_BYTES);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const ensure = (start: number, length: number, label: string) => {
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(length) || start < 0 || length < 0 || start > bytes.length - length) throw new Error(`.NET ${label} exceeds the file`);
  };
  if (view.getUint16(0, true) !== 0x5a4d) throw new Error("Not a PE assembly");
  const pe = view.getUint32(0x3c, true);
  ensure(pe, 24, "PE header");
  if (view.getUint32(pe, true) !== 0x4550) throw new Error("Invalid .NET PE signature");
  const machine = view.getUint16(pe + 4, true);
  const sectionCount = view.getUint16(pe + 6, true);
  const optionalSize = view.getUint16(pe + 20, true);
  if (sectionCount < 1 || sectionCount > 96) throw new Error(".NET PE section count exceeds the budget");
  const optional = pe + 24;
  ensure(optional, optionalSize + sectionCount * 40, "optional header and sections");
  const magic = view.getUint16(optional, true);
  if (magic !== 0x10b && magic !== 0x20b) throw new Error("Unsupported .NET PE optional header");
  const wide = magic === 0x20b;
  const directory = optional + (wide ? 112 : 96);
  if (directory + 15 * 8 > optional + optionalSize || view.getUint32(optional + (wide ? 108 : 92), true) < 15) {
    throw new Error(".NET PE lacks a CLR data directory");
  }
  const sections: { virtual: number; extent: number; raw: number; size: number }[] = [];
  for (let index = 0; index < sectionCount; index++) {
    const section = optional + optionalSize + index * 40;
    const virtualSize = view.getUint32(section + 8, true);
    const virtualAddress = view.getUint32(section + 12, true);
    const size = view.getUint32(section + 16, true);
    const raw = view.getUint32(section + 20, true);
    if (size) ensure(raw, size, "section data");
    sections.push({ virtual: virtualAddress, extent: Math.max(virtualSize, size), raw, size });
  }
  const locate = (rva: number, size: number): number => {
    const section = sections.find((item) => rva >= item.virtual && rva - item.virtual <= item.size - size);
    if (!section) throw new Error(".NET RVA is outside file-backed section data");
    const offset = section.raw + rva - section.virtual;
    ensure(offset, size, "RVA");
    return offset;
  };
  const clrDirectory = directory + 14 * 8;
  const clrRva = view.getUint32(clrDirectory, true);
  const clrSize = view.getUint32(clrDirectory + 4, true);
  if (clrRva === 0 || clrSize < 72 || clrSize > 4096) throw new Error(".NET CLR directory is missing or invalid");
  const clr = locate(clrRva, clrSize);
  if (view.getUint32(clr, true) < 72) throw new Error(".NET CLR header is truncated");
  const metadataRva = view.getUint32(clr + 8, true);
  const metadataSize = view.getUint32(clr + 12, true);
  if (metadataSize < 24 || metadataSize > 8 * 1024 * 1024) throw new Error(".NET metadata extent is invalid");
  const metadata = locate(metadataRva, metadataSize);
  if (view.getUint32(metadata, true) !== 0x424a5342) throw new Error(".NET metadata lacks BSJB signature");
  const versionLength = view.getUint32(metadata + 12, true);
  if (versionLength < 1 || versionLength > 256 || versionLength > metadataSize - 16) throw new Error(".NET metadata version is invalid");
  const version = bytes.subarray(metadata + 16, metadata + 16 + versionLength);
  const terminator = version.indexOf(0);
  if (terminator < 1) throw new Error(".NET metadata version is unterminated");
  const metadataVersion = new TextDecoder("utf-8", { fatal: true }).decode(version.subarray(0, terminator));
  let position = metadata + 16 + ((versionLength + 3) & ~3);
  if (position + 4 > metadata + metadataSize) throw new Error(".NET metadata stream header is truncated");
  const count = view.getUint16(position + 2, true);
  position += 4;
  if (count < 1 || count > 16) throw new Error(".NET stream count exceeds the budget");
  const streams: DotNetReport["streams"] = [];
  for (let index = 0; index < count; index++) {
    if (signal?.aborted) throw signal.reason;
    if (position + 9 > metadata + metadataSize) throw new Error(".NET stream directory is truncated");
    const offset = view.getUint32(position, true);
    const size = view.getUint32(position + 4, true);
    const nameStart = position + 8;
    let end = nameStart;
    while (end < Math.min(nameStart + 32, metadata + metadataSize) && bytes[end] !== 0) end++;
    if (end === nameStart || end === Math.min(nameStart + 32, metadata + metadataSize)) throw new Error(".NET stream name is unterminated");
    const name = new TextDecoder("ascii", { fatal: true }).decode(bytes.subarray(nameStart, end));
    if (!/^#(?:~|-|[A-Za-z0-9]+)$/.test(name) || streams.some((stream) => stream.name === name) || offset > metadataSize - size) {
      throw new Error(".NET stream name or extent is invalid");
    }
    streams.push({ name, size, offset });
    position = nameStart + ((end - nameStart + 1 + 3) & ~3);
  }
  const directoryBytes = position - metadata;
  if (streams.some((stream) => stream.offset < directoryBytes)) throw new Error(".NET stream overlaps metadata directory");
  const ranges = streams.map((stream) => ({ start: stream.offset, end: stream.offset + stream.size })).sort((first, second) => first.start - second.start);
  if (ranges.some((range, index) => index > 0 && range.start < ranges[index - 1].end)) throw new Error(".NET metadata streams overlap");
  const tablesStream = streams.find((stream) => stream.name === "#~" || stream.name === "#-");
  if (!tablesStream) throw new Error(".NET metadata tables stream is missing");
  if (tablesStream.size < 24) throw new Error(".NET metadata tables header is truncated");
  const tableStart = metadata + tablesStream.offset;
  const tableEnd = tableStart + tablesStream.size;
  const valid = view.getBigUint64(tableStart + 8, true);
  const sorted = view.getBigUint64(tableStart + 16, true);
  if ((sorted & ~valid) !== 0n) throw new Error(".NET sorted table mask contains absent tables");
  if (view.getUint32(tableStart, true) !== 0 || view.getUint8(tableStart + 7) !== 1) {
    throw new Error(".NET metadata tables header is invalid");
  }
  const rows: DotNetTables["rows"] = [];
  let rowPosition = tableStart + 24;
  let rowTotal = 0;
  for (let id = 0; id < 64; id++) {
    if ((valid & (1n << BigInt(id))) === 0n) continue;
    if (signal?.aborted) throw signal.reason;
    if (rowPosition + 4 > tableEnd) throw new Error(".NET table row-count directory is truncated");
    const count = view.getUint32(rowPosition, true);
    rowTotal += count;
    if (rowTotal > 1_000_000) throw new Error(".NET metadata table row budget exceeded");
    rows.push({ id, name: TABLE_NAMES[id] ?? `Table${id}`, count });
    rowPosition += 4;
  }
  let moduleName: string | null = null;
  const moduleCount = rows.find((row) => row.id === 0)?.count ?? 0;
  if (moduleCount > 1) throw new Error(".NET Module table has more than one row");
  if (moduleCount === 1) {
    const stringWidth = (view.getUint8(tableStart + 6) & 1) ? 4 : 2;
    const moduleRowBytes = 2 + stringWidth + ((view.getUint8(tableStart + 6) & 2) ? 4 : 2) * 3;
    if (rowPosition + moduleRowBytes > tableEnd) throw new Error(".NET Module row exceeds the table stream");
    const nameOffset = stringWidth === 4 ? view.getUint32(rowPosition + 2, true) : view.getUint16(rowPosition + 2, true);
    const strings = streams.find((stream) => stream.name === "#Strings");
    if (!strings || nameOffset < 1 || nameOffset >= strings.size) throw new Error(".NET Module name offset is outside #Strings");
    const bytes = new Uint8Array(view.buffer, view.byteOffset + metadata + strings.offset + nameOffset, strings.size - nameOffset);
    const end = bytes.indexOf(0);
    if (end < 1 || end > 4096) throw new Error(".NET Module name is unterminated or exceeds the budget");
    moduleName = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, end));
  }
  const tables: DotNetTables = { stream: tablesStream.name as "#~" | "#-",
    version: `${view.getUint8(tableStart + 4)}.${view.getUint8(tableStart + 5)}`,
    heapSizes: view.getUint8(tableStart + 6), validMask: `0x${valid.toString(16).padStart(16, "0")}`,
    sortedMask: `0x${sorted.toString(16).padStart(16, "0")}`, rows, moduleName, rowsDecoded: false };
  return { format: "PE/CLR", machine, pe32Plus: wide, runtime: { major: view.getUint16(clr + 4, true), minor: view.getUint16(clr + 6, true) },
    metadataVersion, entryPointToken: `0x${view.getUint32(clr + 20, true).toString(16).padStart(8, "0")}`, streams, metadataOffset: metadata, tables, assemblyExecuted: false };
}

/** Select one null-terminated UTF-8 string from the validated #Strings heap by relative offset. */
export async function extractDotNetString(source: ByteSource, relativeOffset: number, signal?: AbortSignal): Promise<string> {
  if (!Number.isSafeInteger(relativeOffset) || relativeOffset < 1) throw new Error(".NET string heap offset must be a positive integer");
  const report = await inspectDotNet(source, signal);
  const heap = report.streams.find((stream) => stream.name === "#Strings");
  if (!heap || relativeOffset >= heap.size) throw new Error(".NET string heap offset is not present");
  const remaining = Math.min(4096, heap.size - relativeOffset);
  const bytes = await source.read(report.metadataOffset + heap.offset + relativeOffset, remaining);
  const end = bytes.indexOf(0);
  if (bytes.length !== remaining || end < 0) throw new Error(".NET string heap entry is truncated or exceeds 4096 bytes");
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, end));
}
