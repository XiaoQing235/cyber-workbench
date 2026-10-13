import type { ByteSource } from "../core/bytes/ByteSource";
import { MemorySource, SliceSource } from "../core/bytes/sources";

const BASE = 4096;
const MAX_CELL = 1024 * 1024;
const MAX_KEYS = 4096;
const MAX_BINS = 8192;
export const MAX_HIVE_BYTES = 512 * 1024 * 1024;
const NULL_OFFSET = 0xffffffff;
const WINDOWS_EPOCH = 116444736000000000n;

export interface RegistryKey {
  path: string;
  lastWrite: { filetime: string; utc: string } | null;
  subkeyCount: number;
  valueCount: number;
  cellOffset: number;
}

export interface RegistryValue {
  name: string;
  type: number;
  bytes: number;
  cellOffset: number;
  dataOffset: number | null;
  inline: boolean;
}

export interface RegistryReport {
  root: RegistryKey;
  selected: RegistryKey;
  children: RegistryKey[];
  values: RegistryValue[];
  hiveBytes: number;
  headerChecksumValid: true;
  primarySequence: number;
  secondarySequence: number;
  synchronized: boolean;
}

function time(ticks: bigint): RegistryKey["lastWrite"] {
  if (ticks === 0n) return null;
  const since = ticks - WINDOWS_EPOCH;
  let millis = since / 10000n;
  let remainder = since % 10000n;
  if (remainder < 0n) { millis--; remainder += 10000n; }
  const date = new Date(Number(millis));
  if (!Number.isFinite(date.getTime())) throw new Error("Registry FILETIME is outside the supported range");
  return { filetime: ticks.toString(), utc: date.toISOString().replace(/Z$/, `${String(remainder / 10n).padStart(3, "0")}Z`) };
}

/** Read allocated cells only. Offsets are relative to the first hbin, not the file start. */
export async function inspectRegistryHive(source: ByteSource, keyPath = "", signal?: AbortSignal): Promise<RegistryReport> {
  if (!Number.isSafeInteger(source.size) || source.size < BASE + 32 || source.size > MAX_HIVE_BYTES) {
    throw new Error("Registry hive is outside the supported size budget");
  }
  if (signal?.aborted) throw signal.reason;
  const header = await source.read(0, BASE);
  if (header.length !== BASE || String.fromCharCode(...header.subarray(0, 4)) !== "regf") throw new Error("Not a complete registry hive header");
  const h = new DataView(header.buffer, header.byteOffset, header.byteLength);
  const binsSize = h.getUint32(0x28, true);
  if (binsSize < 4096 || binsSize % 4096 !== 0 || binsSize > source.size - BASE) throw new Error("Registry hbin extent exceeds the file");
  let checksum = 0;
  for (let offset = 0; offset < 0x1fc; offset += 4) checksum ^= h.getUint32(offset, true);
  if ((checksum >>> 0) !== h.getUint32(0x1fc, true)) throw new Error("Registry header checksum mismatch");
  if (h.getUint32(0x1c, true) !== 0) throw new Error("Registry transaction-log header is not a standalone hive");
  const bins: { start: number; end: number }[] = [];
  for (let start = 0; start < binsSize;) {
    if (signal?.aborted) throw signal.reason;
    if (bins.length >= MAX_BINS) throw new Error("Registry hive exceeds the hbin count budget");
    const bin = await source.read(BASE + start, 32);
    if (bin.length !== 32) throw new Error("Registry hbin header is truncated");
    const view = new DataView(bin.buffer, bin.byteOffset, bin.byteLength);
    const size = view.getUint32(8, true);
    if (String.fromCharCode(...bin.subarray(0, 4)) !== "hbin" || view.getUint32(4, true) !== start ||
      size < 4096 || size % 4096 !== 0 || size > binsSize - start) throw new Error("Registry hbin header is invalid");
    bins.push({ start, end: start + size });
    start += size;
  }
  let inspected = 0;
  const cell = async (relative: number): Promise<Uint8Array> => {
    if (signal?.aborted) throw signal.reason;
    const bin = bins.find((item) => relative >= item.start + 32 && relative <= item.end - 8);
    if (relative === NULL_OFFSET || relative % 8 !== 0 || !bin) throw new Error("Registry cell offset is invalid");
    if (++inspected > MAX_KEYS * 3) throw new Error("Registry traversal exceeds its cell budget");
    const offset = BASE + relative;
    const sizeBytes = await source.read(offset, 4);
    if (sizeBytes.length !== 4) throw new Error("Registry cell header is truncated");
    const size = new DataView(sizeBytes.buffer, sizeBytes.byteOffset).getInt32(0, true);
    if (size > -8 || -size > MAX_CELL || -size % 8 !== 0 || -size > bin.end - relative) {
      throw new Error("Registry cell is unallocated or exceeds its extent");
    }
    const data = await source.read(offset + 4, -size - 4);
    if (data.length !== -size - 4) throw new Error("Registry cell payload is truncated");
    return data;
  };
  const checkedPayload = async (relative: number, length: number): Promise<number> => {
    if (length < 1 || length > MAX_CELL || relative === NULL_OFFSET || relative % 8 !== 0) throw new Error("Registry value data cell is invalid");
    const bin = bins.find((item) => relative >= item.start + 32 && relative <= item.end - 8);
    if (!bin) throw new Error("Registry value data cell is outside the hbin extent");
    const sizeBytes = await source.read(BASE + relative, 4);
    if (sizeBytes.length !== 4) throw new Error("Registry value data cell is truncated");
    const size = new DataView(sizeBytes.buffer, sizeBytes.byteOffset).getInt32(0, true);
    if (size > -8 || -size > MAX_CELL || -size % 8 !== 0 || -size > bin.end - relative || length > -size - 4) {
      throw new Error("Registry value data cell is truncated or invalid");
    }
    return BASE + relative + 4;
  };
  const name = (data: Uint8Array, start: number, length: number, ascii: boolean, empty = false): string => {
    if ((!empty && length === 0) || length > 2048 || length > data.length - start || (!ascii && length % 2 !== 0)) throw new Error("Registry key name exceeds its extent");
    const decoded = new TextDecoder(ascii ? "windows-1252" : "utf-16le", { fatal: true }).decode(data.subarray(start, start + length));
    if (/[\0-\x1f\x7f]/.test(decoded) || decoded.includes("\\")) throw new Error("Registry key name contains invalid characters");
    return decoded;
  };
  const key = async (relative: number, parent: string): Promise<{ entry: RegistryKey; list: number; volatileCount: number; valuesList: number }> => {
    const data = await cell(relative);
    if (data.length < 0x4c || data[0] !== 0x6e || data[1] !== 0x6b) throw new Error("Registry cell is not a complete nk key");
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const label = name(data, 0x4c, view.getUint16(0x48, true), (view.getUint16(2, true) & 0x20) !== 0);
    const path = parent ? `${parent}\\${label}` : label;
    return { entry: { path, lastWrite: time(view.getBigUint64(4, true)), subkeyCount: view.getUint32(0x14, true),
      valueCount: view.getUint32(0x24, true), cellOffset: relative }, list: view.getUint32(0x1c, true), volatileCount: view.getUint32(0x18, true), valuesList: view.getUint32(0x28, true) };
  };
  const offsets = async (relative: number, depth: number, seen: Set<number>): Promise<number[]> => {
    if (depth > 4 || seen.has(relative)) throw new Error("Registry subkey list is cyclic or too deeply nested");
    seen.add(relative);
    const data = await cell(relative);
    if (data.length < 4) throw new Error("Registry subkey list is truncated");
    const signature = String.fromCharCode(data[0], data[1]);
    if (!["li", "lf", "lh", "ri"].includes(signature)) throw new Error("Unsupported registry subkey-list type");
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const count = view.getUint16(2, true);
    const stride = signature === "lf" || signature === "lh" ? 8 : 4;
    if (count > MAX_KEYS || count * stride > data.length - 4) throw new Error("Registry subkey list exceeds its cell or key budget");
    const result: number[] = [];
    for (let index = 0; index < count; index++) {
      if (signal?.aborted) throw signal.reason;
      const entry = view.getUint32(4 + index * stride, true);
      if (signature === "ri") result.push(...await offsets(entry, depth + 1, seen));
      else result.push(entry);
      if (result.length > MAX_KEYS) throw new Error("Registry subkey count exceeds its budget");
    }
    return result;
  };
  const childrenOf = async (item: Awaited<ReturnType<typeof key>>): Promise<RegistryKey[]> => {
    if (item.volatileCount !== 0) throw new Error("Registry volatile subkeys cannot be reconstructed from this hive");
    if (item.entry.subkeyCount === 0) return [];
    if (item.entry.subkeyCount > MAX_KEYS) throw new Error("Registry subkey count exceeds its budget");
    const entries = await offsets(item.list, 0, new Set());
    if (entries.length !== item.entry.subkeyCount || new Set(entries).size !== entries.length) throw new Error("Registry subkey list disagrees with the key count");
    return Promise.all(entries.map(async (relative) => (await key(relative, item.entry.path)).entry));
  };
  const valuesOf = async (item: Awaited<ReturnType<typeof key>>): Promise<RegistryValue[]> => {
    const count = item.entry.valueCount;
    if (count > MAX_KEYS) throw new Error("Registry value count exceeds its budget");
    if (!count) return [];
    const list = await cell(item.valuesList);
    if (count * 4 > list.length) throw new Error("Registry value list is truncated");
    const view = new DataView(list.buffer, list.byteOffset, list.byteLength);
    const seen = new Set<number>();
    const values: RegistryValue[] = [];
    for (let index = 0; index < count; index++) {
      const relative = view.getUint32(index * 4, true);
      if (seen.has(relative)) throw new Error("Registry value list contains duplicate cells");
      seen.add(relative);
      const data = await cell(relative);
      if (data.length < 20 || data[0] !== 0x76 || data[1] !== 0x6b) throw new Error("Registry value is not a complete vk cell");
      const vk = new DataView(data.buffer, data.byteOffset, data.byteLength);
      const length = vk.getUint16(2, true);
      const rawLength = vk.getUint32(4, true);
      const inline = (rawLength & 0x80000000) !== 0;
      const bytes = rawLength & 0x7fffffff;
      if (bytes > MAX_CELL || (inline && bytes > 4)) throw new Error("Registry value data exceeds its budget");
      const dataOffset = inline || bytes === 0 ? null : vk.getUint32(8, true);
      if (dataOffset !== null) {
        await checkedPayload(dataOffset, bytes);
      }
      values.push({ name: name(data, 20, length, (vk.getUint16(16, true) & 1) !== 0, true),
        type: vk.getUint32(12, true), bytes, cellOffset: relative, dataOffset, inline });
    }
    return values;
  };
  const root = await key(h.getUint32(0x24, true), "");
  let selected = root;
  const parts = keyPath ? keyPath.split("\\") : [];
  if (parts.some((part) => !part || part === "." || part === "..") || parts.length > 32 || keyPath.length > 2048) throw new Error("Registry key path exceeds its budget");
  if (parts[0]?.toLowerCase() === root.entry.path.toLowerCase()) parts.shift();
  for (const part of parts) {
    const children = await childrenOf(selected);
    const match = children.find((entry) => entry.path.slice(entry.path.lastIndexOf("\\") + 1).toLowerCase() === part.toLowerCase());
    if (!match) throw new Error(`Registry key path component ${JSON.stringify(part)} was not found`);
    selected = await key(match.cellOffset, selected.entry.path);
  }
  return { root: root.entry, selected: selected.entry, children: await childrenOf(selected),
    values: await valuesOf(selected), hiveBytes: source.size, headerChecksumValid: true,
    primarySequence: h.getUint32(4, true), secondarySequence: h.getUint32(8, true),
    synchronized: h.getUint32(4, true) === h.getUint32(8, true) };
}

/** Return bytes only after the user explicitly selects a key and value. Large/big-data values are unsupported. */
export async function extractRegistryValue(source: ByteSource, keyPath: string, valueName: string,
  signal?: AbortSignal): Promise<ByteSource> {
  const report = await inspectRegistryHive(source, keyPath, signal);
  const value = report.values.find((entry) => entry.name.toLowerCase() === valueName.toLowerCase());
  if (!value) throw new Error("Registry value name is not present in the selected key");
  if (value.inline) {
    if (signal?.aborted) throw signal.reason;
    // Inline sizes below four occupy the last bytes of vk's four-byte data-offset field.
    const bytes = await source.read(BASE + value.cellOffset + 4 + 8 + 4 - value.bytes, value.bytes);
    if (bytes.length !== value.bytes) throw new Error("Registry inline value is truncated");
    return new MemorySource(bytes);
  }
  if (!value.bytes) return new MemorySource(new Uint8Array(0));
  if (value.dataOffset === null) throw new Error("Registry value has no allocated data cell");
  if (signal?.aborted) throw signal.reason;
  // The metadata walk already validated this allocated cell and its hbin boundary.
  const header = await source.read(BASE + value.dataOffset, 4);
  if (header.length !== 4) throw new Error("Registry value data cell changed or is truncated");
  const cellSize = new DataView(header.buffer, header.byteOffset).getInt32(0, true);
  if (cellSize > -8 || -cellSize > MAX_CELL || -cellSize % 8 !== 0 || value.bytes > -cellSize - 4) {
    throw new Error("Registry value data cell changed or is truncated");
  }
  return new SliceSource(source, BASE + value.dataOffset + 4, value.bytes);
}

export async function decodeRegistryValue(source: ByteSource, keyPath: string, valueName: string, signal?: AbortSignal): Promise<{
  name: string; type: "REG_SZ" | "REG_DWORD"; value: string | number; bytes: number;
}> {
  const report = await inspectRegistryHive(source, keyPath, signal);
  const value = report.values.find((entry) => entry.name.toLowerCase() === valueName.toLowerCase());
  if (!value) throw new Error("Registry value is not in the selected key");
  if (value.bytes > 4096) throw new Error("Registry value exceeds the decoded-value budget");
  if (value.type !== 1 && value.type !== 4) throw new Error("Registry decoder supports REG_SZ and REG_DWORD only");
  const selected = await extractRegistryValue(source, keyPath, valueName, signal);
  const bytes = await selected.read(0, selected.size);
  if (bytes.length !== value.bytes) throw new Error("Registry selected value bytes are truncated");
  if (value.type === 4) {
    if (bytes.length !== 4) throw new Error("REG_DWORD value must be four bytes");
    return { name: value.name, type: "REG_DWORD", value: new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true), bytes: 4 };
  }
  if (bytes.length < 2 || bytes.length % 2 !== 0 || bytes.at(-1) !== 0 || bytes.at(-2) !== 0) throw new Error("REG_SZ UTF-16LE data is not terminated");
  const text = new TextDecoder("utf-16le", { fatal: true }).decode(bytes.subarray(0, -2));
  if (text.includes("\0")) throw new Error("REG_SZ contains an embedded null");
  return { name: value.name, type: "REG_SZ", value: text, bytes: bytes.length };
}
