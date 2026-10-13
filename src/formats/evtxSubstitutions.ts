import type { ByteSource } from "../core/bytes/ByteSource";
import { MemorySource } from "../core/bytes/sources";
import { inspectEvtx } from "./evtx";

export interface EvtxSubstitution {
  index: number;
  type: number;
  bytes: number;
  value: string | null;
  dataOffset: number;
}

/** Parse one resident template and its declared substitutions. Offsets are chunk-relative. */
function inlineTable(data: Uint8Array, dataOffset: number, chunkIndex: number, signal?: AbortSignal): EvtxSubstitution[] {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (data.length < 42 || data[0] !== 0x0f || data[1] !== 1 || data[2] !== 1 || data[3] !== 0 || data[4] !== 0x0c ||
    data[5] !== 1) throw new Error("EVTX BinXML does not contain a supported inline template instance");
  const templateOffset = view.getUint32(10, true);
  const templateStart = 14;
  const offsetWithinChunk = dataOffset - (4096 + chunkIndex * 65536);
  if (templateOffset !== offsetWithinChunk + templateStart) {
    throw new Error("EVTX BinXML template pointer does not match the selected inline template");
  }
  const templateBytes = view.getUint32(templateStart + 20, true);
  const declarations = templateStart + 24 + templateBytes;
  if (templateBytes > 32768 || declarations + 4 > data.length || data[templateStart + 24] !== 0x0f ||
    data[declarations - 1] !== 0) {
    throw new Error("EVTX BinXML template exceeds the selected record or has no fragment header");
  }
  const count = view.getUint32(declarations, true);
  if (count > 128 || declarations + 4 + count * 4 > data.length) throw new Error("EVTX substitution declarations exceed their budget");
  if (count === 0) throw new Error("EVTX inline template has no substitution declarations");
  let cursor = declarations + 4 + count * 4;
  const substitutions: EvtxSubstitution[] = [];
  const utf16 = new TextDecoder("utf-16le", { fatal: true });
  for (let index = 0; index < count; index++) {
    if (signal?.aborted) throw signal.reason;
    const descriptor = declarations + 4 + index * 4;
    const size = view.getUint16(descriptor, true);
    const type = data[descriptor + 2];
    if (data[descriptor + 3] !== 0 || size > 4096 || cursor + size > data.length) throw new Error("EVTX substitution extent or reserved byte is invalid");
    const part = new DataView(data.buffer, data.byteOffset + cursor, size);
    let value: string | null = null;
    if (type === 0 && size === 0) value = null;
    else if (type === 4 && size === 1) value = String(part.getUint8(0));
    else if (type === 6 && size === 2) value = String(part.getUint16(0, true));
    else if (type === 8 && size === 4) value = String(part.getUint32(0, true));
    else if (type === 10 && size === 8) value = part.getBigUint64(0, true).toString();
    else if (type === 21 && size === 8) value = `0x${part.getBigUint64(0, true).toString(16).padStart(16, "0")}`;
    else if (type === 17 && size === 8) {
      const ticks = part.getBigUint64(0, true) - 116444736000000000n;
      const micros = ticks / 10n;
      const millis = micros / 1000n;
      const date = new Date(Number(millis));
      if (ticks >= 0n && Number.isSafeInteger(Number(millis)) && Number.isFinite(date.getTime())) {
        value = date.toISOString().replace(/\.\d{3}Z$/, `.${String((micros % 1_000_000n + 1_000_000n) % 1_000_000n).padStart(6, "0")}Z`);
      }
    }
    else if (type === 1 && size % 2 === 0) value = utf16.decode(data.subarray(cursor, cursor + size)).replace(/\0+$/, "");
    substitutions.push({ index, type, bytes: size, value, dataOffset: dataOffset + cursor });
    cursor += size;
  }
  // Some records carry additional bytes after the declared substitutions. Do not treat these as values.
  return substitutions;
}

/** Decode an inline-template BinXML record's typed substitution table, without assigning event-field names. */
export async function evtxSubstitutions(source: ByteSource, chunkIndex: number, recordIndex: number,
  signal?: AbortSignal): Promise<{ substitutions: EvtxSubstitution[]; fieldsMapped: false }> {
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= 256 ||
    !Number.isSafeInteger(recordIndex) || recordIndex < 0 || recordIndex >= 4096) {
    throw new Error("EVTX selected chunk or record index exceeds its budget");
  }
  const inspected = await inspectEvtx(source, chunkIndex + 1, signal, recordIndex + 1);
  const chunk = inspected.chunks[chunkIndex];
  const selected = chunk?.records[recordIndex];
  if (!selected) throw new Error("EVTX selected record is missing");
  if (!chunk.headerChecksumValid || !chunk.dataChecksumValid) throw new Error("EVTX selected chunk checksum is invalid");
  if (selected.bytes < 28 || selected.bytes > 65536 - 512) throw new Error("EVTX selected BinXML extent is invalid");
  const data = await source.read(selected.offset + 24, selected.bytes - 28);
  if (signal?.aborted) throw signal.reason;
  if (data.length !== selected.bytes - 28) throw new Error("EVTX selected BinXML is truncated");
  return { substitutions: inlineTable(data, selected.offset + 24, chunkIndex, signal), fieldsMapped: false };
}

/** Decode only the substitution table of a checked nested BinXML value (type 0x21). */
export async function evtxNestedSubstitutions(source: ByteSource, chunkIndex: number, recordIndex: number,
  substitutionIndex: number, signal?: AbortSignal): Promise<{ substitutions: EvtxSubstitution[]; fieldsMapped: false }> {
  if (!Number.isSafeInteger(substitutionIndex) || substitutionIndex < 0 || substitutionIndex >= 128) {
    throw new Error("EVTX substitution index exceeds its budget");
  }
  const report = await evtxSubstitutions(source, chunkIndex, recordIndex, signal);
  const selected = report.substitutions[substitutionIndex];
  if (!selected || selected.type !== 0x21 || selected.bytes < 42) throw new Error("EVTX selected substitution is not a supported nested BinXML value");
  const data = await source.read(selected.dataOffset, selected.bytes);
  if (signal?.aborted) throw signal.reason;
  if (data.length !== selected.bytes) throw new Error("EVTX nested substitution is truncated");
  return { substitutions: inlineTable(data, selected.dataOffset, chunkIndex, signal), fieldsMapped: false };
}

/** Export one raw value from a checked nested inline-template substitution table. */
export async function extractEvtxNestedSubstitution(source: ByteSource, chunkIndex: number, recordIndex: number,
  parentIndex: number, nestedIndex: number, signal?: AbortSignal): Promise<ByteSource> {
  if (!Number.isSafeInteger(nestedIndex) || nestedIndex < 0 || nestedIndex >= 128) {
    throw new Error("EVTX nested substitution index exceeds its budget");
  }
  const report = await evtxNestedSubstitutions(source, chunkIndex, recordIndex, parentIndex, signal);
  const selected = report.substitutions[nestedIndex];
  if (!selected) throw new Error("EVTX selected nested substitution does not exist");
  const data = await source.read(selected.dataOffset, selected.bytes);
  if (signal?.aborted) throw signal.reason;
  if (data.length !== selected.bytes) throw new Error("EVTX selected nested substitution is truncated");
  return new MemorySource(data);
}

/** Export the exact declared bytes of a selected substitution; no BinXML interpretation. */
export async function extractEvtxSubstitution(source: ByteSource, chunkIndex: number, recordIndex: number,
  substitutionIndex: number, signal?: AbortSignal): Promise<ByteSource> {
  if (!Number.isSafeInteger(substitutionIndex) || substitutionIndex < 0 || substitutionIndex >= 128) {
    throw new Error("EVTX substitution index exceeds its budget");
  }
  const report = await evtxSubstitutions(source, chunkIndex, recordIndex, signal);
  const selected = report.substitutions[substitutionIndex];
  if (!selected) throw new Error("EVTX selected substitution does not exist");
  const data = await source.read(selected.dataOffset, selected.bytes);
  if (signal?.aborted) throw signal.reason;
  if (data.length !== selected.bytes) throw new Error("EVTX selected substitution is truncated");
  return new MemorySource(data);
}
