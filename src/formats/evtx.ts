import type { ByteSource } from "../core/bytes/ByteSource";
import { MemorySource } from "../core/bytes/sources";
import { crc32 } from "../core/checksum/crc32";

const HEADER_BYTES = 4096;
const CHUNK_BYTES = 65536;
const MAX_CHUNKS = 4096;
export const MAX_EVTX_BYTES = HEADER_BYTES + MAX_CHUNKS * CHUNK_BYTES;

export interface EvtxReport {
  headerBytes: number;
  headerBlockBytes: number;
  version: string;
  declaredChunks: number;
  presentChunks: number;
  headerChecksumValid: boolean;
  chunks: { index: number; firstRecord: string; lastRecord: string; headerChecksumValid: boolean;
    storedDataChecksum: string; dataChecksumValid: boolean; freeOffset: number; records: { id: string; utc: string; offset: number; bytes: number; binXmlPrefix: string }[];
    truncatedRecords: boolean }[];
  eventRecordsDecoded: false;
}

/** Inspect bounded EVTX file/chunk and record headers; BinXML event payloads remain opaque. */
export async function inspectEvtx(source: ByteSource, maxChunks: number, signal?: AbortSignal, maxRecords = 256): Promise<EvtxReport> {
  if (!Number.isSafeInteger(source.size) || source.size < HEADER_BYTES || source.size > MAX_EVTX_BYTES ||
    (source.size - HEADER_BYTES) % CHUNK_BYTES !== 0 || !Number.isSafeInteger(maxChunks) || maxChunks < 1 || maxChunks > 256 ||
    !Number.isSafeInteger(maxRecords) || maxRecords < 1 || maxRecords > 4096) {
    throw new Error("EVTX file or chunk budget is invalid");
  }
  if (signal?.aborted) throw signal.reason;
  const header = await source.read(0, HEADER_BYTES);
  if (header.length !== HEADER_BYTES || new TextDecoder("ascii").decode(header.subarray(0, 8)) !== "ElfFile\0") {
    throw new Error("Not a complete EVTX ElfFile header");
  }
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  const headerBytes = view.getUint32(0x20, true);
  const minor = view.getUint16(0x24, true);
  const major = view.getUint16(0x26, true);
  const headerBlockBytes = view.getUint16(0x28, true);
  const declaredChunks = view.getUint32(0x2a, true);
  const presentChunks = (source.size - HEADER_BYTES) / CHUNK_BYTES;
  if (headerBytes !== 128 || headerBlockBytes !== HEADER_BYTES || major !== 3 || declaredChunks > MAX_CHUNKS || presentChunks > MAX_CHUNKS) {
    throw new Error("EVTX file header version, size or chunk count is unsupported");
  }
  const checksum = crc32(header.subarray(0, 0x78));
  const chunks: EvtxReport["chunks"] = [];
  let visitedRecords = 0;
  for (let index = 0; index < Math.min(maxChunks, presentChunks); index++) {
    if (signal?.aborted) throw signal.reason;
    const bytes = await source.read(HEADER_BYTES + index * CHUNK_BYTES, 512);
    if (bytes.length !== 512 || new TextDecoder("ascii").decode(bytes.subarray(0, 8)) !== "ElfChnk\0") {
      throw new Error(`EVTX chunk ${index} header is invalid`);
    }
    const item = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const freeOffset = item.getUint32(0x30, true);
    const chunkHeaderBytes = item.getUint32(0x28, true);
    if (chunkHeaderBytes !== 128 || freeOffset < 512 || freeOffset > CHUNK_BYTES) throw new Error(`EVTX chunk ${index} offsets are invalid`);
    const eventData = await source.read(HEADER_BYTES + index * CHUNK_BYTES + 512, freeOffset - 512);
    if (eventData.length !== freeOffset - 512) throw new Error(`EVTX chunk ${index} data is truncated`);
    // Chunk CRC covers the first 120 bytes and 128..512; flags at 120..124 are excluded too.
    const checked = new Uint8Array(0x78 + 0x200 - 0x80);
    checked.set(bytes.subarray(0, 0x78));
    checked.set(bytes.subarray(0x80, 0x200), 0x78);
    const records: EvtxReport["chunks"][number]["records"] = [];
    let offset = 512;
    while (offset < freeOffset && visitedRecords < maxRecords) {
      if (signal?.aborted) throw signal.reason;
      const header = await source.read(HEADER_BYTES + index * CHUNK_BYTES + offset, 24);
      if (header.length !== 24) throw new Error(`EVTX chunk ${index} record header is truncated`);
      const row = new DataView(header.buffer, header.byteOffset, header.byteLength);
      const size = row.getUint32(4, true);
      if (row.getUint32(0, true) !== 0x2a2a || size < 28 || size > freeOffset - offset) {
        throw new Error(`EVTX chunk ${index} record at ${offset} is invalid`);
      }
      const trailer = await source.read(HEADER_BYTES + index * CHUNK_BYTES + offset + size - 4, 4);
      if (trailer.length !== 4 || new DataView(trailer.buffer, trailer.byteOffset).getUint32(0, true) !== size) {
        throw new Error(`EVTX chunk ${index} record size trailer is invalid`);
      }
      const ticks = row.getBigUint64(16, true);
      const prefix = await source.read(HEADER_BYTES + index * CHUNK_BYTES + offset + 24, Math.min(4, size - 28));
      if (prefix.length === 0) throw new Error(`EVTX chunk ${index} record has no BinXML payload`);
      const diff = ticks - 116444736000000000n;
      let millis = diff / 10000n;
      let remainder = diff % 10000n;
      if (remainder < 0n) { millis--; remainder += 10000n; }
      const date = new Date(Number(millis));
      if (!Number.isSafeInteger(Number(millis)) || !Number.isFinite(date.getTime())) throw new Error(`EVTX chunk ${index} record FILETIME is outside the date range`);
      records.push({ id: row.getBigUint64(8, true).toString(), utc: date.toISOString().replace(/Z$/, `${String(remainder / 10n).padStart(3, "0")}Z`),
        offset: HEADER_BYTES + index * CHUNK_BYTES + offset, bytes: size,
        binXmlPrefix: Array.from(prefix, (part) => part.toString(16).padStart(2, "0")).join("") });
      visitedRecords++;
      offset += size;
    }
    chunks.push({ index, firstRecord: item.getBigUint64(0x08, true).toString(), lastRecord: item.getBigUint64(0x10, true).toString(),
      freeOffset, headerChecksumValid: crc32(checked) === item.getUint32(0x7c, true),
      dataChecksumValid: crc32(eventData) === item.getUint32(0x34, true),
      storedDataChecksum: `0x${item.getUint32(0x34, true).toString(16).padStart(8, "0")}`,
      records, truncatedRecords: offset < freeOffset });
  }
  return { headerBytes, headerBlockBytes, version: `${major}.${minor}`, declaredChunks, presentChunks,
    headerChecksumValid: checksum === view.getUint32(0x7c, true), chunks, eventRecordsDecoded: false };
}

/** Extract one indexed raw BinXML record payload; do not interpret the event or execute any values. */
export async function extractEvtxBinXml(source: ByteSource, chunkIndex: number, recordIndex: number, signal?: AbortSignal): Promise<ByteSource> {
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0 || chunkIndex >= 256 ||
    !Number.isSafeInteger(recordIndex) || recordIndex < 0 || recordIndex >= 4096) throw new Error("EVTX selected chunk or record index exceeds its budget");
  const report = await inspectEvtx(source, chunkIndex + 1, signal, recordIndex + 1);
  const chunk = report.chunks[chunkIndex];
  const record = chunk?.records[recordIndex];
  if (!chunk || !record) throw new Error("EVTX selected record does not exist within the file");
  if (!chunk.headerChecksumValid || !chunk.dataChecksumValid) throw new Error("EVTX selected chunk checksum is invalid");
  const size = record.bytes - 28;
  if (size < 4 || size > CHUNK_BYTES - 512) throw new Error("EVTX selected BinXML extent is invalid");
  const data = await source.read(record.offset + 24, size);
  if (signal?.aborted) throw signal.reason;
  if (data.length !== size || data[0] !== 0x0f || data[1] !== 1 || data[2] !== 1) throw new Error("EVTX selected BinXML is truncated or has an unsupported fragment header");
  return new MemorySource(data);
}
