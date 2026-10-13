import type { Bytes } from "../core/bytes/ByteSource";
import { crc32 } from "../core/checksum/crc32";

const MAX_ZIP_BYTES = 1024 * 1024;
const MAX_RECORDS = 64;
const EOCD = 0x06054b50;
const CENTRAL = 0x02014b50;
const LOCAL = 0x04034b50;

export interface ZipEndChainRecord {
  eocdOffset: number;
  centralOffset: number;
  localOffset: number;
  dataOffset: number;
  name: string;
  bytes: number;
  crc32: string;
}

export interface ZipEndChainReport {
  records: ZipEndChainRecord[];
  candidate: Uint8Array<ArrayBuffer> | null;
  candidateText: string | null;
  contiguous: boolean;
}

export function inspectZipEndChain(bytes: Bytes, prefix = "flag", signal?: AbortSignal): ZipEndChainReport {
  if (bytes.length < 22 || bytes.length > MAX_ZIP_BYTES) throw new Error("ZIP end-record chain must fit within 1 MiB");
  if (!/^[A-Za-z0-9_-]{1,32}$/.test(prefix)) throw new Error("ZIP entry prefix must be 1-32 safe ASCII characters");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const records: ZipEndChainRecord[] = [];
  const payloads = new Map<number, Bytes>();
  for (let offset = 0; offset <= bytes.length - 22; offset++) {
    if ((offset & 0x1fff) === 0 && signal?.aborted) throw signal.reason;
    if (view.getUint32(offset, true) !== EOCD || offset + 22 + view.getUint16(offset + 20, true) !== bytes.length ||
      view.getUint16(offset + 4, true) !== 0 || view.getUint16(offset + 6, true) !== 0 ||
      view.getUint16(offset + 8, true) !== 1 || view.getUint16(offset + 10, true) !== 1) continue;
    const centralOffset = view.getUint32(offset + 16, true);
    const centralBytes = view.getUint32(offset + 12, true);
    if (centralOffset > offset - 46 || centralBytes < 46 || centralBytes > offset - centralOffset ||
      view.getUint32(centralOffset, true) !== CENTRAL) continue;
    const nameBytes = view.getUint16(centralOffset + 28, true);
    const extraBytes = view.getUint16(centralOffset + 30, true);
    if (nameBytes < 1 || nameBytes > 128 || centralOffset + 46 + nameBytes + extraBytes > offset ||
      view.getUint16(centralOffset + 8, true) !== 0 || view.getUint16(centralOffset + 10, true) !== 0) continue;
    const rawName = bytes.subarray(centralOffset + 46, centralOffset + 46 + nameBytes);
    if (rawName.some((byte) => byte < 0x21 || byte > 0x7e)) continue;
    const localOffset = view.getUint32(centralOffset + 42, true);
    if (localOffset > centralOffset - 30 || view.getUint32(localOffset, true) !== LOCAL ||
      view.getUint16(localOffset + 6, true) !== 0 || view.getUint16(localOffset + 8, true) !== 0 ||
      view.getUint16(localOffset + 26, true) !== nameBytes) continue;
    const localName = bytes.subarray(localOffset + 30, localOffset + 30 + nameBytes);
    if (localName.length !== rawName.length || localName.some((byte, index) => byte !== rawName[index])) continue;
    const size = view.getUint32(centralOffset + 20, true);
    const uncompressed = view.getUint32(centralOffset + 24, true);
    const expectedCrc = view.getUint32(centralOffset + 16, true);
    const dataOffset = localOffset + 30 + nameBytes + view.getUint16(localOffset + 28, true);
    if (size > 256 || size !== uncompressed || size !== view.getUint32(localOffset + 18, true) ||
      uncompressed !== view.getUint32(localOffset + 22, true) || expectedCrc !== view.getUint32(localOffset + 14, true) ||
      dataOffset > centralOffset || size > centralOffset - dataOffset) continue;
    const data = bytes.subarray(dataOffset, dataOffset + size);
    if (crc32(data) !== expectedCrc) continue;
    if (records.length >= MAX_RECORDS) throw new Error("ZIP end-record chain exceeds 64 valid records");
    records.push({ eocdOffset: offset, centralOffset, localOffset, dataOffset,
      name: String.fromCharCode(...rawName), bytes: size, crc32: `0x${expectedCrc.toString(16).padStart(8, "0")}` });
    payloads.set(offset, data);
  }
  if (!records.length) throw new Error("No EOF-anchored single-entry stored ZIP records with valid CRCs were found");
  const matching = records.filter((record) => record.name.startsWith(prefix) &&
    /^[0-9]{2}$/.test(record.name.slice(prefix.length))).sort((first, second) => first.name.localeCompare(second.name));
  const contiguous = matching.length > 0 && matching.every((record, index) => Number(record.name.slice(prefix.length)) === index);
  const candidate = contiguous ? new Uint8Array(matching.reduce((length, record) => length + record.bytes, 0)) : null;
  let position = 0;
  if (candidate) for (const record of matching) {
    const data = payloads.get(record.eocdOffset)!;
    candidate.set(data, position);
    position += data.length;
  }
  let candidateText: string | null = null;
  if (candidate) try { candidateText = new TextDecoder("utf-8", { fatal: true }).decode(candidate); }
  catch { candidateText = null; }
  return { records, candidate, candidateText, contiguous };
}