import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { crc32 } from "../core/checksum/crc32";

const SECTOR_BYTES = 512;
const MAX_ENTRIES = 4_096;
const MAX_ENTRY_BYTES = 1024 * 1024;

export interface DiskPartition {
  number: number;
  startLba: number;
  endLba: number;
  offset: number;
  bytes: number;
  type: string;
  name: string;
  uniqueGuid: string | null;
  bootable: boolean;
}

export interface DiskPartitionReport {
  scheme: "MBR" | "GPT";
  sectorBytes: 512;
  imageBytes: number;
  trailingBytes: number;
  partitions: DiskPartition[];
  diskGuid?: string;
  primaryHeaderCrcValid?: boolean;
  partitionArrayCrcValid?: boolean;
  backupHeaderChecked?: false;
}

function guid(bytes: Bytes, offset: number): string {
  const view = new DataView(bytes.buffer, bytes.byteOffset + offset, 16);
  const hex = (value: number, length: number) => value.toString(16).padStart(length, "0");
  return `${hex(view.getUint32(0, true), 8)}-${hex(view.getUint16(4, true), 4)}-${hex(view.getUint16(6, true), 4)}-${hex(bytes[offset + 8], 2)}${hex(bytes[offset + 9], 2)}-${Array.from(bytes.subarray(offset + 10, offset + 16), (byte) => hex(byte, 2)).join("")}`;
}

function safeLba(value: bigint, sectors: number, label: string): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER) || value >= BigInt(sectors)) throw new Error(`${label} lies outside the disk image`);
  return Number(value);
}

export async function inspectDiskPartitions(source: ByteSource, signal?: AbortSignal): Promise<DiskPartitionReport> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < SECTOR_BYTES) throw new Error("Disk image is too small for an MBR");
  const mbr = await source.read(0, SECTOR_BYTES);
  if (mbr.length !== SECTOR_BYTES || mbr[510] !== 0x55 || mbr[511] !== 0xaa) throw new Error("Disk image has no valid MBR signature");
  const sectors = Math.floor(source.size / SECTOR_BYTES);
  const view = new DataView(mbr.buffer, mbr.byteOffset, mbr.byteLength);
  const entries = Array.from({ length: 4 }, (_, number) => {
    const position = 446 + number * 16;
    return { number: number + 1, status: mbr[position], type: mbr[position + 4], start: view.getUint32(position + 8, true), count: view.getUint32(position + 12, true) };
  }).filter((entry) => entry.type !== 0 || entry.count !== 0);
  if (entries.some((entry) => (entry.status !== 0 && entry.status !== 0x80) || entry.type === 0 || entry.count === 0 || entry.start === 0)) throw new Error("MBR partition entry is malformed");
  const protective = entries.filter((entry) => entry.type === 0xee);
  if (protective.length > 1 || (protective.length === 1 && (protective[0].start !== 1 || source.size < 34 * SECTOR_BYTES))) throw new Error("GPT protective MBR is malformed");
  if (protective.length === 1 && entries.length !== 1) throw new Error("Hybrid protective MBR is unsupported; legacy entries would be omitted");

  const common: Pick<DiskPartitionReport, "sectorBytes" | "imageBytes" | "trailingBytes"> = {
    sectorBytes: SECTOR_BYTES, imageBytes: source.size, trailingBytes: source.size % SECTOR_BYTES,
  };
  if (protective.length === 0) {
    const partitions = entries.map((entry): DiskPartition => {
      const end = entry.start + entry.count - 1;
      if (end >= sectors) throw new Error(`MBR partition ${entry.number} exceeds the disk image`);
      return {
        number: entry.number, startLba: entry.start, endLba: end, offset: entry.start * SECTOR_BYTES, bytes: entry.count * SECTOR_BYTES,
        type: `0x${entry.type.toString(16).padStart(2, "0")}`, name: "", uniqueGuid: null, bootable: entry.status === 0x80,
      };
    });
    return { ...common, scheme: "MBR", partitions };
  }

  const header = await source.read(SECTOR_BYTES, SECTOR_BYTES);
  if (header.length !== SECTOR_BYTES || String.fromCharCode(...header.subarray(0, 8)) !== "EFI PART") throw new Error("GPT primary header signature is missing");
  const head = new DataView(header.buffer, header.byteOffset, header.byteLength);
  const headerSize = head.getUint32(12, true);
  if (head.getUint32(8, true) !== 0x00010000 || headerSize < 92 || headerSize > SECTOR_BYTES || head.getBigUint64(24, true) !== 1n) throw new Error("GPT primary header version, size, or current LBA is invalid");
  const expectedHeaderCrc = head.getUint32(16, true);
  const checkedHeader = header.slice(0, headerSize);
  checkedHeader.fill(0, 16, 20);
  if (crc32(checkedHeader) !== expectedHeaderCrc) throw new Error("GPT primary header CRC-32 is invalid");
  const backup = safeLba(head.getBigUint64(32, true), sectors, "GPT backup header");
  const firstUsable = safeLba(head.getBigUint64(40, true), sectors, "GPT first usable sector");
  const lastUsable = safeLba(head.getBigUint64(48, true), sectors, "GPT last usable sector");
  if (backup <= 1 || firstUsable > lastUsable) throw new Error("GPT usable-sector or backup-header bounds are invalid");
  const entryStart = safeLba(head.getBigUint64(72, true), sectors, "GPT entry table");
  const count = head.getUint32(80, true);
  const entrySize = head.getUint32(84, true);
  const totalBytes = count * entrySize;
  if (count < 1 || count > MAX_ENTRIES || entrySize < 128 || entrySize % 8 !== 0 || totalBytes > MAX_ENTRY_BYTES || entryStart * SECTOR_BYTES + totalBytes > source.size) throw new Error("GPT partition-entry array exceeds the bounded disk extent");
  if (entryStart < 2 || entryStart + Math.ceil(totalBytes / SECTOR_BYTES) > firstUsable || lastUsable >= backup) throw new Error("GPT metadata overlaps usable sectors or the backup header");
  const data = await source.read(entryStart * SECTOR_BYTES, totalBytes);
  if (data.length !== totalBytes || crc32(data) !== head.getUint32(88, true)) throw new Error("GPT partition-entry array CRC-32 is invalid");
  const partitions: DiskPartition[] = [];
  for (let index = 0; index < count; index++) {
    if (index % 128 === 0 && signal?.aborted) throw signal.reason;
    const position = index * entrySize;
    if (data.subarray(position, position + 16).every((byte) => byte === 0)) continue;
    const entry = new DataView(data.buffer, data.byteOffset + position, entrySize);
    const startLba = safeLba(entry.getBigUint64(32, true), sectors, `GPT partition ${index + 1} start`);
    const endLba = safeLba(entry.getBigUint64(40, true), sectors, `GPT partition ${index + 1} end`);
    if (startLba > endLba || startLba < firstUsable || endLba > lastUsable) throw new Error(`GPT partition ${index + 1} exceeds usable sectors`);
    const nameBytes = data.subarray(position + 56, position + 128);
    let nameEnd = 0;
    while (nameEnd < nameBytes.length && (nameBytes[nameEnd] !== 0 || nameBytes[nameEnd + 1] !== 0)) nameEnd += 2;
    const name = new TextDecoder("utf-16le", { fatal: true }).decode(nameBytes.subarray(0, nameEnd));
    partitions.push({ number: index + 1, startLba, endLba, offset: startLba * SECTOR_BYTES, bytes: (endLba - startLba + 1) * SECTOR_BYTES, type: guid(data, position), name, uniqueGuid: guid(data, position + 16), bootable: false });
  }
  const ordered = [...partitions].sort((first, second) => first.startLba - second.startLba);
  for (let index = 1; index < ordered.length; index++) if (ordered[index].startLba <= ordered[index - 1].endLba) throw new Error("GPT partitions overlap");
  return { ...common, scheme: "GPT", partitions, diskGuid: guid(header, 56), primaryHeaderCrcValid: true, partitionArrayCrcValid: true, backupHeaderChecked: false };
}