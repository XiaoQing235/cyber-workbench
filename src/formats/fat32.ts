import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { ConcatSource, MemorySource, SliceSource } from "../core/bytes/sources";

const MAX_DIRECTORY_BYTES = 8 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES = 10_000;
const MAX_FILE_BYTES = 64 * 1024 * 1024;
const MAX_FILE_CLUSTERS = 16_384;

export interface Fat32Entry {
  name: string;
  deleted: boolean;
  directory: boolean;
  attributes: number;
  bytes: number;
  startCluster: number;
  directoryEntryOffset: number;
  createdLocal: string | null;
  accessedLocalDate: string | null;
  modifiedLocal: string | null;
}

export interface Fat32Report {
  filesystem: "FAT32";
  partitionOffset: number;
  volumeLabel: string;
  bytesPerSector: number;
  sectorsPerCluster: number;
  clusterBytes: number;
  totalSectors: number;
  clusterCount: number;
  rootCluster: number;
  fatStartOffset: number;
  dataStartOffset: number;
  rootOnly: true;
  timestampZone: "unknown";
  entries: Fat32Entry[];
}

function dateOnly(value: number): string | null {
  const year = 1980 + (value >> 9);
  const month = (value >> 5) & 15;
  const day = value & 31;
  if (!value || month < 1 || month > 12 || day < 1 || day > 31) return null;
  return `${year}-${String(month).padStart(2, "0")}-${String(day).padStart(2, "0")}`;
}

function localTime(date: number, time: number, centiseconds = 0): string | null {
  const day = dateOnly(date);
  const hour = time >> 11;
  const minute = (time >> 5) & 63;
  const second = (time & 31) * 2 + Math.floor(centiseconds / 100);
  if (!day || hour > 23 || minute > 59 || second > 59 || centiseconds > 199) return null;
  return `${day}T${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}:${String(second).padStart(2, "0")}.${String((centiseconds % 100) * 10).padStart(3, "0")}`;
}

function shortName(entry: Bytes): string {
  const deleted = entry[0] === 0xe5;
  const ascii = (start: number, end: number): string => Array.from(entry.subarray(start, end), (byte, index) =>
    deleted && start === 0 && index === 0 ? "?" : byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : "?",
  ).join("").trimEnd();
  const base = ascii(0, 8);
  const extension = ascii(8, 11);
  return extension ? `${base}.${extension}` : base;
}

export async function inspectFat32(source: ByteSource, partitionOffset = 0, signal?: AbortSignal): Promise<Fat32Report> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(partitionOffset) || partitionOffset < 0 || partitionOffset > source.size - 512) throw new Error("FAT32 partition offset is outside the image");
  const boot = await source.read(partitionOffset, 512);
  if (boot.length !== 512 || boot[510] !== 0x55 || boot[511] !== 0xaa) throw new Error("FAT32 boot-sector signature is missing");
  const header = new DataView(boot.buffer, boot.byteOffset, boot.byteLength);
  const bytesPerSector = header.getUint16(11, true);
  const sectorsPerCluster = boot[13];
  const reserved = header.getUint16(14, true);
  const fatCount = boot[16];
  const fatSectors = header.getUint32(36, true);
  const totalSectors = header.getUint32(32, true);
  const dataStart = reserved + fatCount * fatSectors;
  const clusterBytes = bytesPerSector * sectorsPerCluster;
  const clusterCount = Math.floor((totalSectors - dataStart) / sectorsPerCluster);
  const rootCluster = header.getUint32(44, true) & 0x0fffffff;
  if (bytesPerSector < 512 || bytesPerSector > 4096 || (bytesPerSector & (bytesPerSector - 1)) !== 0 ||
    sectorsPerCluster < 1 || sectorsPerCluster > 128 || (sectorsPerCluster & (sectorsPerCluster - 1)) !== 0 ||
    reserved < 1 || fatCount < 1 || fatCount > 4 || fatSectors < 1 || totalSectors <= dataStart ||
    header.getUint16(17, true) !== 0 || header.getUint16(22, true) !== 0 || header.getUint16(19, true) !== 0 ||
    clusterCount < 65_525 || clusterCount + 2 > fatSectors * bytesPerSector / 4 ||
    rootCluster < 2 || rootCluster >= clusterCount + 2 || totalSectors * bytesPerSector > source.size - partitionOffset) {
    throw new Error("FAT32 boot-sector geometry or filesystem bounds are invalid");
  }

  const dataOffset = partitionOffset + dataStart * bytesPerSector;
  const fatOffset = partitionOffset + reserved * bytesPerSector;
  const entries: Fat32Entry[] = [];
  const visited = new Set<number>();
  let cluster = rootCluster;
  let scannedBytes = 0;
  while (true) {
    if (signal?.aborted) throw signal.reason;
    if (visited.has(cluster) || scannedBytes + clusterBytes > MAX_DIRECTORY_BYTES) throw new Error("FAT32 root directory chain is cyclic or exceeds the read budget");
    visited.add(cluster);
    const offset = dataOffset + (cluster - 2) * clusterBytes;
    const block = await source.read(offset, clusterBytes);
    if (block.length !== clusterBytes) throw new Error("FAT32 root directory extends beyond the image");
    scannedBytes += clusterBytes;
    for (let position = 0; position < block.length; position += 32) {
      const firstByte = block[position];
      if (firstByte === 0) return {
        filesystem: "FAT32", partitionOffset, volumeLabel: new TextDecoder("ascii").decode(boot.subarray(71, 82)).trim(),
        bytesPerSector, sectorsPerCluster, clusterBytes, totalSectors, clusterCount, rootCluster,
        fatStartOffset: fatOffset, dataStartOffset: dataOffset,
        rootOnly: true, timestampZone: "unknown", entries,
      };
      const entry = block.subarray(position, position + 32);
      const attributes = entry[11];
      if (attributes === 0x0f || (attributes & 0x08) !== 0) continue;
      const view = new DataView(entry.buffer, entry.byteOffset, entry.byteLength);
      const startCluster = ((view.getUint16(20, true) & 0x0fff) * 65536) + view.getUint16(26, true);
      const bytes = view.getUint32(28, true);
      const deleted = firstByte === 0xe5;
      if (!deleted && (startCluster >= clusterCount + 2 || (bytes > 0 && startCluster < 2))) throw new Error("FAT32 directory entry has an invalid start cluster");
      if (entries.length >= MAX_DIRECTORY_ENTRIES) throw new Error("FAT32 root directory exceeds the entry budget");
      entries.push({
        name: shortName(entry), deleted, directory: (attributes & 0x10) !== 0, attributes, bytes, startCluster,
        directoryEntryOffset: offset + position,
        createdLocal: localTime(view.getUint16(16, true), view.getUint16(14, true), entry[13]),
        accessedLocalDate: dateOnly(view.getUint16(18, true)),
        modifiedLocal: localTime(view.getUint16(24, true), view.getUint16(22, true)),
      });
    }
    const fatEntry = await source.read(fatOffset + cluster * 4, 4);
    if (fatEntry.length !== 4) throw new Error("FAT32 root directory FAT entry is truncated");
    const next = new DataView(fatEntry.buffer, fatEntry.byteOffset, 4).getUint32(0, true) & 0x0fffffff;
    if (next >= 0x0ffffff8) break;
    if (next < 2 || next >= clusterCount + 2) throw new Error("FAT32 root directory chain contains an invalid cluster");
    cluster = next;
  }
  return {
    filesystem: "FAT32", partitionOffset, volumeLabel: new TextDecoder("ascii").decode(boot.subarray(71, 82)).trim(),
    bytesPerSector, sectorsPerCluster, clusterBytes, totalSectors, clusterCount, rootCluster,
    fatStartOffset: fatOffset, dataStartOffset: dataOffset,
    rootOnly: true, timestampZone: "unknown", entries,
  };
}

export async function extractFat32File(source: ByteSource, entryIndex: number, partitionOffset = 0, signal?: AbortSignal): Promise<{ name: string; data: ByteSource }> {
  const report = await inspectFat32(source, partitionOffset, signal);
  if (!Number.isSafeInteger(entryIndex) || entryIndex < 0 || entryIndex >= report.entries.length) throw new Error("FAT32 root entry index is out of range");
  const entry = report.entries[entryIndex];
  if (entry.deleted) throw new Error("Deleted FAT32 entry has no verified cluster chain; only its metadata can be inspected");
  if (entry.directory) throw new Error("FAT32 directories cannot be extracted as files");
  if (entry.bytes > MAX_FILE_BYTES || Math.ceil(entry.bytes / report.clusterBytes) > MAX_FILE_CLUSTERS) throw new Error("FAT32 file exceeds the bounded extraction budget");
  if (entry.bytes === 0) return { name: entry.name, data: new MemorySource(new Uint8Array(0)) };
  const spans: { offset: number; length: number }[] = [];
  const visited = new Set<number>();
  let cluster = entry.startCluster;
  let remaining = entry.bytes;
  while (remaining > 0) {
    if (signal?.aborted) throw signal.reason;
    if (cluster < 2 || cluster >= report.clusterCount + 2 || visited.has(cluster)) throw new Error("FAT32 file chain is cyclic or outside the filesystem");
    visited.add(cluster);
    const offset = report.dataStartOffset + (cluster - 2) * report.clusterBytes;
    const length = Math.min(remaining, report.clusterBytes);
    if (offset + length > partitionOffset + report.totalSectors * report.bytesPerSector) throw new Error("FAT32 file extends beyond the filesystem");
    const previous = spans.at(-1);
    if (previous && previous.offset + previous.length === offset) previous.length += length;
    else spans.push({ offset, length });
    remaining -= length;
    if (remaining === 0) break;
    const fatEntry = await source.read(report.fatStartOffset + cluster * 4, 4);
    if (fatEntry.length !== 4) throw new Error("FAT32 file FAT entry is truncated");
    const next = new DataView(fatEntry.buffer, fatEntry.byteOffset, 4).getUint32(0, true) & 0x0fffffff;
    if (next >= 0x0ffffff8) throw new Error("FAT32 file chain ends before its declared size");
    cluster = next;
  }
  return { name: entry.name, data: new ConcatSource(spans.map((span) => new SliceSource(source, span.offset, span.length))) };
}

export async function extractDeletedFat32Candidate(source: ByteSource, entryIndex: number, partitionOffset = 0, signal?: AbortSignal): Promise<{
  data: ByteSource;
  report: { name: string; bytes: number; startCluster: number; assumedClusters: number; confidence: "unverified"; assumption: "contiguous-free-clusters"; firstCharacterLost: true };
}> {
  const volume = await inspectFat32(source, partitionOffset, signal);
  if (!Number.isSafeInteger(entryIndex) || entryIndex < 0 || entryIndex >= volume.entries.length) throw new Error("FAT32 root entry index is out of range");
  const entry = volume.entries[entryIndex];
  if (!entry.deleted || entry.directory) throw new Error("FAT32 entry must be a deleted file to inspect contiguous recovery bytes");
  const assumedClusters = Math.ceil(entry.bytes / volume.clusterBytes);
  if (entry.bytes > MAX_FILE_BYTES || assumedClusters > MAX_FILE_CLUSTERS) throw new Error("Deleted FAT32 candidate exceeds the bounded extraction budget");
  if (assumedClusters > 0 && (entry.startCluster < 2 || entry.startCluster + assumedClusters > volume.clusterCount + 2)) throw new Error("Deleted FAT32 candidate exceeds the filesystem");
  for (let index = 0; index < assumedClusters; index++) {
    if (signal?.aborted) throw signal.reason;
    const fatEntry = await source.read(volume.fatStartOffset + (entry.startCluster + index) * 4, 4);
    if (fatEntry.length !== 4 || (new DataView(fatEntry.buffer, fatEntry.byteOffset, 4).getUint32(0, true) & 0x0fffffff) !== 0) {
      throw new Error("Deleted FAT32 candidate cluster is no longer free; contiguous data may be reused");
    }
  }
  const offset = assumedClusters === 0 ? volume.dataStartOffset : volume.dataStartOffset + (entry.startCluster - 2) * volume.clusterBytes;
  return {
    data: new SliceSource(source, offset, entry.bytes),
    report: { name: entry.name, bytes: entry.bytes, startCluster: entry.startCluster, assumedClusters, confidence: "unverified", assumption: "contiguous-free-clusters", firstCharacterLost: true },
  };
}