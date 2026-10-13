import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { ConcatSource, MemorySource, SliceSource } from "../core/bytes/sources";
import { unixMicrosToUtc } from "./windowsTimeline";

const WINDOWS_TO_UNIX_TICKS = 116444736000000000n;
const MAX_RUNS = 1_024;
const MAX_BITMAP_READ = 256 * 1024;

interface NtfsTime {
  filetime: string;
  utc: string;
}

interface NtfsTimes {
  created: NtfsTime | null;
  modified: NtfsTime | null;
  changed: NtfsTime | null;
  accessed: NtfsTime | null;
}

export interface NtfsRecordReport {
  filesystem: "NTFS";
  partitionOffset: number;
  bytesPerSector: number;
  clusterBytes: number;
  recordBytes: number;
  recordNumber: number;
  sequenceNumber: number;
  inUse: boolean;
  directory: boolean;
  fixupsValid: true;
  standardTimes: NtfsTimes | null;
  names: { name: string; parentRecord: number; namespace: number; times: NtfsTimes }[];
  streams: { name: string | null; bytes: number; resident: boolean; flags: number }[];
}

interface Attribute {
  type: number;
  name: string | null;
  flags: number;
  resident: boolean;
  data: Bytes | null;
  bytes: number;
  runs: number | null;
  start: number;
  end: number;
}

function safeNumber(value: bigint, label: string): number {
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error(`${label} exceeds JavaScript's safe integer range`);
  return Number(value);
}

function time(ticks: bigint): NtfsTime | null {
  if (ticks === 0n) return null;
  const delta = ticks - WINDOWS_TO_UNIX_TICKS;
  const micros = delta / 10n - (delta < 0n && delta % 10n !== 0n ? 1n : 0n);
  return { filetime: ticks.toString(), utc: unixMicrosToUtc(micros) };
}

function times(view: DataView, offset: number): NtfsTimes {
  return {
    created: time(view.getBigUint64(offset, true)),
    modified: time(view.getBigUint64(offset + 8, true)),
    changed: time(view.getBigUint64(offset + 16, true)),
    accessed: time(view.getBigUint64(offset + 24, true)),
  };
}

function fixedRecord(raw: Bytes, sectorBytes: number, expected: number): { data: Bytes; view: DataView; used: number; firstAttribute: number } {
  const data = raw.slice();
  if (String.fromCharCode(...data.subarray(0, 4)) !== "FILE") throw new Error(`NTFS MFT record ${expected} has no FILE signature`);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const usa = view.getUint16(4, true);
  const count = view.getUint16(6, true);
  const firstAttribute = view.getUint16(20, true);
  const used = view.getUint32(24, true);
  if (count !== data.length / sectorBytes + 1 || usa < 48 || usa + count * 2 > firstAttribute || firstAttribute < 48 || used > data.length || used < firstAttribute + 4 || view.getUint32(28, true) !== data.length) throw new Error("NTFS MFT update-sequence header or used-byte extent is invalid");
  const sequence = view.getUint16(usa, true);
  for (let index = 1; index < count; index++) {
    const end = index * sectorBytes - 2;
    if (view.getUint16(end, true) !== sequence) throw new Error(`NTFS MFT record ${expected} update-sequence fixup is invalid`);
    view.setUint16(end, view.getUint16(usa + index * 2, true), true);
  }
  if (view.getUint32(44, true) !== expected) throw new Error(`NTFS MFT record number does not match ${expected}`);
  return { data, view, used, firstAttribute };
}

function attributes(record: ReturnType<typeof fixedRecord>): Attribute[] {
  const { data, view, used, firstAttribute } = record;
  const result: Attribute[] = [];
  let position = firstAttribute;
  while (position + 4 <= used && view.getUint32(position, true) !== 0xffffffff) {
    if (position + 24 > used) throw new Error("NTFS MFT attribute header is truncated");
    const type = view.getUint32(position, true);
    const length = view.getUint32(position + 4, true);
    const resident = data[position + 8] === 0;
    const nameLength = data[position + 9];
    const nameOffset = view.getUint16(position + 10, true);
    const minimum = resident ? 24 : 64;
    if (data[position + 8] > 1 || length < minimum || length % 8 !== 0 || length > used - position ||
      (nameLength !== 0 && (nameOffset < minimum || nameOffset + nameLength * 2 > length))) throw new Error("NTFS MFT attribute extent or name is invalid");
    const name = nameLength === 0 ? null : new TextDecoder("utf-16le", { fatal: true }).decode(data.subarray(position + nameOffset, position + nameOffset + nameLength * 2));
    let value: Bytes | null = null;
    let bytes: number;
    let runs: number | null = null;
    if (resident) {
      bytes = view.getUint32(position + 16, true);
      const valueOffset = view.getUint16(position + 20, true);
      if (valueOffset < 24 || bytes > length - valueOffset || (nameLength !== 0 && valueOffset < nameOffset + nameLength * 2)) throw new Error("NTFS resident attribute exceeds its extent");
      value = data.subarray(position + valueOffset, position + valueOffset + bytes);
    } else {
      bytes = safeNumber(view.getBigUint64(position + 48, true), "NTFS non-resident attribute size");
      runs = view.getUint16(position + 32, true);
      if (runs < 64 || runs >= length || (nameLength !== 0 && runs < nameOffset + nameLength * 2)) throw new Error("NTFS non-resident runlist offset is invalid");
    }
    result.push({ type, name, flags: view.getUint16(position + 12, true), resident, data: value, bytes, runs, start: position, end: position + length });
    if (type === 0x20) throw new Error("NTFS external attribute lists are not yet supported");
    position += length;
    if (result.length > 128) throw new Error("NTFS MFT record exceeds the attribute budget");
  }
  if (position + 4 > used || view.getUint32(position, true) !== 0xffffffff) throw new Error("NTFS MFT attribute terminator is missing");
  return result;
}

function decodeRuns(record: Bytes, attribute: Attribute, clusterBytes: number, totalBytes: number, label: string): { logical: number; length: number; physical: number }[] {
  if (attribute.runs === null) throw new Error(`NTFS ${label} must have a non-resident runlist`);
  const runs: { logical: number; length: number; physical: number }[] = [];
  let cursor = attribute.start + attribute.runs;
  let logical = 0;
  let physical = 0n;
  while (cursor < attribute.end && record[cursor] !== 0) {
    const header = record[cursor++];
    const lengthBytes = header & 15;
    const offsetBytes = header >> 4;
    if (lengthBytes < 1 || lengthBytes > 8 || offsetBytes < 1 || offsetBytes > 8 || cursor + lengthBytes + offsetBytes > attribute.end) throw new Error(`NTFS ${label} runlist is malformed or sparse`);
    let count = 0n;
    for (let index = 0; index < lengthBytes; index++) count |= BigInt(record[cursor++]) << BigInt(index * 8);
    let delta = 0n;
    for (let index = 0; index < offsetBytes; index++) delta |= BigInt(record[cursor++]) << BigInt(index * 8);
    if (record[cursor - 1] & 0x80) delta -= 1n << BigInt(offsetBytes * 8);
    physical += delta;
    const length = safeNumber(count, `NTFS ${label} run length`) * clusterBytes;
    const start = safeNumber(physical, `NTFS ${label} cluster`) * clusterBytes;
    if (count < 1n || physical < 0n || length > totalBytes - start || length > Number.MAX_SAFE_INTEGER - logical) throw new Error(`NTFS ${label} run exceeds the filesystem`);
    runs.push({ logical, length, physical: start });
    logical += length;
    if (runs.length > MAX_RUNS) throw new Error(`NTFS ${label} run count exceeds the budget`);
  }
  if (cursor >= attribute.end || runs.length === 0 || runs[0].logical !== 0 || logical < attribute.bytes) throw new Error(`NTFS ${label} runlist is unterminated or incomplete`);
  return runs;
}

async function parseNtfsRecord(source: ByteSource, recordNumber: number, partitionOffset: number, signal?: AbortSignal): Promise<{
  report: NtfsRecordReport; attributes: Attribute[]; record: Bytes; clusterBytes: number; totalBytes: number;
}> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(recordNumber) || recordNumber < 0 || recordNumber > 100_000 ||
    !Number.isSafeInteger(partitionOffset) || partitionOffset < 0 || partitionOffset > source.size - 512) throw new Error("NTFS record number or partition offset is outside the supported bounds");
  const boot = await source.read(partitionOffset, 512);
  if (boot.length !== 512 || String.fromCharCode(...boot.subarray(3, 11)) !== "NTFS    " || boot[510] !== 0x55 || boot[511] !== 0xaa) throw new Error("NTFS boot-sector signature is missing");
  const header = new DataView(boot.buffer, boot.byteOffset, boot.byteLength);
  const bytesPerSector = header.getUint16(11, true);
  const sectorsPerCluster = boot[13];
  const clusterBytes = bytesPerSector * sectorsPerCluster;
  const exponent = new DataView(boot.buffer, boot.byteOffset, boot.byteLength).getInt8(64);
  const recordBytes = exponent < 0 ? 2 ** -exponent : exponent * clusterBytes;
  const totalBytes = safeNumber(header.getBigUint64(40, true), "NTFS volume sectors") * bytesPerSector;
  const mftCluster = safeNumber(header.getBigUint64(48, true), "NTFS $MFT cluster");
  if (bytesPerSector < 512 || bytesPerSector > 4096 || (bytesPerSector & (bytesPerSector - 1)) !== 0 ||
    sectorsPerCluster < 1 || sectorsPerCluster > 128 || (sectorsPerCluster & (sectorsPerCluster - 1)) !== 0 ||
    clusterBytes > 64 * 1024 || recordBytes < bytesPerSector || recordBytes > 4096 || recordBytes % bytesPerSector !== 0 ||
    totalBytes < 0 || totalBytes > source.size - partitionOffset || mftCluster < 1 || (mftCluster + 1) * clusterBytes > totalBytes) throw new Error("NTFS volume or $MFT geometry is invalid");
  const rawMaster = await source.read(partitionOffset + mftCluster * clusterBytes, recordBytes);
  if (rawMaster.length !== recordBytes) throw new Error("NTFS $MFT record zero is truncated");
  const master = fixedRecord(rawMaster, bytesPerSector, 0);
  const mftData = attributes(master).find((attribute) => attribute.type === 0x80 && attribute.name === null);
  if (!mftData || mftData.resident || mftData.flags !== 0 || recordNumber * recordBytes + recordBytes > mftData.bytes) throw new Error("NTFS $MFT data is missing, unsupported, or shorter than the record");
  const runs = decodeRuns(master.data, mftData, clusterBytes, totalBytes, "$MFT");
  if (runs[0].physical !== mftCluster * clusterBytes) throw new Error("NTFS $MFT boot location disagrees with its runlist");

  const target = new Uint8Array(recordBytes);
  let logical = recordNumber * recordBytes;
  let copied = 0;
  for (const run of runs) {
    if (copied === recordBytes) break;
    if (logical < run.logical || logical >= run.logical + run.length) continue;
    const length = Math.min(recordBytes - copied, run.logical + run.length - logical);
    const part = await source.read(partitionOffset + run.physical + logical - run.logical, length);
    if (part.length !== length) throw new Error("NTFS $MFT run is truncated");
    target.set(part, copied);
    copied += length;
    logical += length;
  }
  if (copied !== recordBytes) throw new Error("NTFS MFT record is outside the mapped runs");
  if (signal?.aborted) throw signal.reason;
  const record = fixedRecord(target, bytesPerSector, recordNumber);
  const attrs = attributes(record);
  const standard = attrs.find((attribute) => attribute.type === 0x10);
  if (standard && (!standard.data || standard.data.length < 32)) throw new Error("NTFS standard-information timestamps are truncated");
  const names = attrs.filter((attribute) => attribute.type === 0x30).map((attribute) => {
    if (!attribute.data || attribute.data.length < 66) throw new Error("NTFS filename attribute is truncated");
    const data = attribute.data;
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const nameBytes = data[64] * 2;
    if (66 + nameBytes > data.length) throw new Error("NTFS filename exceeds its attribute");
    return {
      name: new TextDecoder("utf-16le", { fatal: true }).decode(data.subarray(66, 66 + nameBytes)),
      parentRecord: safeNumber(view.getBigUint64(0, true) & 0xffffffffffffn, "NTFS parent record"), namespace: data[65], times: times(view, 8),
    };
  });
  const report: NtfsRecordReport = {
    filesystem: "NTFS", partitionOffset, bytesPerSector, clusterBytes, recordBytes, recordNumber,
    sequenceNumber: record.view.getUint16(16, true), inUse: (record.view.getUint16(22, true) & 1) !== 0,
    directory: (record.view.getUint16(22, true) & 2) !== 0, fixupsValid: true,
    standardTimes: standard?.data ? times(new DataView(standard.data.buffer, standard.data.byteOffset, standard.data.byteLength), 0) : null,
    names, streams: attrs.filter((attribute) => attribute.type === 0x80).map((attribute) => ({ name: attribute.name, bytes: attribute.bytes, resident: attribute.resident, flags: attribute.flags })),
  };
  return { report, attributes: attrs, record: record.data, clusterBytes, totalBytes };
}

export async function inspectNtfsRecord(source: ByteSource, recordNumber: number, partitionOffset = 0, signal?: AbortSignal): Promise<NtfsRecordReport> {
  return (await parseNtfsRecord(source, recordNumber, partitionOffset, signal)).report;
}

export async function extractNtfsStream(source: ByteSource, recordNumber: number, streamName = "", partitionOffset = 0, signal?: AbortSignal): Promise<ByteSource> {
  const parsed = await parseNtfsRecord(source, recordNumber, partitionOffset, signal);
  if (!parsed.report.inUse) throw new Error("Deleted NTFS MFT record streams cannot be extracted as verified files");
  const attribute = parsed.attributes.find((item) => item.type === 0x80 && item.name === (streamName || null));
  if (!attribute) throw new Error("NTFS MFT record has no data stream with this name");
  if (attribute.flags !== 0 || attribute.bytes > 64 * 1024 * 1024) throw new Error("NTFS compressed, encrypted, sparse, or oversized streams are unsupported");
  if (attribute.resident) return new MemorySource(attribute.data!.slice());
  if (attribute.bytes === 0) return new MemorySource(new Uint8Array(0));
  const runs = decodeRuns(parsed.record, attribute, parsed.clusterBytes, parsed.totalBytes, "data stream");
  let remaining = attribute.bytes;
  const slices: SliceSource[] = [];
  for (const run of runs) {
    if (signal?.aborted) throw signal.reason;
    if (remaining === 0) break;
    const length = Math.min(remaining, run.length);
    slices.push(new SliceSource(source, partitionOffset + run.physical, length));
    remaining -= length;
  }
  if (remaining !== 0) throw new Error("NTFS data stream runlist is shorter than its declared size");
  return new ConcatSource(slices);
}

/** Candidate only: resident data remains inside the deleted MFT record; no cluster allocation is assumed. */
export async function recoverDeletedNtfsResident(source: ByteSource, recordNumber: number, streamName = "", partitionOffset = 0,
  signal?: AbortSignal): Promise<{ data: ByteSource; report: { recordNumber: number; name: string | null; bytes: number; verifiedFile: false } }> {
  const parsed = await parseNtfsRecord(source, recordNumber, partitionOffset, signal);
  if (parsed.report.inUse || parsed.report.directory) throw new Error("NTFS candidate requires a deleted non-directory MFT record");
  const attribute = parsed.attributes.find((item) => item.type === 0x80 && item.name === (streamName || null));
  if (!attribute) throw new Error("Deleted NTFS record has no selected data stream");
  if (!attribute.resident || !attribute.data || attribute.flags !== 0 || attribute.bytes > 4096) {
    throw new Error("Deleted NTFS recovery supports only uncompressed resident streams within the record");
  }
  return { data: new MemorySource(attribute.data.slice()), report: { recordNumber, name: attribute.name, bytes: attribute.bytes, verifiedFile: false } };
}

/** Candidate only: deleted non-resident runlists may point at clusters that have since been reused. */
export async function recoverDeletedNtfsNonResident(source: ByteSource, recordNumber: number, streamName = "", partitionOffset = 0,
  signal?: AbortSignal): Promise<{ data: ByteSource; report: { recordNumber: number; name: string | null; bytes: number;
    runs: number; verifiedFile: false; currentClusterAllocationChecked: boolean; currentClusterAllocation: {
      status: "unavailable" | "all-free" | "some-allocated"; freeClusters: number | null; allocatedClusters: number | null;
      reason?: string;
    } } }> {
  const parsed = await parseNtfsRecord(source, recordNumber, partitionOffset, signal);
  if (parsed.report.inUse || parsed.report.directory) throw new Error("NTFS candidate requires a deleted non-directory MFT record");
  const attribute = parsed.attributes.find((item) => item.type === 0x80 && item.name === (streamName || null));
  if (!attribute) throw new Error("Deleted NTFS record has no selected data stream");
  if (attribute.resident || attribute.flags !== 0 || attribute.bytes < 1 || attribute.bytes > 8 * 1024 * 1024) {
    throw new Error("Deleted NTFS non-resident recovery requires an uncompressed nonempty stream of at most 8 MiB");
  }
  const runs = decodeRuns(parsed.record, attribute, parsed.clusterBytes, parsed.totalBytes, "deleted data stream");
  if (runs.length > 128) throw new Error("Deleted NTFS data stream exceeds the 128-run candidate budget");
  let remaining = attribute.bytes;
  const parts: SliceSource[] = [];
  for (const run of runs) {
    if (signal?.aborted) throw signal.reason;
    if (remaining <= 0) break;
    const length = Math.min(remaining, run.length);
    parts.push(new SliceSource(source, partitionOffset + run.physical, length));
    remaining -= length;
  }
  if (remaining) throw new Error("Deleted NTFS data runlist is shorter than the declared stream");
  let currentClusterAllocation: { status: "unavailable" | "all-free" | "some-allocated";
    freeClusters: number | null; allocatedClusters: number | null; reason?: string };
  try {
    // $Bitmap (MFT 6) describes the present volume state, not allocation at deletion time.
    const bitmapRecord = await parseNtfsRecord(source, 6, partitionOffset, signal);
    if (!bitmapRecord.report.inUse || bitmapRecord.report.directory) throw new Error("$Bitmap record is not a live file");
    const bitmapAttribute = bitmapRecord.attributes.find((item) => item.type === 0x80 && item.name === null);
    if (!bitmapAttribute || bitmapAttribute.flags !== 0) throw new Error("$Bitmap data stream is missing or unsupported");
    const clusterCount = Math.ceil(parsed.totalBytes / parsed.clusterBytes);
    if (bitmapAttribute.bytes < Math.ceil(clusterCount / 8)) throw new Error("$Bitmap does not cover the volume");
    const bitmap = await extractNtfsStream(source, 6, "", partitionOffset, signal);
    let freeClusters = 0;
    let allocatedClusters = 0;
    let budget = 0;
    let clustersRemaining = Math.ceil(attribute.bytes / parsed.clusterBytes);
    for (const run of runs) {
      if (signal?.aborted) throw signal.reason;
      if (clustersRemaining === 0) break;
      const first = run.physical / parsed.clusterBytes;
      const count = Math.min(clustersRemaining, run.length / parsed.clusterBytes);
      const startByte = Math.floor(first / 8);
      const byteCount = Math.ceil((first % 8 + count) / 8);
      budget += byteCount;
      if (budget > MAX_BITMAP_READ) throw new Error("$Bitmap lookup exceeds the read budget");
      const bits = await bitmap.read(startByte, byteCount);
      if (bits.length !== byteCount) throw new Error("$Bitmap lookup is truncated");
      for (let index = 0; index < count; index++) {
        if ((bits[Math.floor((first % 8 + index) / 8)] & (1 << ((first + index) % 8))) !== 0) allocatedClusters++;
        else freeClusters++;
      }
      clustersRemaining -= count;
    }
    currentClusterAllocation = { status: allocatedClusters ? "some-allocated" : "all-free", freeClusters, allocatedClusters };
  } catch (error) {
    if (signal?.aborted) throw signal.reason;
    currentClusterAllocation = { status: "unavailable", freeClusters: null, allocatedClusters: null,
      reason: error instanceof Error ? error.message : String(error) };
  }
  return { data: new ConcatSource(parts), report: { recordNumber, name: attribute.name, bytes: attribute.bytes,
    runs: parts.length, verifiedFile: false, currentClusterAllocationChecked: currentClusterAllocation.status !== "unavailable",
    currentClusterAllocation } };
}
