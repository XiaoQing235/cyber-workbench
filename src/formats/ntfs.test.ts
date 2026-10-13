import { describe, expect, it } from "vitest";
import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { ConcatSource, MemorySource, MissingSource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractNtfsStream, inspectNtfsRecord, recoverDeletedNtfsNonResident, recoverDeletedNtfsResident } from "./ntfs";
import { importWindowsTimeline } from "./windowsTimeline";

const decode = (encoded: string) => Uint8Array.from(atob(encoded.replace(/\s/g, "")), (character) => character.charCodeAt(0));
const BOOT = "61KQTlRGUyAgICAAAggAAAAAAAAA+AAAAAAAAAAAAAAAAAAAgACAAP//AQAAAAAABAAAAAAAAAD/HwAAAAAAAPYAAAABAAAATOVgR05dBS4=";
const MASTER = `RklMRTAAAwAAAAAAAAAAAAEAAQA4AAEAmAEAAAAEAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAAQAAAA
YAAAAAAAGAAAAAAASAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAaAAAAAAAGAAAAAIASgAAABgAAQAFAAAA
AAAFAOoK0xdlWd0B6grTF2VZ3QHqCtMXZVndAeoK0xdlWd0BAHAAAAAAAAAAbAAAAAAAAAYAAAAAAAAA
BAMkAE0ARgBUAAAAAAAAAIAAAABIAAAAAQBAAAAAAQAAAAAAAAAAABIAAAAAAAAAQAAAAAAAAAAAMAEA
AAAAAAAIAQAAAAAAAAgBAAAAAAAREwQAAAAAALAAAABIAAAAAQBAAAAAAwAAAAAAAAAAAAAAAAAAAAAA
QAAAAAAAAAAAEAAAAAAAABAAAAAAAAAAEAAAAAAAAAARAQIAAAAAAP////8AAAAA`;
const NOTE = `RklMRTAAAwAAAAAAAAAAAAEAAQA4AAEAwAEAAAAEAAAAAAAAAAAAAAUAAABAAAAABgAAAAAAAAAQAAAA
SAAAAAAAAAAAAAAAMAAAABgAAABXA9q6ZVndAVcD2rplWd0BVwPaumVZ3QFXA9q6ZVndASAAAAAAAAAA
AAAAAAAAAAAwAAAAcAAAAAAAAAAAAAMAUgAAABgAAQAFAAAAAAAFAFcD2rplWd0BVwPaumVZ3QFXA9q6
ZVndAVcD2rplWd0BEAAAAAAAAAAAAAAAAAAAACAAAAAAAAAACABOAE8AVABFAC4AVABYAFQAAAAYAAAA
UAAAAGgAAAAAAAAAAAABAFAAAAAYAAAAAQAEgBQAAAAkAAAAAAAAADQAAAABAgAAAAAABSAAAAAgAgAA
AQIAAAAAAAUgAAAAIAIAAAIAHAABAAAAAAMUAP8BHwABAQAAAAAAAQAAAACAAAAAKAAAAAAAAAAAAAIA
EAAAABgAAABOVEZTIEFEUyBmaXh0dXJlgAAAADgAAAAABhgAAAAEABAAAAAoAAAAcwBlAGMAcgBlAHQA
AAAAAE5URlMgQURTIGZpeHR1cmX/////AAAAAA==`;
const DESIGN = `RklMRTAAAwAAAAAAAAAAAAEAAQA4AAEAqAEAAAAEAAAAAAAAAAAAAAQAAABBAAAACQAAAAAAAAAQAAAA
SAAAAAAAAAAAAAAAMAAAABgAAAAVJWy8ZVndARUlbLxlWd0BFSVsvGVZ3QEVJWy8ZVndASAAAAAAAAAA
AAAAAAAAAAAwAAAAcAAAAAAAAAAAAAMAVgAAABgAAQAFAAAAAAAFABUlbLxlWd0BFSVsvGVZ3QEVJWy8
ZVndARUlbLxlWd0BAMAAAAAAAAAAAAAAAAAAACAAAAAAAAAACgBEAEUAUwBJAEcATgAuAFQAWABUAAAA
UAAAAGgAAAAAAAAAAAABAFAAAAAYAAAAAQAEgBQAAAAkAAAAAAAAADQAAAABAgAAAAAABSAAAAAgAgAA
AQIAAAAAAAUgAAAAIAIAAAIAHAABAAAAAAMUAP8BHwABAQAAAAAAAQAAAACAAAAASAAAAAEAQAAAAAIA
AAAAAAAAAAALAAAAAAAAAEAAAAAAAAAAAMAAAAAAAABquQAAAAAAAGq5AAAAAAAAIQwAIgAAAAD/////
AAAAAA==`;

function record(encoded: string): MemorySource {
  const bytes = new Uint8Array(1024);
  bytes.set(decode(encoded));
  bytes.set(bytes.subarray(48, 50), 510);
  bytes.set(bytes.subarray(48, 50), 1022);
  return new MemorySource(bytes);
}

function ntfsImage(): ConcatSource {
  const boot = new Uint8Array(512);
  boot.set(decode(BOOT));
  boot[510] = 0x55;
  boot[511] = 0xaa;
  return new ConcatSource([
    new MemorySource(boot), new MissingSource(16_384 - 512), record(MASTER),
    new MissingSource(81_920 - 16_384 - 1024), record(NOTE), record(DESIGN),
    new MissingSource(64 * 1024 * 1024 - 81_920 - 2 * 1024),
  ]);
}

function attributeAt(record: Bytes, type: number, named = false): number {
  const view = new DataView(record.buffer, record.byteOffset, record.byteLength);
  for (let position = view.getUint16(20, true); position < view.getUint32(24, true); position += view.getUint32(position + 4, true)) {
    if (view.getUint32(position, true) === type && (record[position + 9] !== 0) === named) return position;
  }
  throw new Error(`Fixture has no NTFS attribute ${type}`);
}

describe("NTFS MFT record inspection", () => {
  it("uses real NTFS-3G records to report MACB and a named resident data stream", async () => {
    const report = await inspectNtfsRecord(ntfsImage(), 64);
    expect(report).toMatchObject({
      filesystem: "NTFS", bytesPerSector: 512, clusterBytes: 4096, recordBytes: 1024,
      recordNumber: 64, inUse: true, directory: false, fixupsValid: true,
      names: [{ name: "NOTE.TXT", parentRecord: 5, namespace: 0 }],
      streams: [{ name: null, resident: true, bytes: 16 }, { name: "secret", resident: true, bytes: 16 }],
    });
    expect(report.standardTimes?.created?.utc).toMatch(/^2026-10-11T09:48:55\./);
    expect(report.standardTimes?.changed?.filetime).toMatch(/^134/);
    const larger = await inspectNtfsRecord(ntfsImage(), 65);
    expect(larger).toMatchObject({ names: [{ name: "DESIGN.TXT" }], streams: [{ name: null, resident: false, bytes: 47466 }] });
  });

  it("rejects damaged update-sequence fixups rather than trusting sector-tail bytes", async () => {
    const bytes = (ntfsImage().parts[4] as MemorySource).bytes.slice();
    bytes[510] ^= 1;
    const image = ntfsImage();
    const damaged = new ConcatSource([...image.parts.slice(0, 4), new MemorySource(bytes), ...image.parts.slice(5)]);
    await expect(inspectNtfsRecord(damaged, 64)).rejects.toThrow(/update-sequence fixup/);
  });

  it("rejects malformed $MFT runs and resident ADS bounds", async () => {
    const image = ntfsImage();
    const master = (image.parts[2] as MemorySource).bytes.slice();
    const masterView = new DataView(master.buffer);
    const dataPosition = attributeAt(master, 0x80);
    master[dataPosition + masterView.getUint16(dataPosition + 32, true)] = 0x01;
    await expect(inspectNtfsRecord(new ConcatSource([...image.parts.slice(0, 2), new MemorySource(master), ...image.parts.slice(3)]), 64)).rejects.toThrow(/runlist is malformed or sparse/);

    const note = (image.parts[4] as MemorySource).bytes.slice();
    const notePosition = attributeAt(note, 0x80, true);
    new DataView(note.buffer).setUint32(notePosition + 16, 1024, true);
    await expect(inspectNtfsRecord(new ConcatSource([...image.parts.slice(0, 4), new MemorySource(note), ...image.parts.slice(5)]), 64)).rejects.toThrow(/resident attribute exceeds/);
  });

  it("inspects a large image with only three bounded metadata reads", async () => {
    const image = ntfsImage();
    let bytesRead = 0;
    const source: ByteSource = {
      size: image.size,
      async read(offset, length) {
        bytesRead += length;
        if (bytesRead > 512 + 2 * 1024) throw new Error("Unexpected read beyond NTFS metadata budget");
        return image.read(offset, length);
      },
      stream: image.stream.bind(image),
    };
    expect((await inspectNtfsRecord(source, 64)).names[0].name).toBe("NOTE.TXT");
    expect(bytesRead).toBe(512 + 2 * 1024);
  });

  it("exposes named ADS and UTC timestamps through the Forensics registry", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.disk.ntfs.record", inputs: { data: bytesValue(ntfsImage()) }, params: { recordNumber: 64 },
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: {
      recordNumber: 64, names: [{ name: "NOTE.TXT" }], streams: [{ name: null, bytes: 16 }, { name: "secret", bytes: 16 }],
    } });
  });

  it("exports separate standard and filename MACB events with microsecond UTC", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.disk.ntfs.timeline-export", inputs: { data: bytesValue(ntfsImage()) },
      params: { recordNumber: 64, hostname: "fixture-host" },
    });
    expect(result.run.status).toBe("success");
    if (result.outputs.text?.type !== "text") throw new Error("Expected NTFS timeline JSONL");
    const events = result.outputs.text.text.split("\n").map((line) => JSON.parse(line));
    expect(events).toHaveLength(8);
    expect(events[0]).toMatchObject({ parser: "ntfs_mft", hostname: "fixture-host", filename: "NOTE.TXT", message: "MFT 64 $STANDARD_INFORMATION created" });
    expect(events[0].timestamp).toMatch(/^2026-10-11T09:48:55\.\d{6}Z$/);
    expect(events[4].message).toBe("MFT 64 $FILE_NAME (0) created");
    const timeline = await importWindowsTimeline(result.outputs.text.text, "plaso-jsonl", 0, 60);
    expect(timeline.total).toBe(8);
    expect(timeline.events[0]).toMatchObject({ host: "fixture-host", source: "plaso:ntfs_mft", artifact: "NOTE.TXT", utc: events[0].timestamp });
  });

  it("extracts the native named resident ADS bytes and refuses unknown stream names", async () => {
    const expected = new TextEncoder().encode("NTFS ADS fixture");
    expect(await readAll(await extractNtfsStream(ntfsImage(), 64, "secret"))).toEqual(expected);
    await expect(extractNtfsStream(ntfsImage(), 64, "missing")).rejects.toThrow(/no data stream/);
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.disk.ntfs.stream-extract", inputs: { data: bytesValue(ntfsImage()) },
      params: { recordNumber: 64, streamName: "secret" },
    });
    expect(result.run.status).toBe("success");
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected named NTFS stream bytes");
    expect(await readAll(result.outputs.data.source)).toEqual(expected);
    expect((await extractNtfsStream(ntfsImage(), 65)).size).toBe(47466);
  });

  it("returns only resident bytes left in a deleted MFT record as an unverified candidate", async () => {
    const image = ntfsImage();
    const deleted = (image.parts[4] as MemorySource).bytes.slice();
    const view = new DataView(deleted.buffer);
    view.setUint16(22, view.getUint16(22, true) & ~1, true);
    const modified = new ConcatSource([...image.parts.slice(0, 4), new MemorySource(deleted), ...image.parts.slice(5)]);
    expect((await inspectNtfsRecord(modified, 64)).inUse).toBe(false);
    await expect(extractNtfsStream(modified, 64)).rejects.toThrow(/Deleted NTFS/);
    const candidate = await recoverDeletedNtfsResident(modified, 64, "secret");
    expect(candidate.report).toEqual({ recordNumber: 64, name: "secret", bytes: 16, verifiedFile: false });
    expect(new TextDecoder().decode(await readAll(candidate.data))).toBe("NTFS ADS fixture");
    const run = await executeOperation(createDefaultRegistry(), { operationId: "forensics.disk.ntfs.deleted-resident",
      inputs: { data: bytesValue(modified) }, params: { recordNumber: 64, streamName: "secret" } });
    expect(run.run.status).toBe("success");
    expect(run.outputs.report).toMatchObject({ type: "structured", data: { verifiedFile: false } });
    await expect(recoverDeletedNtfsResident(ntfsImage(), 64)).rejects.toThrow(/deleted non-directory/);
    await expect(recoverDeletedNtfsResident(modified, 64, "missing")).rejects.toThrow(/no selected data stream/);
  });

  it("reads a deleted non-resident candidate from its mapped clusters without claiming allocation or integrity", async () => {
    const image = ntfsImage();
    const deleted = (image.parts[5] as MemorySource).bytes.slice();
    const flags = new DataView(deleted.buffer);
    flags.setUint16(22, flags.getUint16(22, true) & ~1, true);
    const expected = new TextEncoder().encode("deleted NTFS mapped cluster candidate");
    const stream = attributeAt(deleted, 0x80);
    const runOffset = flags.getUint16(stream + 32, true);
    const runHeader = deleted[stream + runOffset];
    const countBytes = runHeader & 0x0f;
    const offsetBytes = runHeader >> 4;
    let physical = 0;
    for (let i = 0; i < offsetBytes; i++) physical |= deleted[stream + runOffset + 1 + countBytes + i] << (8 * i);
    const cluster = new Uint8Array(4096);
    cluster.set(expected);
    const physicalOffset = physical * 4096;
    const patched = new ConcatSource([
      ...image.parts.slice(0, 5), new MemorySource(deleted),
      new MissingSource(physicalOffset - 81_920 - 2 * 1024), new MemorySource(cluster),
      new MissingSource(image.size - physicalOffset - cluster.length),
    ]);
    expect((await inspectNtfsRecord(patched, 65)).inUse).toBe(false);
    const candidate = await recoverDeletedNtfsNonResident(patched, 65);
    expect(candidate.report).toMatchObject({ recordNumber: 65, name: null, bytes: 47466,
      verifiedFile: false, currentClusterAllocationChecked: false,
      currentClusterAllocation: { status: "unavailable", freeClusters: null, allocatedClusters: null } });
    expect((await candidate.data.read(0, expected.length))).toEqual(expected);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.disk.ntfs.deleted-nonresident",
      inputs: { data: bytesValue(patched) }, params: { recordNumber: 65 } });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: candidate.report });
    await expect(recoverDeletedNtfsNonResident(ntfsImage(), 65)).rejects.toThrow(/deleted non-directory/);
    await expect(recoverDeletedNtfsNonResident(patched, 64)).rejects.toThrow(/deleted non-directory/);
    const sparse = deleted.slice(); sparse[stream + runOffset] = 0x01;
    const malformed = new ConcatSource([...patched.parts.slice(0, 5), new MemorySource(sparse), ...patched.parts.slice(6)]);
    await expect(recoverDeletedNtfsNonResident(malformed, 65)).rejects.toThrow(/sparse/);
  });

  it("checks present-day $Bitmap bits without treating free clusters as verified historical bytes", async () => {
    const image = ntfsImage();
    const deleted = (image.parts[5] as MemorySource).bytes.slice();
    new DataView(deleted.buffer).setUint16(22, 0, true);
    const stream = attributeAt(deleted, 0x80);
    const runOffset = new DataView(deleted.buffer).getUint16(stream + 32, true);
    const runHeader = deleted[stream + runOffset];
    const countBytes = runHeader & 15;
    const offsetBytes = runHeader >> 4;
    let candidateCluster = 0;
    for (let i = 0; i < offsetBytes; i++) candidateCluster |= deleted[stream + runOffset + 1 + countBytes + i] << (i * 8);
    const bitmapRecord = (image.parts[5] as MemorySource).bytes.slice();
    const bitmapView = new DataView(bitmapRecord.buffer);
    bitmapView.setUint32(44, 6, true);
    bitmapRecord[stream + runOffset + 1 + countBytes] = 0xe8; // $Bitmap data in cluster 1000
    bitmapRecord[stream + runOffset + 2 + countBytes] = 0x03;
      const bitmap = new Uint8Array(4096 * 12);
    const candidateBytes = new TextEncoder().encode("candidate bits are not a file integrity check");
    const candidateData = new Uint8Array(4096);
    candidateData.set(candidateBytes);
    const assemble = (allocated: boolean) => {
      bitmap.fill(0);
      if (allocated) bitmap[Math.floor(candidateCluster / 8)] |= 1 << (candidateCluster % 8);
      return new ConcatSource([
        ...image.parts.slice(0, 3), new MissingSource(6144 - 1024), new MemorySource(bitmapRecord),
        new MissingSource(81_920 - 16_384 - 7168), ...image.parts.slice(4, 5), new MemorySource(deleted),
        new MissingSource(1000 * 4096 - 81_920 - 2048), new MemorySource(bitmap.slice()),
        new MissingSource(candidateCluster * 4096 - 1000 * 4096 - bitmap.length), new MemorySource(candidateData),
        new MissingSource(image.size - candidateCluster * 4096 - candidateData.length),
      ]);
    };
    const freeImage = assemble(false);
    const free = await recoverDeletedNtfsNonResident(freeImage, 65);
    expect(free.report).toMatchObject({ currentClusterAllocationChecked: true, verifiedFile: false,
      currentClusterAllocation: { status: "all-free", freeClusters: 12, allocatedClusters: 0 } });
    expect(await free.data.read(0, candidateBytes.length)).toEqual(candidateBytes);
    const used = await recoverDeletedNtfsNonResident(assemble(true), 65);
    expect(used.report.currentClusterAllocation).toMatchObject({ status: "some-allocated", freeClusters: 11, allocatedClusters: 1 });
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.disk.ntfs.deleted-nonresident",
      inputs: { data: bytesValue(freeImage) }, params: { recordNumber: 65 } });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: free.report });
  });
});
