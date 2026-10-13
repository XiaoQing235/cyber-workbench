import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { ByteSource } from "../core/bytes/ByteSource";
import { MemorySource, readAll } from "../core/bytes/sources";
import { crc32 } from "../core/checksum/crc32";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractEvtxBinXml, inspectEvtx } from "./evtx";
import { importWindowsTimeline } from "./windowsTimeline";

function log(): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(4096 + 65536);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("ElfFile\0"));
  view.setUint32(0x20, 128, true);
  view.setUint16(0x28, 4096, true);
  view.setUint16(0x26, 3, true);
  view.setUint32(0x2a, 1, true);
  view.setUint32(0x7c, crc32(bytes.subarray(0, 0x78)), true);
  const start = 4096;
  bytes.set(new TextEncoder().encode("ElfChnk\0"), start);
  view.setBigUint64(start + 0x08, 10n, true);
  view.setBigUint64(start + 0x10, 11n, true);
   view.setUint32(start + 0x28, 128, true);
   view.setUint32(start + 0x30, 512, true);
   view.setUint32(start + 0x34, crc32(bytes.subarray(start + 512, start + 512)), true);
   const checked = new Uint8Array(504);
   checked.set(bytes.subarray(start, start + 0x78));
   checked.set(bytes.subarray(start + 0x80, start + 0x200), 0x78);
  view.setUint32(start + 0x7c, crc32(checked), true);
  return bytes;
}

describe("bounded EVTX header inventory", () => {
  it("reads the independently published Plaso System.evtx with record-header evidence", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/plaso-system.evtx", import.meta.url)));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("70f50e5d058ee8db3d4ee94c108eb7ad556977ac");
    const report = await inspectEvtx(new MemorySource(bytes), 1, undefined, 10);
    expect(report).toMatchObject({ presentChunks: 17, headerChecksumValid: true, eventRecordsDecoded: false,
      chunks: [{ index: 0, headerChecksumValid: true, dataChecksumValid: true, truncatedRecords: true }] });
    expect(report.chunks[0].records).toHaveLength(10);
    expect(report.chunks[0].records[0]).toMatchObject({ binXmlPrefix: "0f010100" });
    expect(report.chunks[0].records.every((record, index, records) => index === 0 || Number(record.id) > Number(records[index - 1].id))).toBe(true);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.evtx.inspect",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: { maxChunks: 1, maxRecords: 10 } });
    expect(operation.run.status).toBe("success");
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: { chunks: [{ records: report.chunks[0].records }] } });
    const selected = report.chunks[0].records[0];
    const payload = await readAll(await extractEvtxBinXml(new MemorySource(bytes), 0, 0));
    expect(payload).toEqual(bytes.slice(selected.offset + 24, selected.offset + selected.bytes - 4));
    const extracted = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.evtx.binxml-extract",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: { chunkIndex: 0, recordIndex: 0 } });
    expect(extracted.run.status).toBe("success");
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected raw BinXML payload");
    expect(await readAll(extracted.outputs.data.source)).toEqual(payload);
    await expect(extractEvtxBinXml(new MemorySource(bytes), 0, 4095)).rejects.toThrow(/does not exist/);
    const changedFlags = bytes.slice();
    changedFlags[4096 + 0x78] ^= 1;
    expect((await inspectEvtx(new MemorySource(changedFlags), 1, undefined, 1)).chunks[0].headerChecksumValid).toBe(true);
    const changedHeader = bytes.slice();
    changedHeader[4096 + 0x70] ^= 1;
    expect((await inspectEvtx(new MemorySource(changedHeader), 1, undefined, 1)).chunks[0].headerChecksumValid).toBe(false);
    const changedData = bytes.slice();
    changedData[report.chunks[0].records[0].offset + 32] ^= 1;
    const corruptReport = await inspectEvtx(new MemorySource(changedData), 1, undefined, 1);
    expect(corruptReport.chunks[0]).toMatchObject({ dataChecksumValid: false, headerChecksumValid: true });
    await expect(extractEvtxBinXml(new MemorySource(changedData), 0, 0)).rejects.toThrow(/checksum/);
  });
  it("checks file and chunk headers with range reads and keeps records opaque", async () => {
    const bytes = log();
    let readBytes = 0;
    const source: ByteSource = { size: bytes.length,
      async read(offset, length) { readBytes += length; return bytes.slice(offset, offset + length); },
      stream() { throw new Error("EVTX inventory must use range reads"); } };
    expect(await inspectEvtx(source, 4)).toMatchObject({ headerChecksumValid: true, headerBytes: 128, headerBlockBytes: 4096, version: "3.0", presentChunks: 1,
      chunks: [{ firstRecord: "10", lastRecord: "11", headerChecksumValid: true, freeOffset: 512 }], eventRecordsDecoded: false });
    expect(readBytes).toBe(4608);
    const result = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.evtx.inspect",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: {} });
    expect(result.run.status).toBe("success");
  });

  it("rejects truncated or corrupt chunk headers and reports checksum mismatches", async () => {
    const short = log().slice(0, -1);
    await expect(inspectEvtx(new MemorySource(short), 1)).rejects.toThrow(/budget/);
    const badChunk = log(); badChunk[4096] ^= 1;
    await expect(inspectEvtx(new MemorySource(badChunk), 1)).rejects.toThrow(/chunk 0 header/);
    const badChecksum = log(); badChecksum[0x7c] ^= 1;
    expect((await inspectEvtx(new MemorySource(badChecksum), 1)).headerChecksumValid).toBe(false);
    const badOffset = log(); new DataView(badOffset.buffer).setUint32(4096 + 0x30, 1, true);
    await expect(inspectEvtx(new MemorySource(badOffset), 1)).rejects.toThrow(/offsets/);
    const wrongHeader = log(); new DataView(wrongHeader.buffer).setUint32(0x20, 4096, true);
    await expect(inspectEvtx(new MemorySource(wrongHeader), 1)).rejects.toThrow(/file header/);
    const wrongChunk = log(); new DataView(wrongChunk.buffer).setUint32(4096 + 0x28, 512, true);
    await expect(inspectEvtx(new MemorySource(wrongChunk), 1)).rejects.toThrow(/offsets/);
  });

  it("walks bounded event record headers and validates record-size trailers", async () => {
    const bytes = log();
    const view = new DataView(bytes.buffer);
    const start = 4096 + 512;
    view.setUint32(4096 + 0x30, 544, true);
    view.setUint32(start, 0x2a2a, true);
    view.setUint32(start + 4, 32, true);
    view.setBigUint64(start + 8, 42n, true);
    view.setBigUint64(start + 16, 133801632001234560n, true);
    bytes.set([0x0f, 0x01, 0x01, 0x00], start + 24);
    view.setUint32(start + 28, 32, true);
    expect((await inspectEvtx(new MemorySource(bytes), 1)).chunks[0].records).toEqual([
      { id: "42", utc: "2025-01-01T00:00:00.123456Z", offset: start, bytes: 32, binXmlPrefix: "0f010100" },
    ]);
    const exported = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.evtx.timeline-export",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: { maxChunks: 1, maxRecords: 2, hostname: "LAB" } });
    expect(exported.run.status).toBe("success");
    if (exported.outputs.text?.type !== "text") throw new Error("Expected EVTX timeline JSONL");
    const timeline = await importWindowsTimeline(exported.outputs.text.text, "plaso-jsonl", 0, 1);
    expect(timeline.events[0]).toMatchObject({ utc: "2025-01-01T00:00:00.123456Z", source: "plaso:evtx_record_header", host: "LAB" });
    view.setUint32(start + 28, 31, true);
    await expect(inspectEvtx(new MemorySource(bytes), 1)).rejects.toThrow(/trailer/);
    view.setUint32(start + 4, 70000, true);
    await expect(inspectEvtx(new MemorySource(bytes), 1)).rejects.toThrow(/record at/);
    const synthetic = log();
    const syntheticView = new DataView(synthetic.buffer);
    syntheticView.setUint32(4096 + 0x30, 544, true);
    syntheticView.setUint32(4096 + 512, 0x2a2a, true);
    syntheticView.setUint32(4096 + 512 + 4, 32, true);
    syntheticView.setBigUint64(4096 + 512 + 16, 133801632001234560n, true);
    synthetic.set([0x0f, 0x01, 0x01, 0x00], 4096 + 512 + 24);
    syntheticView.setUint32(4096 + 512 + 28, 32, true);
    syntheticView.setUint32(4096 + 0x34, crc32(synthetic.subarray(4096 + 512, 4096 + 544)), true);
    const syntheticHeader = new Uint8Array(504);
    syntheticHeader.set(synthetic.subarray(4096, 4096 + 0x78));
    syntheticHeader.set(synthetic.subarray(4096 + 0x80, 4096 + 0x200), 0x78);
    syntheticView.setUint32(4096 + 0x7c, crc32(syntheticHeader), true);
    await expect(readAll(await extractEvtxBinXml(new MemorySource(synthetic), 0, 0)))
      .resolves.toEqual(Uint8Array.of(0x0f, 1, 1, 0));
  });
});
