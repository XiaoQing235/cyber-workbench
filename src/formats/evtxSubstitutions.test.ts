import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { crc32 } from "../core/checksum/crc32";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { evtxNestedSubstitutions, evtxSubstitutions, extractEvtxNestedSubstitution, extractEvtxSubstitution } from "./evtxSubstitutions";

describe("EVTX inline substitution inspection", () => {
  it("reads typed values from the original Plaso System.evtx first record", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/plaso-system.evtx", import.meta.url)));
    const report = await evtxSubstitutions(new MemorySource(bytes), 0, 0);
    expect(report.substitutions.length).toBeGreaterThan(10);
    expect(report.fieldsMapped).toBe(false);
    expect(report.substitutions.slice(0, 4)).toMatchObject([
      { index: 0, type: 4, value: "4" }, { index: 1, type: 4, value: "0" },
      { index: 2, type: 6, value: "105" }, { index: 3, type: 6, value: "105" },
    ]);
    expect(report.substitutions.slice(8, 11)).toMatchObject([
      { index: 8, value: "820" }, { index: 9, value: "2868" }, { index: 10, value: "12049" },
    ]);
    expect(report.substitutions.slice(5, 7)).toMatchObject([
      { index: 5, type: 21, value: "0x8000000000000000" },
      { index: 6, type: 17, value: "2012-03-14T04:17:43.354562Z" },
    ]);
    expect(report.substitutions[19]).toMatchObject({ index: 19, type: 33, bytes: 597, value: null });
    expect(report.substitutions[19].dataOffset).toBeGreaterThan(4096 + 512);
    const nested = await readAll(await extractEvtxSubstitution(new MemorySource(bytes), 0, 0, 19));
    expect(nested).toEqual(bytes.subarray(report.substitutions[19].dataOffset, report.substitutions[19].dataOffset + 597));
    expect([...nested.subarray(0, 4)]).toEqual([0x0f, 1, 1, 0]);
    expect(new TextDecoder("utf-16le").decode(nested)).toContain("System");
    const child = await evtxNestedSubstitutions(new MemorySource(bytes), 0, 0, 19);
    expect(child).toMatchObject({ fieldsMapped: false });
    expect(child.substitutions).toMatchObject([
      { index: 0, type: 1, value: "System" },
      { index: 1, type: 1, value: "C:\\Windows\\System32\\Winevt\\Logs\\Archive-System-2012-03-14-04-17-39-932.evtx" },
    ]);
    expect(child.substitutions).toHaveLength(2);
    const nestedOperation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.evtx.nested-substitutions",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: { chunkIndex: 0, recordIndex: 0, substitutionIndex: 19 } });
    expect(nestedOperation.outputs.report).toMatchObject({ type: "structured", data: child });
    await expect(evtxNestedSubstitutions(new MemorySource(bytes), 0, 0, 2)).rejects.toThrow(/not a supported nested/);
    const exported = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.evtx.substitution-extract",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: { chunkIndex: 0, recordIndex: 0, substitutionIndex: 19 } });
    if (exported.outputs.data?.type !== "bytes") throw new Error("Expected nested BinXML bytes");
    expect(await readAll(exported.outputs.data.source)).toEqual(nested);
    await expect(extractEvtxSubstitution(new MemorySource(bytes), 0, 0, 20)).rejects.toThrow(/does not exist/);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.evtx.substitutions",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: { chunkIndex: 0, recordIndex: 0 } });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: report });
    const modified = bytes.slice();
    modified[4096 + 0x34] ^= 1;
    await expect(evtxSubstitutions(new MemorySource(modified), 0, 0)).rejects.toThrow(/checksum/);
    await expect(extractEvtxSubstitution(new MemorySource(modified), 0, 0, 19)).rejects.toThrow(/checksum/);
    await expect(evtxNestedSubstitutions(new MemorySource(modified), 0, 0, 19)).rejects.toThrow(/checksum/);
    const corruptedPointer = bytes.slice();
    corruptedPointer[4096 + 512 + 24 + 10] ^= 1;
    const start = 4096;
    const view = new DataView(corruptedPointer.buffer);
    view.setUint32(start + 0x34, crc32(corruptedPointer.subarray(start + 512, view.getUint32(start + 0x30, true) + start)), true);
    const checked = new Uint8Array(504);
    checked.set(corruptedPointer.subarray(start, start + 0x78));
    checked.set(corruptedPointer.subarray(start + 0x80, start + 0x200), 0x78);
    view.setUint32(start + 0x7c, crc32(checked), true);
    await expect(evtxSubstitutions(new MemorySource(corruptedPointer), 0, 0)).rejects.toThrow(/template pointer/);
    await expect(evtxSubstitutions(new MemorySource(bytes), 0, 4096)).rejects.toThrow(/budget/);
    const second = await evtxSubstitutions(new MemorySource(bytes), 0, 1);
    expect(second.substitutions).toHaveLength(20);
    expect(second.substitutions.slice(8, 11)).toMatchObject([
      { index: 8, value: "548" }, { index: 9, value: "1340" }, { index: 10, value: "12050" },
    ]);
    const secondNested = await evtxNestedSubstitutions(new MemorySource(bytes), 0, 1, 19);
    expect(secondNested.fieldsMapped).toBe(false);
    expect(secondNested.substitutions).toMatchObject([
      { index: 0, type: 1, value: "Windows Modules Installer" },
      { index: 1, type: 1, value: "stopped" },
      { index: 2, type: 8, value: "38" },
      { index: 3, type: 14, bytes: 38, value: null },
    ]);
    const binary = await readAll(await extractEvtxNestedSubstitution(new MemorySource(bytes), 0, 1, 19, 3));
    expect(binary).toHaveLength(38);
    expect(binary).toEqual(bytes.slice(secondNested.substitutions[3].dataOffset, secondNested.substitutions[3].dataOffset + 38));
    expect([...binary.subarray(0, 8)]).toEqual([0x54, 0x00, 0x72, 0x00, 0x75, 0x00, 0x73, 0x00]);
    const exportedNested = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.evtx.nested-extract",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: { chunkIndex: 0, recordIndex: 1, parentIndex: 19, nestedIndex: 3 } });
    if (exportedNested.outputs.data?.type !== "bytes") throw new Error("Expected nested binary bytes");
    expect(await readAll(exportedNested.outputs.data.source)).toEqual(binary);
    await expect(extractEvtxNestedSubstitution(new MemorySource(bytes), 0, 1, 19, 4)).rejects.toThrow(/does not exist/);
    await expect(extractEvtxNestedSubstitution(new MemorySource(bytes), 0, 1, 2, 0)).rejects.toThrow(/not a supported nested/);
    const brokenNested = bytes.slice();
    brokenNested[second.substitutions[19].dataOffset + 10] ^= 1;
    const chunkBase = 4096;
    const broken = new DataView(brokenNested.buffer);
    broken.setUint32(chunkBase + 0x34, crc32(brokenNested.subarray(chunkBase + 512,
      chunkBase + broken.getUint32(chunkBase + 0x30, true))), true);
    const chunkCrcBytes = new Uint8Array(504);
    chunkCrcBytes.set(brokenNested.subarray(chunkBase, chunkBase + 0x78));
    chunkCrcBytes.set(brokenNested.subarray(chunkBase + 0x80, chunkBase + 0x200), 0x78);
    broken.setUint32(chunkBase + 0x7c, crc32(chunkCrcBytes), true);
    await expect(evtxNestedSubstitutions(new MemorySource(brokenNested), 0, 1, 19)).rejects.toThrow(/template pointer/);
    await expect(extractEvtxNestedSubstitution(new MemorySource(brokenNested), 0, 1, 19, 3)).rejects.toThrow(/template pointer/);
  });
});
