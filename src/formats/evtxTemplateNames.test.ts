import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { crc32 } from "../core/checksum/crc32";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { evtxInlineNames } from "./evtxTemplateNames";

describe("bounded EVTX inline name inspection", () => {
  it("resolves name pointers on the independently published Plaso record", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/plaso-system.evtx", import.meta.url)));
    const report = await evtxInlineNames(new MemorySource(bytes), 0, 0);
    expect(report).toMatchObject({ fieldsMapped: false, candidateNames: true });
    expect(report.names).toEqual(expect.arrayContaining([
      { offset: 589, kind: "element", name: "Event" }, { offset: 760, kind: "element", name: "System" },
      { offset: 1018, kind: "element", name: "EventID" }, { offset: 1297, kind: "element", name: "TimeCreated" },
    ]));
    const registered = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.evtx.inline-names",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: { chunkIndex: 0, recordIndex: 0 } });
    expect(registered.outputs.report).toMatchObject({ type: "structured", data: report });
    const second = await evtxInlineNames(new MemorySource(bytes), 0, 1);
    expect(second).toMatchObject({ fieldsMapped: false, candidateNames: true });
    expect(second.names).toEqual(expect.arrayContaining([{ offset: 3057, kind: "attribute", name: "EventSourceName" }]));
    const damaged = bytes.slice();
    damaged[4096 + 0x34] ^= 1;
    await expect(evtxInlineNames(new MemorySource(damaged), 0, 0)).rejects.toThrow(/checksum/);
    const pointer = bytes.slice();
    pointer[4096 + 512 + 24 + 10] ^= 1;
    const view = new DataView(pointer.buffer);
    view.setUint32(4096 + 0x34, crc32(pointer.subarray(4096 + 512, 4096 + view.getUint32(4096 + 0x30, true))), true);
    const checked = new Uint8Array(504);
    checked.set(pointer.subarray(4096, 4096 + 0x78));
    checked.set(pointer.subarray(4096 + 0x80, 4096 + 0x200), 0x78);
    view.setUint32(4096 + 0x7c, crc32(checked), true);
    await expect(evtxInlineNames(new MemorySource(pointer), 0, 0)).rejects.toThrow(/inline template/);
    const name = bytes.slice();
    const nameOffset = 4096 + 589;
    name[nameOffset + 8] = 0;
    const changed = new DataView(name.buffer);
    changed.setUint32(4096 + 0x34, crc32(name.subarray(4096 + 512, 4096 + changed.getUint32(4096 + 0x30, true))), true);
    const changedHeader = new Uint8Array(504);
    changedHeader.set(name.subarray(4096, 4096 + 0x78));
    changedHeader.set(name.subarray(4096 + 0x80, 4096 + 0x200), 0x78);
    changed.setUint32(4096 + 0x7c, crc32(changedHeader), true);
    const inventory = await evtxInlineNames(new MemorySource(name), 0, 0);
    expect(inventory.names.some((candidate) => candidate.name === "Event")).toBe(false);
  });
});
