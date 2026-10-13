import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { inspectEseHeader } from "./eseHeader";

function ese(): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(4096 * 3);
  const view = new DataView(bytes.buffer);
  view.setUint32(4, 0x89abcdef, true);
  view.setUint32(8, 0x620, true);
  view.setUint32(12, 0, true);
  view.setUint32(52, 3, true);
  view.setUint32(232, 0xc8, true);
  view.setUint32(236, 4096, true);
  let checksum = 0x89abcdef;
  for (let offset = 4; offset < 4096; offset += 4) checksum ^= view.getUint32(offset, true);
  view.setUint32(0, checksum >>> 0, true);
  bytes.set(bytes.subarray(0, 4096), 4096);
  return bytes;
}

describe("bounded ESE/ESENT header inspection", () => {
  it("inspects the published Plaso Catalog1.edb database header", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/plaso-catalog1.edb", import.meta.url)));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("22c61563ad84a869ce65dc2004075c8032223882");
    const report = await inspectEseHeader(new MemorySource(bytes));
    expect(report).toMatchObject({ format: "ESE/ESENT", fileType: "database", fileBytes: 3153920,
      primaryChecksumValid: true, tablesDecoded: false, pagesDecoded: false });
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.ese.header",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: {} });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: report });
  });
  it("reports version, state, page checksum and shadow equality without table decoding", async () => {
    const input = new MemorySource(ese());
    expect(await inspectEseHeader(input)).toEqual({ format: "ESE/ESENT", pageBytes: 4096, fileBytes: 12288,
      version: "0x620", revision: 0xc8, state: "clean", fileType: "database", primaryChecksumValid: true,
      shadowMatchesPrimary: true, tablesDecoded: false, pagesDecoded: false });
    const result = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.ese.header",
      inputs: { data: bytesValue(input) }, params: {} });
    expect(result.run.status).toBe("success");
  });

  it("detects shadow mismatch and rejects invalid page geometry or file types", async () => {
    const shadow = ese(); shadow[4096 + 64] ^= 1;
    expect((await inspectEseHeader(new MemorySource(shadow))).shadowMatchesPrimary).toBe(false);
    const geometry = ese(); new DataView(geometry.buffer).setUint32(236, 6000, true);
    await expect(inspectEseHeader(new MemorySource(geometry))).rejects.toThrow(/page size/);
    const stream = ese(); new DataView(stream.buffer).setUint32(12, 1, true);
    await expect(inspectEseHeader(new MemorySource(stream))).rejects.toThrow(/Not an ESE database/);
  });
});
