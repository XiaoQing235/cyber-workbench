import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractSafeTensor, inspectSafeTensors } from "./safeTensors";

const NATIVE = `qAAAAAAAAAB7Il9fbWV0YWRhdGFfXyI6eyJzb3VyY2UiOiJuYXRpdmUtZml4dHVyZSJ9LCJ3ZWlnaHRz
Ijp7ImR0eXBlIjoiRjMyIiwic2hhcGUiOls0XSwiZGF0YV9vZmZzZXRzIjpbMCwxNl19LCJzaWduYWwi
OnsiZHR5cGUiOiJVOCIsInNoYXBlIjpbNF0sImRhdGFfb2Zmc2V0cyI6WzE2LDIwXX19ICAgICAAAAA/
AACAvwAAAEAAAGBARkxBRw==`;
const fixture = () => new MemorySource(Uint8Array.from(atob(NATIVE.replace(/\s/g, "")), (character) => character.charCodeAt(0)));

describe("SafeTensors model inventory", () => {
  it("matches the official serializer's header and reads selected tensor bytes lazily", async () => {
    const report = await inspectSafeTensors(fixture());
    expect(report).toMatchObject({ format: "safetensors", headerBytes: 168, dataOffset: 176, tensorCount: 2,
      metadataKeys: ["source"], metadataValuesReturned: false,
      tensors: [{ name: "weights", dtype: "F32", shape: [4], bytes: 16, offset: 0 },
        { name: "signal", dtype: "U8", shape: [4], bytes: 4, offset: 16 }] });
    expect(JSON.stringify(report)).not.toContain("native-fixture");
    expect(new TextDecoder().decode(await readAll(await extractSafeTensor(fixture(), "signal")))).toBe("FLAG");
  });

  it("rejects a tensor whose shape or extent disagrees with the file", async () => {
    const badHeader = fixture().bytes.slice();
    const text = new TextDecoder().decode(badHeader.subarray(8, 176));
    const changed = new TextEncoder().encode(text.replace('"data_offsets":[16,20]', '"data_offsets":[15,20]'));
    badHeader.set(changed, 8);
    await expect(inspectSafeTensors(new MemorySource(badHeader))).rejects.toThrow(/byte length disagrees/);
    const truncated = fixture().bytes.slice(0, -1);
    await expect(inspectSafeTensors(new MemorySource(truncated))).rejects.toThrow(/exceeds the file data/);
  });

  it("keeps metadata values and tensor bytes out of the registered report", async () => {
    const registry = createDefaultRegistry();
    const data = bytesValue(fixture());
    const inspected = await executeOperation(registry, { operationId: "forensics.model.safetensors.inspect", inputs: { data }, params: {} });
    expect(inspected.run.status).toBe("success");
    expect(JSON.stringify(inspected.outputs)).not.toContain("native-fixture");
    expect(JSON.stringify(inspected.outputs)).not.toContain("FLAG");
    const extracted = await executeOperation(registry, {
      operationId: "forensics.model.safetensors.extract", inputs: { data }, params: { name: "signal" },
    });
    expect(extracted.run.status).toBe("success");
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected selected tensor bytes");
    expect(new TextDecoder().decode(await readAll(extracted.outputs.data.source))).toBe("FLAG");
  });
});