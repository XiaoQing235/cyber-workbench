import { describe, expect, it } from "vitest";
import type { ByteSource } from "../core/bytes/ByteSource";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractIl2CppLiteral, inspectIl2Cpp, readIl2CppStringLiterals } from "./il2cpp";

function metadata(): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(512);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0xfab11baf, true);
  view.setUint32(4, 29, true);
  view.setUint32(8, 256, true);
  view.setUint32(12, 16, true);
  view.setUint32(16, 272, true);
  view.setUint32(20, 24, true);
  view.setUint32(24, 296, true);
  view.setUint32(28, 32, true);
  view.setUint32(256, 5, true);
  view.setUint32(260, 0, true);
  view.setUint32(264, 5, true);
  view.setUint32(268, 5, true);
  bytes.set(new TextEncoder().encode("HelloWORLD"), 272);
  return bytes;
}

describe("bounded Unity IL2CPP header inventory", () => {
  it("reads only the metadata directory even when the source is large", async () => {
    const bytes = metadata();
    let readBytes = 0;
    const source: ByteSource = { size: 100 * 1024 * 1024,
      async read(offset, length) { readBytes += length; return bytes.slice(offset, offset + length); },
      stream() { throw new Error("Expected a range-only read"); } };
    expect(await inspectIl2Cpp(source)).toMatchObject({ version: 29, stringLiterals: { offset: 256, bytes: 16 },
      stringLiteralData: { offset: 272, bytes: 24 }, strings: { offset: 296, bytes: 32 }, metadataExecuted: false, dataDecoded: false });
    expect(readBytes).toBe(256);
    const result = await executeOperation(createDefaultRegistry(), { operationId: "reverse.il2cpp.inspect",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: {} });
    expect(result.run.status).toBe("success");
  });

  it("rejects unknown versions, malformed offsets and overlapping sections", async () => {
    const version = metadata(); new DataView(version.buffer).setUint32(4, 99, true);
    await expect(inspectIl2Cpp(new MemorySource(version))).rejects.toThrow(/unsupported/);
    const offset = metadata(); new DataView(offset.buffer).setUint32(8, 1, true);
    await expect(inspectIl2Cpp(new MemorySource(offset))).rejects.toThrow(/directory/);
    const overlap = metadata(); new DataView(overlap.buffer).setUint32(16, 260, true);
    await expect(inspectIl2Cpp(new MemorySource(overlap))).rejects.toThrow(/overlap/);
  });

  it("reads selected UTF-8 literal entries while bounding count and offsets", async () => {
    const source = new MemorySource(metadata());
    expect(await readIl2CppStringLiterals(source, 1)).toEqual({ total: 2, truncated: true,
      literals: [{ index: 0, offset: 272, bytes: 5, text: "Hello" }] });
    const result = await executeOperation(createDefaultRegistry(), { operationId: "reverse.il2cpp.literals",
      inputs: { data: bytesValue(source) }, params: { maxLiterals: 2 } });
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { total: 2, literals: [{ text: "Hello" }, { text: "WORLD" }] } });
    const corrupt = metadata(); new DataView(corrupt.buffer).setUint32(260, 999, true);
    await expect(readIl2CppStringLiterals(new MemorySource(corrupt), 1)).rejects.toThrow(/exceeds its data section/);
    const invalidUtf8 = metadata(); invalidUtf8[272] = 0xff;
    await expect(readIl2CppStringLiterals(new MemorySource(invalidUtf8), 1)).rejects.toThrow();
  });

  it("extracts exact literal bytes separately from UTF-8 interpretation", async () => {
    const bytes = metadata(); bytes[272] = 0xff;
    const source = new MemorySource(bytes);
    expect(await readAll(await extractIl2CppLiteral(source, 0))).toEqual(Uint8Array.of(0xff, 101, 108, 108, 111));
    await expect(readIl2CppStringLiterals(source, 1)).rejects.toThrow();
    await expect(extractIl2CppLiteral(source, 2)).rejects.toThrow(/outside the table/);
    const result = await executeOperation(createDefaultRegistry(), { operationId: "reverse.il2cpp.literal-extract",
      inputs: { data: bytesValue(source) }, params: { index: 0 } });
    expect(result.run.status).toBe("success");
  });
});
