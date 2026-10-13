import { describe, expect, it } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractDotNetString, inspectDotNet } from "./dotnet";

function assembly(): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(1024);
  const view = new DataView(bytes.buffer);
  const put = (at: number, value: string) => bytes.set(new TextEncoder().encode(value), at);
  put(0, "MZ"); view.setUint32(0x3c, 0x80, true);
  put(0x80, "PE\0\0"); view.setUint16(0x84, 0x14c, true);
  view.setUint16(0x86, 1, true); view.setUint16(0x94, 0xe0, true);
  const optional = 0x98;
  view.setUint16(optional, 0x10b, true);
  view.setUint32(optional + 92, 16, true);
  view.setUint32(optional + 96 + 14 * 8, 0x1000, true);
  view.setUint32(optional + 96 + 14 * 8 + 4, 72, true);
  const section = optional + 0xe0;
  put(section, ".text");
  view.setUint32(section + 8, 512, true);
  view.setUint32(section + 12, 0x1000, true);
  view.setUint32(section + 16, 512, true);
  view.setUint32(section + 20, 512, true);
  const clr = 512;
  view.setUint32(clr, 72, true);
  view.setUint16(clr + 4, 2, true);
  view.setUint16(clr + 6, 5, true);
  view.setUint32(clr + 8, 0x1080, true);
  view.setUint32(clr + 12, 192, true);
  view.setUint32(clr + 20, 0x06000001, true);
  const metadata = 640;
  put(metadata, "BSJB");
  view.setUint16(metadata + 4, 1, true);
  view.setUint32(metadata + 12, 12, true);
  put(metadata + 16, "v4.0.30319\0");
  view.setUint16(metadata + 30, 2, true);
  view.setUint32(metadata + 32, 80, true);
  view.setUint32(metadata + 36, 64, true);
  put(metadata + 40, "#~\0");
  view.setUint32(metadata + 44, 144, true);
  view.setUint32(metadata + 48, 16, true);
  put(metadata + 52, "#Strings\0");
  const tables = metadata + 80;
  view.setUint8(tables + 7, 1);
  view.setUint8(tables + 4, 2);
  view.setUint8(tables + 5, 0);
  view.setBigUint64(tables + 8, 1n | (1n << 2n) | (1n << 6n) | (1n << 32n), true);
  view.setBigUint64(tables + 16, 1n << 2n, true);
  view.setUint32(tables + 24, 1, true);
  view.setUint32(tables + 28, 3, true);
  view.setUint32(tables + 32, 7, true);
  view.setUint32(tables + 36, 1, true);
  view.setUint16(tables + 40, 0, true);
  view.setUint16(tables + 42, 1, true);
  put(metadata + 145, "Hello\0");
  return bytes;
}

describe("bounded static PE/CLR inspection", () => {
  it("reports CLR version and stream ranges without executing the assembly", async () => {
    const report = await inspectDotNet(new MemorySource(assembly()));
    expect(report).toMatchObject({ format: "PE/CLR", machine: 0x14c, pe32Plus: false, runtime: { major: 2, minor: 5 },
      metadataVersion: "v4.0.30319", entryPointToken: "0x06000001", assemblyExecuted: false,
      streams: [{ name: "#~", size: 64, offset: 80 }, { name: "#Strings", size: 16, offset: 144 }],
      tables: { stream: "#~", version: "2.0", validMask: "0x0000000100000045", sortedMask: "0x0000000000000004",
        rows: [{ id: 0, name: "Module", count: 1 }, { id: 2, name: "TypeDef", count: 3 }, { id: 6, name: "MethodDef", count: 7 }, { id: 32, name: "Assembly", count: 1 }], moduleName: "Hello", rowsDecoded: false } });
    const result = await executeOperation(createDefaultRegistry(), { operationId: "reverse.dotnet.inspect",
      inputs: { data: bytesValue(new MemorySource(assembly())) }, params: {} });
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { assemblyExecuted: false } });
  });

  it("rejects invalid directory pointers and metadata stream extents", async () => {
    const missingClr = assembly(); new DataView(missingClr.buffer).setUint32(0x98 + 96 + 14 * 8, 0, true);
    await expect(inspectDotNet(new MemorySource(missingClr))).rejects.toThrow(/CLR directory/);
    const badStream = assembly(); new DataView(badStream.buffer).setUint32(640 + 32, 191, true);
    await expect(inspectDotNet(new MemorySource(badStream))).rejects.toThrow(/stream name or extent/);
    const badSignature = assembly(); badSignature[640] ^= 1;
    await expect(inspectDotNet(new MemorySource(badSignature))).rejects.toThrow(/BSJB/);
  });

  it("rejects truncated or inconsistent table row directories", async () => {
    const truncated = assembly();
    new DataView(truncated.buffer).setUint32(640 + 36, 32, true);
    await expect(inspectDotNet(new MemorySource(truncated))).rejects.toThrow(/row-count directory is truncated/);
    const invalidMask = assembly();
    new DataView(invalidMask.buffer).setBigUint64(640 + 80 + 16, 1n << 10n, true);
    await expect(inspectDotNet(new MemorySource(invalidMask))).rejects.toThrow(/sorted table mask/);
    const oversized = assembly();
    new DataView(oversized.buffer).setUint32(640 + 80 + 24, 1_000_001, true);
    await expect(inspectDotNet(new MemorySource(oversized))).rejects.toThrow(/row budget/);
    const badModule = assembly();
    new DataView(badModule.buffer).setUint16(640 + 80 + 42, 1024, true);
    await expect(inspectDotNet(new MemorySource(badModule))).rejects.toThrow(/Module name offset/);
  });

  it("extracts one explicit heap string while rejecting zero, out-of-range and unterminated entries", async () => {
    const source = new MemorySource(assembly());
    expect(await extractDotNetString(source, 1)).toBe("Hello");
    const result = await executeOperation(createDefaultRegistry(), { operationId: "reverse.dotnet.string",
      inputs: { data: bytesValue(source) }, params: { offset: 1 } });
    expect(result.outputs.text).toMatchObject({ type: "text", text: "Hello" });
    await expect(extractDotNetString(source, 0)).rejects.toThrow(/positive/);
    await expect(extractDotNetString(source, 16)).rejects.toThrow(/not present/);
    const unterminated = assembly(); unterminated.fill(0x41, 640 + 144, 640 + 160);
    await expect(extractDotNetString(new MemorySource(unterminated), 1)).rejects.toThrow(/unterminated/);
  });
});
