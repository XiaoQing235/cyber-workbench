import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractPythonMarshal, inspectPythonBytecode } from "./pythonBytecode";

const header = (hex: string) => Uint8Array.from(hex.match(/../g)!, (pair) => Number.parseInt(pair, 16));
const pyc = (hex: string) => new MemorySource(Uint8Array.from([...header(hex), 0xe3, 0x00, 0x01]));

describe("Python bytecode envelope", () => {
  it("identifies independently generated Python 3.11, 3.12, and 3.13 hashes", async () => {
    const fixtures = [
      ["a70d0d0a0300000015e4a7ef85e79136", "3.11", "15e4a7ef85e79136"],
      ["cb0d0d0a0300000027ec82eeb9127688", "3.12", "27ec82eeb9127688"],
      ["f30d0d0a03000000f7c6e6b6cb76908b", "3.13", "f7c6e6b6cb76908b"],
    ];
    for (const [bytes, version, sourceHash] of fixtures) {
      expect(await inspectPythonBytecode(pyc(bytes))).toMatchObject({ pythonVersion: version, invalidation: "checked-hash", sourceHash, sourceSize: null, marshalOffset: 16, marshalBytes: 3, executed: false });
    }
  });

  it("parses the native 3.13 timestamp header and slices marshal bytes without running them", async () => {
    const input = pyc("f30d0d0a000000002762cb6a38000000");
    expect(await inspectPythonBytecode(input)).toMatchObject({ pythonVersion: "3.13", invalidation: "timestamp", sourceSize: 56, sourceHash: null });
    expect(await readAll(await extractPythonMarshal(input))).toEqual(Uint8Array.of(0xe3, 0x00, 0x01));
  });

  it("rejects unsupported magics, reserved flags, and truncated payloads", async () => {
    await expect(inspectPythonBytecode(pyc("01020d0a000000000000000000000000"))).rejects.toThrow(/Unsupported Python bytecode magic/);
    await expect(inspectPythonBytecode(pyc("f30d0d0a020000000000000000000000"))).rejects.toThrow(/invalidation flags/);
    await expect(inspectPythonBytecode(new MemorySource(header("f30d0d0a000000002762cb6a38000000")))).rejects.toThrow(/truncated/);
  });

  it("runs both static Reverse operations without executing the contained code", async () => {
    const registry = createDefaultRegistry();
    const data = bytesValue(pyc("f30d0d0a03000000f7c6e6b6cb76908b"));
    const inspected = await executeOperation(registry, { operationId: "reverse.python.pyc.inspect", inputs: { data }, params: {} });
    expect(inspected.run.status).toBe("success");
    expect(inspected.outputs.report).toMatchObject({ type: "structured", data: { executed: false, invalidation: "checked-hash" } });
    const extracted = await executeOperation(registry, { operationId: "reverse.python.pyc.marshal-extract", inputs: { data }, params: {} });
    expect(extracted.run.status).toBe("success");
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected marshal bytes");
    expect(await readAll(extracted.outputs.data.source)).toEqual(Uint8Array.of(0xe3, 0x00, 0x01));
  });
});