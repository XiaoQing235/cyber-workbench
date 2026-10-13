import fc from "fast-check";
import { describe, expect, it } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { inspectLuaBytecode, inspectLuaBytecodeHeader, MAX_LUA_CHUNK_BYTES } from "./luaBytecode";

const STRIPPED_HEX = [
  "1b4c7561540019930d0a1a0a0408087856000000000000000000000028774000",
  "80818101000486cf000000000101008001000045010200460100004701010080",
  "808180818101000284950000862f008606c8000200c700010080808080808080",
  "80808080",
].join("");
const strippedChunk = () => Uint8Array.from(STRIPPED_HEX.match(/../g)!, (pair) => Number.parseInt(pair, 16));

function chunk(): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(35);
  bytes.set([0x1b, 0x4c, 0x75, 0x61, 0x54, 0x00, 0x19, 0x93, 0x0d, 0x0a, 0x1a, 0x0a, 4, 8, 8, 0x78, 0x56]);
  new DataView(bytes.buffer).setFloat64(23, 370.5, true);
  bytes[31] = 1;
  bytes[32] = 1;
  return bytes;
}

describe("Lua 5.4 bytecode header", () => {
  it("walks compiled upvalues, strings, floats, and debug tables", async () => {
    const hex = [
      "1b4c7561540019930d0a1a0a0408087856000000000000000000000028774001",
      "8d40666978747572652e6c7561818101000587830000004f0100008001020000",
      "020000c5010200c6010000c70101008104846c75618101000081808181010002",
      "8789000000a40000012e00010896000100b0000006c8000200c7000100811300",
      "0000000000f43f8100000080870000000000000080818676616c756580878187",
      "666163746f728700000000000000808385736565648087866c6162656c818785",
      "7374657082878187666163746f72",
    ].join("");
    const data = Uint8Array.from(hex.match(/../g)!, (pair) => Number.parseInt(pair, 16));
    expect(data).toHaveLength(206);
    const report = await inspectLuaBytecode(new MemorySource(data));
    expect(report.prototypes.map((prototype) => prototype.path)).toEqual(["main", "main/0"]);
    expect(report.mainUpvalues).toBe(1);
    expect(report.prototypes[0].constantCount).toBe(1);
    expect(report.prototypes[1].constantCount).toBe(1);
    expect(report.executed).toBe(false);
  });

  it("recognizes a nested function compiled by Wasmoon Lua 5.4", async () => {
    const data = strippedChunk();
    expect(data).toHaveLength(100);
    expect(await inspectLuaBytecodeHeader(new MemorySource(data))).toMatchObject({
      version: "5.4", mainUpvalues: 0, bodyOffset: 32, bodyBytes: 68, executed: false,
    });
    const report = await inspectLuaBytecode(new MemorySource(data));
    expect(report.executed).toBe(false);
    expect(report.prototypes.map((prototype) => prototype.path)).toEqual(["main", "main/0"]);
    expect(report.prototypes[0]).toMatchObject({ parameters: 1, nestedCount: 1, instructionCount: 6 });
    expect(report.prototypes[1]).toMatchObject({ parameters: 1, nestedCount: 0, instructionCount: 4 });
  });

  it("identifies a bounded 64-bit little-endian chunk without running it", async () => {
    expect(await inspectLuaBytecodeHeader(new MemorySource(chunk()))).toEqual({
      version: "5.4", endianness: "little", instructionSize: 4, integerSize: 8, numberSize: 8,
      mainUpvalues: 1, bodyOffset: 32, bodyBytes: 3, executed: false,
    });
  });

  it("rejects truncated, foreign, and incompatible chunks", async () => {
    await expect(inspectLuaBytecodeHeader(new MemorySource(chunk().subarray(0, 32)))).rejects.toThrow(/truncated/);
    for (const [index, value] of [[4, 0x53], [12, 8], [15, 0], [30, 0]] as const) {
      const bytes = chunk();
      bytes[index] = value;
      await expect(inspectLuaBytecodeHeader(new MemorySource(bytes))).rejects.toThrow(/Lua bytecode|Unsupported/);
    }
  });

  it("rejects forged section lengths, mismatched upvalues, trailing data, and over-budget input", async () => {
    for (const invalid of [
      strippedChunk().subarray(0, 99),
      Uint8Array.from([...strippedChunk(), 0]),
      Uint8Array.from(strippedChunk(), (byte, index) => index === 31 ? 1 : byte),
      Uint8Array.from(strippedChunk(), (byte, index) => index === 38 ? 0xff : byte),
    ]) {
      await expect(inspectLuaBytecode(new MemorySource(invalid))).rejects.toThrow(/Lua bytecode/);
    }
    await expect(inspectLuaBytecode(new MemorySource(new Uint8Array(MAX_LUA_CHUNK_BYTES + 1)))).rejects.toThrow(/8 MiB/);
  });

  it("rejects every truncation of the compiled chunk and handles arbitrary short bodies", async () => {
    const original = strippedChunk();
    for (let end = 32; end < original.length; end++) {
      await expect(inspectLuaBytecode(new MemorySource(original.subarray(0, end)))).rejects.toThrow();
    }
    await fc.assert(fc.asyncProperty(fc.uint8Array({ maxLength: 256 }), async (body) => {
      const bytes = new Uint8Array(32 + body.length);
      bytes.set(original.subarray(0, 32));
      bytes.set(body, 32);
      let report;
      try {
        report = await inspectLuaBytecode(new MemorySource(bytes));
      } catch (error) {
        expect(error).toBeInstanceOf(Error);
        return;
      }
      expect(report.executed).toBe(false);
      expect(report.prototypes.length).toBeLessThanOrEqual(512);
    }), { numRuns: 64 });
  });

  it("exposes static function and opcode metadata through the Reverse operation", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "reverse.lua.bytecode.inspect", inputs: { data: bytesValue(new MemorySource(strippedChunk())) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { executed: false, totalInstructions: 10 } });
  });
});