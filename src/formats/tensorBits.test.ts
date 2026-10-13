import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractTensorBits } from "./tensorBits";

function tensor(dtype: string, values: Uint8Array, elements: number): MemorySource {
  const header = new TextEncoder().encode(JSON.stringify({ bits: { dtype, shape: [elements], data_offsets: [0, values.length] } }));
  const bytes = new Uint8Array(8 + header.length + values.length);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(header.length), true);
  bytes.set(header, 8);
  bytes.set(values, 8 + header.length);
  return new MemorySource(bytes);
}

describe("bounded SafeTensors integer bit planes", () => {
  it("recovers bits per element from U8 and U16 with both packing orders", async () => {
    const values = Uint8Array.of(1, 0, 1, 0, 0, 0, 0, 1, 1);
    expect(await extractTensorBits(tensor("U8", values, 9), "bits", 0, "msb", 2)).toEqual({ data: Uint8Array.of(0xa1, 0x80), samples: 9 });
    expect((await extractTensorBits(tensor("U8", values, 9), "bits", 0, "lsb", 2)).data).toEqual(Uint8Array.of(0x85, 0x01));
    expect((await extractTensorBits(tensor("U16", Uint8Array.of(0x00, 0x80, 0x00, 0x00), 2), "bits", 15, "msb", 1)).data).toEqual(Uint8Array.of(0x80));
  });

  it("extracts raw float representation bits without interpreting numerical values", async () => {
    // IEEE-754 F32 little-endian 1.0 has exponent bit 29 set; 0.0 does not.
    const values = Uint8Array.of(0, 0, 0x80, 0x3f, 0, 0, 0, 0, 0, 0, 0x80, 0x3f);
    expect((await extractTensorBits(tensor("F32", values, 3), "bits", 29, "msb", 1)).data).toEqual(Uint8Array.of(0xa0));
  });

  it("rejects oversized extraction and out-of-width bits", async () => {
    await expect(extractTensorBits(tensor("U8", Uint8Array.of(1), 1), "bits", 8, "msb", 1)).rejects.toThrow(/dtype width/);
    await expect(extractTensorBits(tensor("U8", new Uint8Array(16), 16), "bits", 0, "msb", 1)).rejects.toThrow(/budget/);
  });

  it("returns an explicit candidate artifact through the shared registry", async () => {
    const result = await executeOperation(createDefaultRegistry(), { operationId: "forensics.model.safetensors.bits",
      inputs: { data: bytesValue(tensor("U8", Uint8Array.of(0, 1, 0, 0, 1, 0, 0, 0), 8)) },
      params: { name: "bits", bit: 0, bitOrder: "msb", maxOutputBytes: 1 } });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { samples: 8, verifiedPayload: false } });
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected extracted bytes");
    expect(await readAll(result.outputs.data.source)).toEqual(Uint8Array.of(0x48));
  });
});
