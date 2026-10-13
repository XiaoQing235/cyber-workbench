import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { planFormatWrites } from "./formatString";

describe("bounded positional printf write planning", () => {
  it("produces correct modulo-256 counts for reordered little-endian bytes", () => {
    const result = planFormatWrites("0x404040", "0x0010ff10", 4, 2, 1, 10);
    expect(result.format).toBe("%1$6c%2$hhn%4$hhn%1$239c%3$hhn%1$1c%5$hhn");
    expect(result.writes.map(({ byteOffset, address, value, printed }) => ({ byteOffset, address, value, printed }))).toEqual([
      { byteOffset: 0, address: "0x404040", value: 16, printed: 16 },
      { byteOffset: 2, address: "0x404042", value: 16, printed: 16 },
      { byteOffset: 1, address: "0x404041", value: 255, printed: 255 },
      { byteOffset: 3, address: "0x404043", value: 0, printed: 256 },
    ]);
    expect(result).toMatchObject({ totalPrinted: 256, pointerArgumentsRequired: [2, 3, 4, 5], paddingArgument: 1, addressesEmbedded: false });
    for (const write of result.writes) expect(write.printed % 256).toBe(write.value);
  });

  it("handles a zero delta without a fake %0c and wraps an initial printed count", () => {
    expect(planFormatWrites("0x0", "0x0", 1, 2, 1, 0).format).toBe("%2$hhn");
    expect(planFormatWrites("0x0", "0x1", 1, 2, 1, 255).format).toBe("%1$2c%2$hhn");
    expect(planFormatWrites("0x0", "0x1", 1, 2, 1, 0).format).toBe("%1$1c%2$hhn");
    expect(planFormatWrites("0x0", "0x1", 1, 2, 1, 0).writes[0].printed).toBe(1);
  });

  it("plans aligned non-overlapping little-endian halfwords modulo 65536", () => {
    const plan = planFormatWrites("0x404040", "0x0010ff10", 4, 2, 1, 10, 2);
    expect(plan).toMatchObject({ format: "%1$6c%3$hn%1$65280c%2$hn", totalPrinted: 65296,
      writeWidthBytes: 2, pointerArgumentsRequired: [2, 3], addressesEmbedded: false,
      writes: [{ byteOffset: 2, address: "0x404042", value: 16, argument: 3, printed: 16 },
        { byteOffset: 0, address: "0x404040", value: 65296, argument: 2, printed: 65296 }] });
    expect(plan.writes.every((write) => write.printed % 65536 === write.value)).toBe(true);
    expect(plan.writes.map((write) => write.address)).toEqual(["0x404042", "0x404040"]);
    expect(planFormatWrites("0x1000", "0x0", 2, 2, 1, 0, 2).format).toBe("%2$hn");
    expect(() => planFormatWrites("0x1001", "0x1", 2, 2, 1, 0, 2)).toThrow(/aligned/);
    expect(() => planFormatWrites("0x1000", "0x1", 3, 2, 1, 0, 2)).toThrow(/bounds/);
    expect(() => planFormatWrites("0x1000", "0x10000", 2, 2, 1, 0, 2)).toThrow(/fit/);
  });

  it("rejects wrapped addresses, truncated values and overlapping positional arguments", () => {
    expect(() => planFormatWrites("0xffffffffffffffff", "0x1234", 2, 7, 1, 0)).toThrow(/wraps/);
    expect(() => planFormatWrites("0x10", "0x100", 1, 7, 1, 0)).toThrow(/fit/);
    expect(() => planFormatWrites("0x10", "0x1", 1, 7, 7, 0)).toThrow(/bounds/);
    expect(() => planFormatWrites("0x10", "0x1", 1, 7, 1, 0)).toThrow(/starting at 2/);
    expect(() => planFormatWrites("0x10", "-1", 1, 7, 1, 0)).toThrow(/hexadecimal/);
  });

  it("makes the plan available as a provenance-tracked operation", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "reverse.format-string.writes", inputs: { data: bytesFrom(Uint8Array.of(0x90, 0xc3)) },
      params: { address: "0x404040", value: "0x10", byteCount: 1, firstArgument: 2, paddingArgument: 1, alreadyPrinted: 0 },
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { format: "%1$16c%2$hhn", addressesEmbedded: false } });
    const halfword = await executeOperation(createDefaultRegistry(), { operationId: "reverse.format-string.writes",
      inputs: { data: bytesFrom(Uint8Array.of(0x90, 0xc3)) },
      params: { address: "0x404040", value: "0x10", byteCount: 2, writeWidthBytes: 2 } });
    expect(halfword.outputs.report).toMatchObject({ type: "structured", data: { format: "%1$16c%2$hn", writeWidthBytes: 2 } });
  });
});
