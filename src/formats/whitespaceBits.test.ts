import { describe, expect, it } from "vitest";
import { readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractWhitespaceBits } from "./whitespaceBits";

describe("whitespace steganography", () => {
  it("extracts an ASCII byte only from line-end spaces and tabs", () => {
    const text = ["word ", "inside text\t", "word ", "word ", "word ", "word ", "word ", "word\t"].join("\r\n");
    const { bytes, report } = extractWhitespaceBits(text, "line-end", "msb-first", 8);
    expect(new TextDecoder().decode(bytes)).toBe("A");
    expect(report).toMatchObject({ bits: 8, bytes: 1, leftoverBits: 0, truncated: false });
    expect(report.firstOffsets).toHaveLength(8);
    expect(Array.from(extractWhitespaceBits(text, "line-end", "lsb-first", 8).bytes)).toEqual([0x82]);
  });

  it("reads zero-width bit characters and respects the output budget", () => {
    const bits = "01000001".replace(/0/g, "\u200b").replace(/1/g, "\u200c");
    const result = extractWhitespaceBits(`plain${bits}text`, "zero-width", "msb-first", 1);
    expect(new TextDecoder().decode(result.bytes)).toBe("A");
    expect(result.report.firstOffsets).toEqual([5, 6, 7, 8, 9, 10, 11, 12]);
    const limited = extractWhitespaceBits(bits + "\u200b", "zero-width", "msb-first", 1);
    expect(limited.report).toMatchObject({ bits: 8, bytes: 1, truncated: true });
  });

  it("reports incomplete bytes without fabricating padding", () => {
    expect(extractWhitespaceBits("x\u200b\u200c", "zero-width", "msb-first", 10)).toMatchObject({ bytes: new Uint8Array(0), report: { bits: 2, leftoverBits: 2 } });
    expect(() => extractWhitespaceBits("x", "zero-width", "msb-first", 0)).toThrow(/output limit/);
  });

  it("returns a byte artifact and bit evidence through the registry", async () => {
    const bits = "01000001".replace(/0/g, "\u200b").replace(/1/g, "\u200c");
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "text.whitespace.extract", inputs: { text: textValue(`message${bits}`) },
      params: { mode: "zero-width", bitOrder: "msb-first", maxBytes: 64 },
    });
    expect(result.run.error).toBeUndefined();
    expect(new TextDecoder().decode(await readAll((result.outputs.data as { source: Parameters<typeof readAll>[0] }).source))).toBe("A");
    expect((result.outputs.report as { data: object }).data).toMatchObject({ bits: 8, bytes: 1, leftoverBits: 0 });
  });
});