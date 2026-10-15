import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { encodeBmp24 } from "./bmp/encode";
import { decodeImage } from "./decode";
import { decodePng2 } from "./png2";
import { colorContrastStrip } from "./colorContrast";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";

describe("chromatic text strip evidence", () => {
  it("orders regions by row and column and keeps absolute source coordinates", async () => {
    const pixels = new Uint8Array(40 * 30 * 3).fill(255);
    for (const [left, top] of [[4, 3], [20, 3], [8, 20]]) {
      for (let y = top; y < top + 4; y++) for (let x = left; x < left + 3; x++) {
        pixels.set([255, 0, 0], (y * 40 + x) * 3);
      }
    }
    const original = encodeBmp24(40, 30, pixels);
    const before = original.slice();
    const result = await colorContrastStrip(new MemorySource(original), 2, 1, 30, 25, 120);
    expect(result.regions).toEqual([
      { left: 4, top: 3, width: 3, height: 4 },
      { left: 20, top: 3, width: 3, height: 4 },
      { left: 8, top: 20, width: 3, height: 4 },
    ]);
    expect((await decodeImage(new MemorySource(result.image))).image).toMatchObject({ width: 59, height: 64 });
    expect(original).toEqual(before);
    const operation = await executeOperation(createDefaultRegistry(), {
      operationId: "image.color-contrast.text-strip", inputs: { data: bytesFrom(original) },
      params: { left: 2, top: 1, width: 30, height: 25, threshold: 120 },
    });
    expect(operation.run.status).toBe("success");
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: { regions: result.regions, textRecovered: false } });
  });

  it("rejects empty masks, invalid bounds and cancellation", async () => {
    const source = new MemorySource(encodeBmp24(10, 10, new Uint8Array(300).fill(255)));
    await expect(colorContrastStrip(source, 0, 0, 10, 10, 120)).rejects.toThrow(/1–256/);
    await expect(colorContrastStrip(source, 0, 0, 11, 10, 120)).rejects.toThrow(/intact image/);
    await expect(colorContrastStrip(source, 0, 0, 10, 10, 0)).rejects.toThrow(/invalid/);
    const controller = new AbortController(); controller.abort(new Error("cancelled"));
    await expect(colorContrastStrip(source, 0, 0, 10, 10, 120, controller.signal)).rejects.toThrow();
  });

  it("scales tall regions proportionally rather than squashing their glyphs", async () => {
    const pixels = new Uint8Array(30 * 70 * 3).fill(255);
    for (let y = 5; y < 65; y++) for (let x = 5; x < 17; x++) pixels.set([255, 0, 0], (y * 30 + x) * 3);
    const result = await colorContrastStrip(new MemorySource(encodeBmp24(30, 70, pixels)), 0, 0, 30, 70, 120);
    expect(result.regions).toEqual([{ left: 5, top: 5, width: 12, height: 60 }]);
    const { image } = await decodeImage(new MemorySource(result.image));
    expect(image).toMatchObject({ width: 24, height: 64 });
  });

  it("rejects more than 256 regions before allocating the output strip", async () => {
    const pixels = new Uint8Array(800 * 3).fill(255);
    for (let x = 0; x < 800; x += 3) pixels.set([255, 0, 0], x * 3);
    await expect(colorContrastStrip(new MemorySource(encodeBmp24(800, 1, pixels)), 0, 0, 800, 1, 120))
      .rejects.toThrow(/1–256/);
  });

  it("extracts scattered coloured regions from independently reproduced PNG2 pixels", async () => {
    const original = new Uint8Array(readFileSync(new URL("./testing/google-ctf-2023-reproduced.png2", import.meta.url)));
    const { png } = await decodePng2(new MemorySource(original));
    const result = await colorContrastStrip(new MemorySource(png), 0, 410, 1024, 320, 60);
    expect(result.regions.length).toBeGreaterThan(20);
    expect(result.regions).toContainEqual({ left: 524, top: 423, width: 7, height: 9 });
    expect((await decodeImage(new MemorySource(result.image))).image.height).toBe(64);
  }, 30_000);
});
