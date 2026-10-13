import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { decodePng2 } from "./png2";
import { decodePng } from "./png/decode";
import { parsePng } from "./png/parse";
import { colorContrastCrop } from "./colorContrast";
import { decodeBmp, parseBmp } from "./bmp/bmp";

const reproduced = new Uint8Array(readFileSync(new URL("./testing/google-ctf-2023-reproduced.png2", import.meta.url)));

describe("Google CTF 2023 PNG2 image reconstruction", () => {
  it("matches every reference pixel recovered by the official decoder", async () => {
    const inputSha = createHash("sha256").update(reproduced).digest("hex");
    const generic = await executeOperation(createDefaultRegistry(), { operationId: "png.inspect", inputs: { data: bytesFrom(reproduced) }, params: {} });
    expect(generic.run.error).toBeUndefined();
    expect(generic.outputs.report).toMatchObject({ type: "structured", data: {
      ihdr: { width: 1024, height: 1024, filter: 0xc0, interlace: 0xde },
      findings: [{ id: "png.ihdr.methods" }],
    } });
    const { png, report } = await decodePng2(new MemorySource(reproduced));
    expect(report).toMatchObject({ width: 1024, height: 1024, inflatedBytes: 1024 * (1024 * 3 + 1), chunkCrcsValid: true, outputFormat: "PNG RGBA" });
    expect(Object.values(report.filterCounts).reduce((sum, count) => sum + count, 0)).toBe(1024);
    const decoded = await decodePng(new MemorySource(png), await parsePng(new MemorySource(png)));
    expect(decoded.warnings).toEqual([]);
    const rgba = decoded.image.samples;
    const rgb = new Uint8Array(1024 * 1024 * 3);
    for (let pixel = 0; pixel < 1024 * 1024; pixel++) rgb.set(rgba.subarray(pixel * 4, pixel * 4 + 3), pixel * 3);
    expect(createHash("sha256").update(rgb).digest("hex")).toBe("f14a58e5464f2f7d0d67e25d768200c652b1d7fd752d587c1eb5a1a57b089ffe");
    expect(Array.from(rgb.subarray(0, 3))).toEqual([205, 213, 232]);
    expect(Array.from(rgb.subarray(-3))).toEqual([241, 241, 241]);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "reverse.png2.decode", inputs: { data: bytesFrom(reproduced) }, params: {} });
    expect(operation.run.error).toBeUndefined();
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: { width: 1024, chunkCrcsValid: true } });
    if (operation.outputs.data?.type !== "bytes") throw new Error("Expected reconstructed PNG artifact");
    expect(await readAll(operation.outputs.data.source)).toEqual(png);
    expect(createHash("sha256").update(reproduced).digest("hex")).toBe(inputSha);
  });

  it("rejects a damaged PNG2 marker, invalid chunk CRC and missing file tail", async () => {
    const damaged = reproduced.slice();
    damaged[28] = 0;
    await expect(decodePng2(new MemorySource(damaged))).rejects.toThrow(/custom 8-bit RGB/);
    const altered = reproduced.slice();
    altered[45] ^= 1;
    await expect(decodePng2(new MemorySource(altered))).rejects.toThrow(/CRC-valid/);
    await expect(decodePng2(new MemorySource(reproduced.subarray(0, reproduced.length - 1)))).rejects.toThrow(/complete CRC-valid/);
  });

  it("isolates chromatic prefix pixels from the independently reconstructed PNG2", async () => {
    const { png } = await decodePng2(new MemorySource(reproduced));
    const source = new MemorySource(png);
    const crop = await colorContrastCrop(source, 320, 215, 390, 180, 120);
    expect(crop.coloredPixels).toBeGreaterThan(1_000);
    const bmp = new MemorySource(crop.image);
    expect((await decodeBmp(bmp, await parseBmp(bmp))).image).toMatchObject({ width: 390, height: 180 });
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "image.color-contrast.crop",
      inputs: { data: bytesFrom(png) }, params: { left: 320, top: 215, width: 390, height: 180, threshold: 120 } });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: {
      coloredPixels: crop.coloredPixels, width: 390, height: 180, textRecovered: false,
    } });
    if (operation.outputs.image?.type !== "bytes") throw new Error("Missing chromatic crop");
    expect(await readAll(operation.outputs.image.source)).toEqual(crop.image);
    await expect(colorContrastCrop(source, 1000, 1000, 390, 180, 120)).rejects.toThrow(/exceeds/);
    await expect(colorContrastCrop(source, 0, 0, 390, 180, 256)).rejects.toThrow(/bounds/);
  });

  it("never trusts randomly corrupted header or encoded stream bytes", async () => {
    await fc.assert(fc.asyncProperty(fc.integer({ min: 0, max: reproduced.length - 13 }),
      fc.integer({ min: 1, max: 255 }), async (offset, mask) => {
        const damaged = reproduced.slice();
        damaged[offset] ^= mask;
        await expect(decodePng2(new MemorySource(damaged))).rejects.toThrow();
      }), { seed: 20261012, numRuns: 24 });
  });
});
