import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { compareGifFrames, compositeGifFrameRgba, exportGifFramePng, extractGifFrameRgba, gifFrameTimeline, inspectGifFrames } from "./gifFrames";
import { decodePng } from "./png/decode";
import { parsePng } from "./png/parse";

const GIF = Uint8Array.from(atob("R0lGODlhAgACAIEAAP8AAAD/AAAA/wAAACH/C05FVFNDQVBFMi4wAwEAAAAh+QQFCgACACwAAAAAAgACAAAIBwABBBAAICAAIfkECRkAAgAsAAAAAAIAAgCB/wAAAP8AAAD/AAAACAcABQgAICAgADs="), (character) => character.charCodeAt(0));
const DISPOSAL_GIF = Uint8Array.from(atob("R0lGODlhAwADAIEAAP8AAAAAAAAAAAAAACH/C05FVFNDQVBFMi4wAwEAAAAh+QQECgAAACwAAAAAAwADAAAIBwABCBw4MCAAIfkECRQAAQAsAAAAAAMAAwCBAP8AAAAAAAAAAAAACAkAAwgMAGBggIAAIfkEDR4AAQAsAgACAAEAAQCBAAD/AAAAAAAAAAAACAQAAQQEACH5BAUoAAEALAAAAAADAAMAgQD/AAAAAAAAAAAAAAgIAAEEGEhwYEAAOw=="), (character) => character.charCodeAt(0));

describe("animated GIF frame forensics", () => {
  it("inspects a real two-frame GIF without compositing away its palette metadata", async () => {
    const report = await inspectGifFrames(new MemorySource(GIF));
    expect(report).toMatchObject({
      version: "89a", width: 2, height: 2, frameCount: 2,
      frames: [
        { delayMs: 100, disposal: 1, transparentIndex: 2, transparentRgb: [0, 0, 255], left: 0, top: 0 },
        { delayMs: 250, disposal: 2, transparentIndex: 2, transparentRgb: [0, 0, 255], left: 0, top: 0 },
      ],
    });
  });

  it("preserves cumulative GIF frame delays for animation timing analysis", async () => {
    const report = await gifFrameTimeline(new MemorySource(GIF));
    expect(report).toEqual({ frames: [{ index: 0, startMs: 0, delayMs: 100, disposal: 1 },
      { index: 1, startMs: 100, delayMs: 250, disposal: 2 }], durationMs: 350 });
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "image.gif.frames.timeline",
      inputs: { data: bytesFrom(GIF) }, params: {} });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: { durationMs: 350 } });
  });

  it("reveals hidden blue RGB in an otherwise transparent frame pixel", async () => {
    const source = new MemorySource(GIF);
    const visible = await extractGifFrameRgba(source, 0, false);
    const revealed = await extractGifFrameRgba(source, 0, true);
    expect(visible.transparentPixels).toBe(1);
    expect(Array.from(visible.rgba.subarray(8, 12))).toEqual([0, 0, 255, 0]);
    expect(Array.from(revealed.rgba.subarray(8, 12))).toEqual([0, 0, 255, 255]);
    expect(Array.from(revealed.rgba.subarray(0, 8))).toEqual([255, 0, 0, 255, 0, 255, 0, 255]);
  });

  it("exports byte-exact hidden RGB as a valid PNG for downstream analysis", async () => {
    const result = await exportGifFramePng(new MemorySource(GIF), 0, false);
    const source = new MemorySource(result.png);
    const parsed = await parsePng(source);
    expect(parsed.findings).toEqual([]);
    expect(parsed.ihdr).toMatchObject({ width: 2, height: 2, colorType: 6, bitDepth: 8 });
    const decoded = await decodePng(source, parsed);
    expect(Array.from(decoded.image.samples.slice(8, 12))).toEqual([0, 0, 255, 0]);
  });

  it("composites the second frame over visible earlier pixels", async () => {
    const { rgba } = await compositeGifFrameRgba(new MemorySource(GIF), 1, "palette");
    expect(Array.from(rgba)).toEqual([
      255, 0, 0, 255, 0, 255, 0, 255,
      255, 0, 0, 255, 255, 0, 0, 255,
    ]);
    const transparent = await compositeGifFrameRgba(new MemorySource(GIF), 0, "transparent");
    expect(Array.from(transparent.rgba.subarray(8, 12))).toEqual([0, 0, 0, 0]);
  });

  it("restores background and previous pixels around cropped frames", async () => {
    const source = new MemorySource(DISPOSAL_GIF);
    const second = await compositeGifFrameRgba(source, 1, "palette");
    const third = await compositeGifFrameRgba(source, 2, "palette");
    const fourth = await compositeGifFrameRgba(source, 3, "palette");
    expect(third.report.frames[2]).toMatchObject({ left: 2, top: 2, width: 1, height: 1, disposal: 3 });
    expect(Array.from(second.rgba.subarray(16, 20))).toEqual([0, 255, 0, 255]);
    expect(Array.from(third.rgba.subarray(16, 20))).toEqual([255, 0, 0, 255]);
    expect(Array.from(third.rgba.subarray(32, 36))).toEqual([0, 0, 255, 255]);
    expect(Array.from(fourth.rgba.subarray(0, 4))).toEqual([0, 255, 0, 255]);
    expect(Array.from(fourth.rgba.subarray(32, 36))).toEqual([255, 0, 0, 255]);
  });

  it("highlights only changed pixels across disposal-aware composites", async () => {
    const comparison = await compareGifFrames(new MemorySource(DISPOSAL_GIF), 1, 2, "difference", "palette");
    expect(comparison).toMatchObject({ width: 3, height: 3, changedPixels: 2 });
    const png = new MemorySource(comparison.png);
    const decoded = await decodePng(png, await parsePng(png));
    expect(Array.from(decoded.image.samples.slice(16, 20))).toEqual([255, 255, 0, 255]);
    expect(Array.from(decoded.image.samples.slice(32, 36))).toEqual([255, 0, 255, 255]);
    const xor = await compareGifFrames(new MemorySource(DISPOSAL_GIF), 1, 2, "xor", "palette");
    expect(xor.changedPixels).toBe(2);
  });

  it("rejects invalid frame indexes and oversized screen dimensions", async () => {
    await expect(extractGifFrameRgba(new MemorySource(GIF), 2, true)).rejects.toThrow(/does not exist/);
    const oversized = GIF.slice();
    oversized[6] = 0xff;
    oversized[7] = 0x7f;
    await expect(inspectGifFrames(new MemorySource(oversized))).rejects.toThrow(/pixel limit/);
  });

  it("exports a GIF frame as a downstream PNG artifact through the registry", async () => {
    const registry = createDefaultRegistry();
    const inspection = await executeOperation(registry, { operationId: "image.gif.frames.inspect", inputs: { data: bytesFrom(GIF) }, params: {} });
    expect(inspection.run.error).toBeUndefined();
    expect((inspection.outputs.report as { data: object }).data).toMatchObject({ frameCount: 2 });
    const exported = await executeOperation(registry, { operationId: "image.gif.frame.export", inputs: { data: bytesFrom(GIF) }, params: { frameIndex: 0, mode: "raw" } });
    expect(exported.run.error).toBeUndefined();
    expect((exported.outputs.report as { data: object }).data).toMatchObject({ transparentPixels: 1, mode: "raw", composited: false });
    const source = (exported.outputs.data as { source: Parameters<typeof readAll>[0] }).source;
    const png = new MemorySource(await readAll(source));
    const decoded = await decodePng(png, await parsePng(png));
    expect(Array.from(decoded.image.samples.slice(8, 12))).toEqual([0, 0, 255, 255]);
  });

  it("exports a disposal-aware composite as a PNG artifact", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "image.gif.frame.export", inputs: { data: bytesFrom(DISPOSAL_GIF) },
      params: { frameIndex: 3, mode: "composited", background: "palette" },
    });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: object }).data).toMatchObject({ mode: "composited", background: "palette", composited: true });
    const png = (result.outputs.data as { source: Parameters<typeof readAll>[0] }).source;
    const decoded = await decodePng(png, await parsePng(png));
    expect(Array.from(decoded.image.samples.slice(0, 4))).toEqual([0, 255, 0, 255]);
    expect(Array.from(decoded.image.samples.slice(32, 36))).toEqual([255, 0, 0, 255]);
  });

  it("exports a disposal-aware frame difference through the registry", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "image.gif.frames.compare", inputs: { data: bytesFrom(DISPOSAL_GIF) },
      params: { firstIndex: 1, secondIndex: 2, mode: "difference", background: "palette" },
    });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: object }).data).toMatchObject({ changedPixels: 2, mode: "difference", firstIndex: 1, secondIndex: 2 });
    expect(result.run.diagnostics).toEqual(["Compared GIF frames 1 and 2; 2 pixel(s) changed."]);
  });
});
