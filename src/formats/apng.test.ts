import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { crc32 } from "../core/checksum/crc32";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { compositeApngFramePng, extractApngFramePng, inspectApng } from "./apng";
import { decodePng } from "./png/decode";
import { parsePng } from "./png/parse";

const APNG = Uint8Array.from(atob("iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAYAAABytg0kAAAACGFjVEwAAAACAAAAAPONk3AAAAAaZmNUTAAAAAAAAAACAAAAAgAAAAAAAAAAAAEACgAA6FTcAAAAABVJREFUeJxj/M/A8J+BgYGBCUSAMAAfFwICAkezFAAAABpmY1RMAAAAAQAAAAIAAAACAAAAAAAAAAAAAQAEAQEXpRoJAAAAEmZkQVQAAAACeJxjYEAB/xkaAAOPAYAN5dWlAAAAAElFTkSuQmCC"), (character) => character.charCodeAt(0));
const DISPOSAL_APNG = Uint8Array.from(atob("iVBORw0KGgoAAAANSUhEUgAAAAMAAAADCAYAAABWKLW/AAAACGFjVEwAAAAEAAAAAHzNZtAAAAAaZmNUTAAAAAAAAAADAAAAAwAAAAAAAAAAAAEACgAAhk2HsAAAABVJREFUeNpj/M/A8J8BCpgYkAAKBwBJUwIEZMhTzwAAABpmY1RMAAAAAQAAAAMAAAADAAAAAAAAAAAAAQAFAQF4fiuOAAAAFWZkQVQAAAACeNpjYMAA/xn+Y4gBACYBAf+9U/DSAAAAGmZjVEwAAAADAAAAAQAAAAEAAAACAAAAAgADAAoCAdyYoHEAAAARZmRBVAAAAAR42mNgYPj/HwADAgH/0uf8cQAAABpmY1RMAAAABQAAAAIAAAACAAAAAAAAAAAAAgAFAAFIgJo8AAAAFGZkQVQAAAAGeNpjYPjP8J8BGQAAHfQB/4H7pGMAAAAASUVORK5CYII="), (character) => character.charCodeAt(0));

describe("APNG frame metadata", () => {
  it("inspects real Pillow-produced animation controls and frame data", async () => {
    expect(await inspectApng(new MemorySource(APNG))).toEqual({
      width: 2, height: 2, plays: 0, frameCount: 2,
      frames: [
        { index: 0, width: 2, height: 2, left: 0, top: 0, delayMs: 100, disposal: 0, blend: 0, compressedBytes: 21 },
        { index: 1, width: 2, height: 2, left: 0, top: 0, delayMs: 250, disposal: 1, blend: 1, compressedBytes: 14 },
      ],
    });
  });

  it("rejects a bad animation CRC and a truncated animation", async () => {
    const damaged = APNG.slice();
    damaged[44] ^= 1;
    await expect(inspectApng(new MemorySource(damaged))).rejects.toThrow(/failed CRC\/structure/);
    await expect(inspectApng(new MemorySource(APNG.slice(0, -1)))).rejects.toThrow(/incomplete/);
  });

  it("exports both controlled zlib streams as standalone RGBA PNGs", async () => {
    const first = await extractApngFramePng(new MemorySource(APNG), 0);
    const second = await extractApngFramePng(new MemorySource(APNG), 1);
    expect(first.report.frameCount).toBe(2);
    const firstPng = new MemorySource(first.png);
    const secondPng = new MemorySource(second.png);
    const firstDecoded = await decodePng(firstPng, await parsePng(firstPng));
    const secondDecoded = await decodePng(secondPng, await parsePng(secondPng));
    expect(Array.from(firstDecoded.image.samples.slice(0, 4))).toEqual([255, 0, 0, 255]);
    expect(Array.from(secondDecoded.image.samples.slice(12, 16))).toEqual([0, 255, 0, 128]);
    await expect(extractApngFramePng(new MemorySource(APNG), 2)).rejects.toThrow(/does not exist/);
  });

  it("composites semi-transparent green over opaque red using APNG source-over", async () => {
    const result = await compositeApngFramePng(new MemorySource(APNG), 1);
    const png = new MemorySource(result.png);
    const decoded = await decodePng(png, await parsePng(png));
    expect(Array.from(decoded.image.samples.slice(0, 4))).toEqual([255, 0, 0, 255]);
    expect(Array.from(decoded.image.samples.slice(12, 16))).toEqual([127, 128, 0, 255]);
  });

  it("clears background then restores the previous canvas around cropped frames", async () => {
    const source = new MemorySource(DISPOSAL_APNG);
    const third = await compositeApngFramePng(source, 2);
    const fourth = await compositeApngFramePng(source, 3);
    expect(third.report.frames[2]).toMatchObject({ left: 2, top: 2, width: 1, height: 1, disposal: 2 });
    const thirdPng = new MemorySource(third.png);
    const fourthPng = new MemorySource(fourth.png);
    const thirdImage = await decodePng(thirdPng, await parsePng(thirdPng));
    const fourthImage = await decodePng(fourthPng, await parsePng(fourthPng));
    expect(Array.from(thirdImage.image.samples.slice(0, 4))).toEqual([0, 0, 0, 0]);
    expect(Array.from(thirdImage.image.samples.slice(32, 36))).toEqual([0, 0, 255, 255]);
    expect(Array.from(fourthImage.image.samples.slice(0, 4))).toEqual([0, 255, 0, 255]);
    expect(Array.from(fourthImage.image.samples.slice(32, 36))).toEqual([0, 0, 0, 0]);
  });

  it("rejects an APNG sequence gap even when the chunk CRC is repaired", async () => {
    const damaged = APNG.slice();
    const structure = await parsePng(new MemorySource(damaged));
    const secondControl = structure.chunks.filter((chunk) => chunk.type === "fcTL")[1];
    damaged[secondControl.offset + 11] = 9;
    new DataView(damaged.buffer).setUint32(secondControl.offset + 8 + secondControl.length, crc32(damaged.subarray(secondControl.offset + 4, secondControl.offset + 8 + secondControl.length)));
    await expect(inspectApng(new MemorySource(damaged))).rejects.toThrow(/sequence number is invalid/);
  });

  it("exposes inspected controls and an uncomposited frame artifact through the registry", async () => {
    const registry = createDefaultRegistry();
    const inspection = await executeOperation(registry, { operationId: "image.apng.frames.inspect", inputs: { data: bytesFrom(APNG) }, params: {} });
    expect(inspection.run.error).toBeUndefined();
    expect((inspection.outputs.report as { data: object }).data).toMatchObject({ frameCount: 2 });
    const exported = await executeOperation(registry, { operationId: "image.apng.frame.export", inputs: { data: bytesFrom(APNG) }, params: { frameIndex: 1 } });
    expect(exported.run.error).toBeUndefined();
    expect((exported.outputs.report as { data: object }).data).toMatchObject({ frame: { index: 1, blend: 1, disposal: 1 }, composited: false });
    const png = new MemorySource(await readAll((exported.outputs.data as { source: Parameters<typeof readAll>[0] }).source));
    const decoded = await decodePng(png, await parsePng(png));
    expect(Array.from(decoded.image.samples.slice(12, 16))).toEqual([0, 255, 0, 128]);
    const composited = await executeOperation(registry, { operationId: "image.apng.frame.export", inputs: { data: bytesFrom(APNG) }, params: { frameIndex: 1, mode: "composited" } });
    expect(composited.run.error).toBeUndefined();
    expect((composited.outputs.report as { data: object }).data).toMatchObject({ composited: true });
    const compositedPng = (composited.outputs.data as { source: Parameters<typeof readAll>[0] }).source;
    const composed = await decodePng(compositedPng, await parsePng(compositedPng));
    expect(Array.from(composed.image.samples.slice(12, 16))).toEqual([127, 128, 0, 255]);
  });
});