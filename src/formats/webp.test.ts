import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractAnimatedWebpFrame, inspectAnimatedWebp } from "./webp";

const animation = new Uint8Array(readFileSync(new URL("./testing/animated-pillow.webp", import.meta.url)));
const lossyAnimation = new Uint8Array(readFileSync(new URL("./testing/animated-pillow-lossy.webp", import.meta.url)));

describe("animated WebP frame forensics", () => {
  it("inspects an independently encoded Pillow animation", async () => {
    expect(await inspectAnimatedWebp(new MemorySource(animation))).toMatchObject({ width: 4, height: 4, plays: 2, frameCount: 2, frames: [
      { index: 0, left: 0, top: 0, width: 4, height: 4, durationMs: 100, blend: "source", dispose: "none", encoding: "VP8L", encodedBytes: 24 },
      { index: 1, left: 0, top: 0, width: 4, height: 4, durationMs: 250, blend: "source", dispose: "none", encoding: "VP8L", encodedBytes: 26 },
    ] });
  });

  it("exports a bounded uncomposited frame as a standalone RIFF WebP", async () => {
    const { webp, frame } = await extractAnimatedWebpFrame(new MemorySource(animation), 1);
    expect(frame).toMatchObject({ index: 1, durationMs: 250, width: 4, height: 4 });
    expect(new TextDecoder().decode(webp.subarray(0, 4))).toBe("RIFF");
    expect(new TextDecoder().decode(webp.subarray(8, 12))).toBe("WEBP");
    expect(new DataView(webp.buffer).getUint32(4, true)).toBe(webp.length - 8);
    expect(new TextDecoder().decode(webp.subarray(30, 34))).toBe("VP8L");
    const inspected = await executeOperation(createDefaultRegistry(), { operationId: "image.webp.frames.inspect", inputs: { data: bytesFrom(animation) }, params: {} });
    expect(inspected.outputs.report).toMatchObject({ type: "structured", data: { frameCount: 2 } });
    const exported = await executeOperation(createDefaultRegistry(), { operationId: "image.webp.frame.export", inputs: { data: bytesFrom(animation) }, params: { frameIndex: 1 } });
    expect(exported.run.error).toBeUndefined();
    if (exported.outputs.data?.type !== "bytes") throw new Error("Expected raw WebP frame bytes");
    expect(await readAll(exported.outputs.data.source)).toEqual(webp);
  });

  it("keeps lossy VP8 frames and separate ALPH chunks together", async () => {
    const report = await inspectAnimatedWebp(new MemorySource(lossyAnimation));
    expect(report).toMatchObject({ width: 6, height: 4, plays: 1, frameCount: 2, frames: [
      { durationMs: 120, encoding: "VP8", alpha: false, encodedBytes: 60 },
      { durationMs: 300, encoding: "VP8", alpha: true, encodedBytes: 78 },
    ] });
    const first = await extractAnimatedWebpFrame(new MemorySource(lossyAnimation), 0);
    const second = await extractAnimatedWebpFrame(new MemorySource(lossyAnimation), 1);
    expect(new TextDecoder().decode(first.webp.subarray(30, 34))).toBe("VP8 ");
    expect(new TextDecoder().decode(second.webp.subarray(30, 34))).toBe("ALPH");
    expect(new TextDecoder().decode(second.webp.subarray(46, 50))).toBe("VP8 ");
    expect(second.webp[20]).toBe(0x10);
  });

  it("rejects truncation, out-of-canvas frames and missing indices", async () => {
    await expect(inspectAnimatedWebp(new MemorySource(animation.slice(0, -1)))).rejects.toThrow(/RIFF\/WEBP envelope/);
    const oversized = animation.slice();
    oversized[58] = 0xff;
    await expect(inspectAnimatedWebp(new MemorySource(oversized))).rejects.toThrow(/rectangle/);
    await expect(extractAnimatedWebpFrame(new MemorySource(animation), 2)).rejects.toThrow(/does not exist/);
  });
});