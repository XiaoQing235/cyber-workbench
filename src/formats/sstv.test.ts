import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { decodeSstvVis } from "./sstv";

describe("SSTV VIS evidence", () => {
  it("classifies parity-verified Robot 36 and Martin M1 headers from PySSTV", async () => {
    for (const [name, mode, modeName, bits] of [
      ["robot36", 8, "Robot 36", [0, 0, 0, 1, 0, 0, 0]],
      ["martinm1", 44, "Martin M1", [0, 0, 1, 1, 0, 1, 0]],
    ] as const) {
      const bytes = new Uint8Array(readFileSync(new URL(`./testing/sstv-${name}-vis.wav`, import.meta.url)));
      const report = await decodeSstvVis(new MemorySource(bytes), 0, 0, -40);
      expect(report).toMatchObject({ mode, modeName, bits, parityBit: 1, verified: true,
        wav: { channels: 1, sampleRate: 8_000, frames: 7_600 } });
      expect(report.tones.map((tone) => tone.classifiedHz)).toEqual([1900, 1200, 1900, 1200,
        ...bits.map((bit) => bit ? 1100 : 1300), 1100, 1200]);
      const result = await executeOperation(createDefaultRegistry(), { operationId: "hardware.audio.sstv-vis",
        inputs: { data: bytesFrom(bytes) }, params: { channel: 0, startFrame: 0, minLevelDbfs: -40 } });
      expect(result.run.error).toBeUndefined();
      expect(result.outputs.report).toMatchObject({ type: "structured", data: { mode, modeName, verified: true } });
    }
  });

  it("rejects a wrong VIS parity bit, shifted leader and incomplete WAV header", async () => {
    const original = new Uint8Array(readFileSync(new URL("./testing/sstv-robot36-vis.wav", import.meta.url)));
    const changed = original.slice();
    const pcm = new DataView(changed.buffer);
    for (let frame = 6_800; frame < 7_040; frame++) {
      pcm.setInt16(44 + frame * 2, Math.round(15_000 * Math.sin(2 * Math.PI * 1_300 * frame / 8_000)), true);
    }
    await expect(decodeSstvVis(new MemorySource(changed), 0, 0, -40)).rejects.toThrow(/parity check failed/);
    await expect(decodeSstvVis(new MemorySource(original), 0, 80, -40)).rejects.toThrow(/break tone is invalid/);
    const short = original.slice(0, 44 + 7_200 * 2);
    const header = new DataView(short.buffer);
    header.setUint32(4, short.length - 8, true);
    header.setUint32(40, short.length - 44, true);
    await expect(decodeSstvVis(new MemorySource(short), 0, 0, -40)).rejects.toThrow(/910 ms header extent/);
  });
});