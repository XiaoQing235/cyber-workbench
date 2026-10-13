import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { spectrumIqU8 } from "./iqSpectrum";

const tone = new Uint8Array(readFileSync(new URL("./testing/iq-u8-1200.iq", import.meta.url)));

describe("bounded unsigned-8-bit I/Q spectra", () => {
  it("reports the independently produced +1.2 kHz complex tone without mirroring it", async () => {
    const report = await spectrumIqU8(new MemorySource(tone), 8_000, 0, 1_024, "hann", 8);
    expect(report).toMatchObject({ sampleFormat: "interleaved-u8-iq", sampleRate: 8_000, totalFrames: 2_048,
      startFrame: 0, fftSize: 1_024, binWidthHz: 7.8125 });
    expect(report.peaks[0]).toMatchObject({ bin: 154, frequencyHz: 1_203.125 });
    expect(report.peaks[0].levelDbfs).toBeGreaterThan(-7);
    const output = await executeOperation(createDefaultRegistry(), { operationId: "hardware.iq.spectrum",
      inputs: { data: bytesFrom(tone) }, params: { sampleRate: 8_000, startFrame: 0, fftSize: 1_024, window: "hann", peakCount: 8 } });
    expect(output.run.error).toBeUndefined();
    expect((output.outputs.report as { data: { peaks: object[] } }).data.peaks[0]).toMatchObject({ bin: 154, frequencyHz: 1_203.125 });
  });

  it("changes frequency sign when Q is inverted and rejects odd or incomplete input", async () => {
    const reverse = tone.slice();
    for (let index = 1; index < reverse.length; index += 2) reverse[index] = 255 - reverse[index];
    expect((await spectrumIqU8(new MemorySource(reverse), 8_000, 1_024, 1_024, "rectangular", 1)).peaks[0])
      .toMatchObject({ bin: 870, frequencyHz: -1_203.125 });
    await expect(spectrumIqU8(new MemorySource(tone.subarray(0, -1)), 8_000, 0, 1_024, "hann", 8)).rejects.toThrow(/interleaved I\/Q pairs/);
    await expect(spectrumIqU8(new MemorySource(tone), 8_000, 1_500, 1_024, "hann", 8)).rejects.toThrow(/FFT window/);
  });
});