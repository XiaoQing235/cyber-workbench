import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { MAX_IQ_BYTES, spectrumIqU8 } from "../../formats/iqSpectrum";
import { bytesInput } from "../util";

export const iqSpectrum = defineOperation<{ sampleRate: number; startFrame: number; fftSize: number; window: "hann" | "rectangular"; peakCount: number }>({
  spec: {
    id: "hardware.iq.spectrum", version: "1.0.0", title: "Analyze I/Q spectrum", category: "Hardware",
    description: "Rank baseband complex FFT peaks from interleaved unsigned-8-bit I/Q samples, preserving positive and negative frequencies. Supply the capture sample rate; no radio signal is demodulated.",
    keywords: ["iq", "sdr", "quadrature", "baseband", "spectrum", "fft", "hardware"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      sampleRate: { type: "integer", title: "Sample rate (Hz)", minimum: 8_000, maximum: 192_000, default: 8_000 },
      startFrame: { type: "integer", title: "Start I/Q frame", minimum: 0, default: 0 },
      fftSize: { type: "integer", title: "FFT window (power of 2)", minimum: 256, maximum: 8_192, default: 1_024 },
      window: { type: "string", title: "Window", enum: ["hann", "rectangular"], default: "hann" },
      peakCount: { type: "integer", title: "Top peaks", minimum: 1, maximum: 32, default: 8 },
    }, required: ["sampleRate", "startFrame", "fftSize", "window", "peakCount"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_IQ_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await spectrumIqU8(bytesInput(inputs), params.sampleRate, params.startFrame, params.fftSize, params.window, params.peakCount, ctx.signal);
      ctx.diagnostic(`Strongest I/Q baseband peak ${report.peaks[0].frequencyHz.toFixed(2)} Hz at ${report.binWidthHz.toFixed(2)} Hz per bin.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});