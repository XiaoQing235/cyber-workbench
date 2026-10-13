import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { inspectWav, MAX_WAV_BYTES, spectrogramWav, spectrumWav } from "../../formats/wavSpectrum";
import { bytesFrom } from "../../core/value";
import { bytesInput } from "../util";

export const wavInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "audio.wav.inspect", version: "1.0.0", title: "Inspect WAV samples", category: "Audio",
    description: "Read RIFF/WAVE chunk boundaries, PCM16 format, sample rate, channel count, and sample duration without playing or resampling audio.",
    keywords: ["wav", "riff", "pcm", "audio", "samples", "channels"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_WAV_BYTES },
  },
  async run(ctx, inputs) {
    try {
      return { report: structuredValue(await inspectWav(bytesInput(inputs), ctx.signal)) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const wavSpectrum = defineOperation<{ channel: number; startFrame: number; fftSize: number; window: "hann" | "rectangular"; peakCount: number }>({
  spec: {
    id: "audio.wav.spectrum", version: "1.0.0", title: "Analyze WAV spectrum", category: "Audio",
    description: "Rank FFT peaks in a bounded mono/stereo PCM16 window without browser playback or resampling. Frequencies and dBFS are derived from raw WAV samples.",
    keywords: ["wav", "fft", "spectrum", "frequency", "audio", "stego", "tone"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        channel: { type: "integer", title: "Channel", minimum: 0, maximum: 1, default: 0 },
        startFrame: { type: "integer", title: "Start sample frame", minimum: 0, default: 0 },
        fftSize: { type: "integer", title: "FFT window (power of 2)", minimum: 256, maximum: 8_192, default: 1_024 },
        window: { type: "string", title: "Window", enum: ["hann", "rectangular"], default: "hann" },
        peakCount: { type: "integer", title: "Top peaks", minimum: 1, maximum: 32, default: 8 },
      },
      required: ["channel", "startFrame", "fftSize", "window", "peakCount"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_WAV_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await spectrumWav(bytesInput(inputs), params.channel, params.startFrame, params.fftSize, params.window, params.peakCount, ctx.signal);
      ctx.diagnostic(`Dominant WAV frequency ${report.peaks[0].frequencyHz.toFixed(2)} Hz in ${report.fftSize} samples.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      const message = error instanceof Error ? error.message : String(error);
      throw new OperationError(message.includes("FFT parameters are invalid") ? "INVALID_PARAMS" : "INVALID_INPUT", message);
    }
  },
});

export const wavSpectrogram = defineOperation<{ channel: number; startFrame: number; fftSize: number; hopFrames: number; maxWindows: number; window: "hann" | "rectangular"; levelFloorDbfs: number }>({
  spec: {
    id: "audio.wav.spectrogram", version: "1.0.0", title: "Render WAV spectrogram", category: "Audio",
    description: "Render a bounded PCM16 spectrogram PNG from raw samples. Time runs left to right; lower frequencies are at the bottom, and intensity spans the chosen dBFS floor to 0.",
    keywords: ["wav", "audio", "spectrogram", "frequency", "fft", "stego", "tone"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "image", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        channel: { type: "integer", title: "Channel", minimum: 0, maximum: 1, default: 0 },
        startFrame: { type: "integer", title: "Start sample frame", minimum: 0, default: 0 },
        fftSize: { type: "integer", title: "FFT window (power of 2)", minimum: 256, maximum: 8_192, default: 1_024 },
        hopFrames: { type: "integer", title: "Hop (sample frames)", minimum: 1, maximum: 8_192, default: 256 },
        maxWindows: { type: "integer", title: "Maximum time windows", minimum: 1, maximum: 128, default: 64 },
        window: { type: "string", title: "Window", enum: ["hann", "rectangular"], default: "hann" },
        levelFloorDbfs: { type: "integer", title: "Dynamic range (dB)", minimum: 20, maximum: 120, default: 80 },
      },
      required: ["channel", "startFrame", "fftSize", "hopFrames", "maxWindows", "window", "levelFloorDbfs"],
      additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "high",
    limits: { maxInputBytes: MAX_WAV_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const { png, report } = await spectrogramWav(bytesInput(inputs), params.channel, params.startFrame, params.fftSize, params.hopFrames, params.maxWindows, params.window, params.levelFloorDbfs, ctx.signal);
      ctx.diagnostic(`Rendered ${report.windows} WAV time window(s) at ${report.binWidthHz.toFixed(2)} Hz per bin.${report.truncated ? " Window limit reached." : ""}`);
      return { image: bytesFrom(png), report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      const message = error instanceof Error ? error.message : String(error);
      throw new OperationError(message.includes("spectrogram selection or budget") ? "INVALID_PARAMS" : "INVALID_INPUT", message);
    }
  },
});