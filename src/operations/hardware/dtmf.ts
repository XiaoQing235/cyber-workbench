import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { decodeWavDtmf } from "../../formats/dtmf";
import { MAX_WAV_BYTES } from "../../formats/wavSpectrum";
import { bytesInput } from "../util";

export const dtmfDecode = defineOperation<{ channel: number; startFrame: number; fftSize: number; hopFrames: number; maxWindows: number; minLevelDbfs: number }>({
  spec: {
    id: "hardware.audio.dtmf", version: "1.0.0", title: "Decode WAV DTMF tones", category: "Hardware",
    description: "Decode bounded DTMF windows from mono/stereo PCM16 WAV using FFT low/high tone peaks. Set start frame, hop and level threshold for the recording; silent or unrecognised windows are skipped.",
    keywords: ["dtmf", "telephone", "wav", "tones", "fft", "hardware"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "text", type: "text" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: {
        channel: { type: "integer", title: "Channel", minimum: 0, maximum: 1, default: 0 },
        startFrame: { type: "integer", title: "First tone window frame", minimum: 0, default: 256 },
        fftSize: { type: "integer", title: "FFT window (power of 2)", minimum: 512, maximum: 4_096, default: 1_024 },
        hopFrames: { type: "integer", title: "Frames between tone windows", minimum: 1, maximum: 32_768, default: 2_000 },
        maxWindows: { type: "integer", title: "Maximum windows", minimum: 1, maximum: 128, default: 64 },
        minLevelDbfs: { type: "integer", title: "Minimum tone level (dBFS)", minimum: -80, maximum: -5, default: -35 },
      }, required: ["channel", "startFrame", "fftSize", "hopFrames", "maxWindows", "minLevelDbfs"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "high",
    limits: { maxInputBytes: MAX_WAV_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await decodeWavDtmf(bytesInput(inputs), params.channel, params.startFrame, params.fftSize, params.hopFrames, params.maxWindows, params.minLevelDbfs, ctx.signal);
      ctx.diagnostic(`Decoded ${report.decoded.length} DTMF symbol(s) from ${report.windows} FFT window(s); ${report.ignoredWindows} skipped.${report.truncated ? " Window limit reached." : ""}`);
      return { text: textValue(report.digits), report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});