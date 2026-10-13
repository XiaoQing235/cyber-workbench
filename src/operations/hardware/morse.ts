import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { decodeWavMorse } from "../../formats/morse";
import { MAX_WAV_BYTES } from "../../formats/wavSpectrum";
import { bytesInput } from "../util";

export const morseDecode = defineOperation<{ channel: number; dotMilliseconds: number; minLevelDbfs: number }>({
  spec: {
    id: "hardware.audio.morse", version: "1.0.0", title: "Decode WAV Morse tones", category: "Hardware",
    description: "Decode up to 30 seconds of keyed PCM16 WAV using amplitude and a known dot duration. Returns decoded characters, timed dot/dash codes and an explicit truncation flag; noisy recordings may need a level adjustment.",
    keywords: ["morse", "cw", "wav", "audio", "tone", "dots", "dashes"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "text", type: "text" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: {
        channel: { type: "integer", title: "Channel", minimum: 0, maximum: 1, default: 0 },
        dotMilliseconds: { type: "integer", title: "Dot length (milliseconds)", minimum: 40, maximum: 500, default: 120 },
        minLevelDbfs: { type: "integer", title: "Minimum active level (dBFS)", minimum: -80, maximum: -5, default: -32 },
      }, required: ["channel", "dotMilliseconds", "minLevelDbfs"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_WAV_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await decodeWavMorse(bytesInput(inputs), params.channel, params.dotMilliseconds, params.minLevelDbfs, ctx.signal);
      ctx.diagnostic(`Decoded ${report.symbols.length} Morse character(s) from ${report.processedSeconds.toFixed(2)} second(s).${report.truncated ? " Scan limit reached." : ""}`);
      return { text: textValue(report.text), report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
