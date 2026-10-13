import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { decodeSstvVis } from "../../formats/sstv";
import { MAX_WAV_BYTES } from "../../formats/wavSpectrum";
import { bytesInput } from "../util";

export const sstvVisDecode = defineOperation<{ channel: number; startFrame: number; minLevelDbfs: number }>({
  spec: {
    id: "hardware.audio.sstv-vis", version: "1.0.0", title: "Identify SSTV VIS mode", category: "Hardware",
    description: "Classify the leader and seven VIS data bits of a PCM16 SSTV WAV, checking framing and parity. This identifies the mode but does not reconstruct image scanlines.",
    keywords: ["sstv", "vis", "audio", "radio", "mode", "hardware"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      channel: { type: "integer", title: "Channel", minimum: 0, maximum: 1, default: 0 },
      startFrame: { type: "integer", title: "Leader start frame", minimum: 0, default: 0 },
      minLevelDbfs: { type: "integer", title: "Minimum tone level (dBFS)", minimum: -80, maximum: -5, default: -40 },
    }, required: ["channel", "startFrame", "minLevelDbfs"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_WAV_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await decodeSstvVis(bytesInput(inputs), params.channel, params.startFrame, params.minLevelDbfs, ctx.signal);
      ctx.diagnostic(`Verified SSTV VIS code ${report.mode}${report.modeName ? ` (${report.modeName})` : ""}; image scanlines were not decoded.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});