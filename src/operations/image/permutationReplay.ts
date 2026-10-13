import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { replayPixelPermutation } from "../../formats/pixelPermutation";
import { bytesInput } from "../util";

export const pixelPermutationReplay = defineOperation<{ mapping: string; inverse: boolean }>({
  spec: {
    id: "image.permutation.replay", version: "1.1.0", title: "Replay pixel position map", category: "Image",
    description: "Apply or reverse an explicit 4096-position JSON permutation to a 64x64 RGBA PNG as a new PNG artifact. Mapping is output-position per input pixel; no key is inferred.",
    keywords: ["pixel", "permutation", "replay", "image", "rgba", "otp"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "image", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      mapping: { type: "string", title: "Output position for each input pixel (JSON array)", multiline: true, maxLength: 24_000, default: "" },
      inverse: { type: "boolean", title: "Reverse the supplied position map", default: false },
    }, required: ["mapping", "inverse"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: 64 * 1024 },
  },
  async run(ctx, inputs, params) {
    try {
      const result = await replayPixelPermutation(bytesInput(inputs), params.mapping, ctx.signal, params.inverse);
      return { image: bytesFrom(result.png), report: structuredValue({ pixels: result.pixels, mapVerified: true, flagRecovered: false }) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
