import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue, textValue } from "../../core/value";
import { improveSharedPermutation } from "../../formats/pixelPermutation";
import { bytesInput, MiB } from "../util";

export const pixelPermutationImprove = defineOperation<{ seed: number; iterations: number; imageIndex: number; resumeMap: string; previousIterations: number }>({
  spec: {
    id: "image.permutation.improve", version: "1.5.0", title: "Improve shared pixel permutation", category: "Image",
    description: "Apply cancellable bounded shared pixel swaps to 2–64 equally sized 64x64 RGBA PNGs in a ZIP. Resume from a previous map and iteration count with the same seed, up to ten million cumulative attempts. Export a selected candidate image and replayable position map; this does not prove the key or recover a flag.",
    keywords: ["pixel", "permutation", "images", "shuffled", "stego", "ctf"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "image", type: "bytes" }, { name: "mapping", type: "text" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      seed: { type: "integer", title: "Search seed", minimum: 0, maximum: 0xffffffff, default: 20261012 },
      iterations: { type: "integer", title: "Maximum swaps", minimum: 1, maximum: 100_000, default: 2_000 },
      imageIndex: { type: "integer", title: "Candidate image index (zero-based)", minimum: 0, maximum: 63, default: 0 },
      resumeMap: { type: "string", title: "Previous position map JSON (blank = new search)", maxLength: 24_000, default: "" },
      previousIterations: { type: "integer", title: "Swaps attempted before this batch", minimum: 0, maximum: 9_999_999, default: 0 },
    }, required: ["seed", "iterations", "imageIndex", "resumeMap", "previousIterations"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "high",
    limits: { maxInputBytes: 1 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const { png, map, report } = await improveSharedPermutation(bytesInput(inputs), params.seed, params.iterations, ctx.signal,
        params.imageIndex, params.resumeMap, params.previousIterations);
      ctx.diagnostic(`Accepted ${report.accepted} of ${report.iterations} shared swaps; neighbor-color error ${report.initialScore} → ${report.finalScore}. This is not a recovered permutation key.`);
      return { image: bytesFrom(png), mapping: textValue(JSON.stringify(map)), report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
