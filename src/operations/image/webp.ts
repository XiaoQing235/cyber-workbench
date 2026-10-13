import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { extractAnimatedWebpFrame, inspectAnimatedWebp, MAX_ANIMATED_WEBP_BYTES } from "../../formats/webp";
import { bytesInput } from "../util";

export const webpFramesInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "image.webp.frames.inspect", version: "1.0.0", title: "Inspect animated WebP frames", category: "Image",
    description: "Inspect bounded RIFF WebP animation rectangles, timing, blend/disposal flags and VP8/VP8L subchunks without decoding pixels.",
    keywords: ["webp", "animated", "frames", "timeline", "stego"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_ANIMATED_WEBP_BYTES },
  },
  async run(ctx, inputs) {
    try { return { report: structuredValue(await inspectAnimatedWebp(bytesInput(inputs), ctx.signal)) }; }
    catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const webpFrameExport = defineOperation<{ frameIndex: number }>({
  spec: {
    id: "image.webp.frame.export", version: "1.0.0", title: "Export raw WebP frame", category: "Image",
    description: "Rewrap one bounded animation frame as a standalone WebP patch, preserving encoded VP8/VP8L bytes. Prior frames, canvas position and color-profile compositing are not applied.",
    keywords: ["webp", "frame", "extract", "patch", "stego"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      frameIndex: { type: "integer", title: "Frame index", minimum: 0, maximum: 63, default: 0 },
    }, required: ["frameIndex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_ANIMATED_WEBP_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const result = await extractAnimatedWebpFrame(bytesInput(inputs), params.frameIndex, ctx.signal);
      ctx.diagnostic(`Exported raw ${result.frame.width}x${result.frame.height} WebP frame ${params.frameIndex}; animation compositing was not applied.`);
      return { data: bytesFrom(result.webp), report: structuredValue(result.frame) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});