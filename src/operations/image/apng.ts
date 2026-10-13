import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { compositeApngFramePng, extractApngFramePng, inspectApng, MAX_APNG_BYTES } from "../../formats/apng";
import { bytesInput } from "../util";

export const apngFramesInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "image.apng.frames.inspect", version: "1.0.0", title: "Inspect APNG frames", category: "Image",
    description: "Inspect bounded 8-bit RGBA APNG controls, frame delays, offsets, blend and disposal, validating every PNG chunk CRC and sequence number.",
    keywords: ["apng", "animated png", "frames", "delay", "blend", "disposal"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_APNG_BYTES },
  },
  async run(ctx, inputs) {
    try {
      return { report: structuredValue(await inspectApng(bytesInput(inputs), ctx.signal)) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const apngFrameExport = defineOperation<{ frameIndex: number; mode?: "raw" | "composited" }>({
  spec: {
    id: "image.apng.frame.export", version: "1.1.0", title: "Export APNG frame PNG", category: "Image",
    description: "Export a CRC-validated APNG frame as a raw PNG patch or as a composited PNG with prior frame blend and disposal applied.",
    keywords: ["apng", "frame", "png", "extract", "stego", "lsb"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: {
        frameIndex: { type: "integer", title: "Frame index", minimum: 0, maximum: 63, default: 0 },
        mode: { type: "string", title: "Frame view", enum: ["raw", "composited"], default: "raw" },
      },
      required: ["frameIndex"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_APNG_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const composited = params.mode === "composited";
      const { png, report } = composited
        ? await compositeApngFramePng(bytesInput(inputs), params.frameIndex, ctx.signal)
        : await extractApngFramePng(bytesInput(inputs), params.frameIndex, ctx.signal);
      const frame = report.frames[params.frameIndex];
      ctx.diagnostic(composited
        ? `Exported composited APNG frame ${params.frameIndex} as PNG.`
        : `Exported APNG frame ${params.frameIndex} as an uncomposited ${frame.width}x${frame.height} PNG patch.`);
      return { data: bytesFrom(png), report: structuredValue({ frame, composited }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});