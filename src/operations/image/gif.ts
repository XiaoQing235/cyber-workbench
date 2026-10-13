import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { compareGifFrames, exportCompositedGifFramePng, exportGifFramePng, gifFrameTimeline, inspectGifFrames, MAX_GIF_BYTES } from "../../formats/gifFrames";
import { bytesInput } from "../util";

export const gifFramesInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "image.gif.frames.inspect", version: "1.0.0", title: "Inspect GIF frames", category: "Image",
    description: "Inspect GIF frame offsets, delay, disposal, and transparent palette RGB without Canvas compositing. Files are limited to 4 MiB and 64 frames.",
    keywords: ["gif", "animation", "frames", "disposal", "delay", "transparency", "palette"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_GIF_BYTES },
  },
  async run(ctx, inputs) {
    try {
      return { report: structuredValue(await inspectGifFrames(bytesInput(inputs), ctx.signal)) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const gifTimelineInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "image.gif.frames.timeline", version: "1.0.0", title: "Inspect GIF frame timing", category: "Image",
    description: "Report cumulative start time, raw delay and disposal for each bounded GIF frame. Zero-delay frames remain zero rather than assuming a player-specific minimum.",
    keywords: ["gif", "animation", "frames", "delay", "timeline", "stego"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_GIF_BYTES },
  },
  async run(ctx, inputs) {
    try { return { report: structuredValue(await gifFrameTimeline(bytesInput(inputs), ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const gifFrameExport = defineOperation<{ frameIndex: number; mode: "visible" | "raw" | "composited"; background?: "palette" | "transparent" }>({
  spec: {
    id: "image.gif.frame.export", version: "1.1.0", title: "Export GIF frame PNG", category: "Image",
    description: "Export a GIF frame to PNG. Raw reveals transparent RGB, visible keeps it under alpha 0, and composited applies prior frames and disposal with a chosen background.",
    keywords: ["gif", "frame", "png", "palette", "transparent rgb", "stego", "lsb"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        frameIndex: { type: "integer", title: "Frame index", minimum: 0, maximum: 63, default: 0 },
        mode: { type: "string", title: "Frame view", enum: ["visible", "raw", "composited"], default: "visible" },
        background: { type: "string", title: "Composite background", enum: ["palette", "transparent"], default: "palette" },
      },
      required: ["frameIndex", "mode"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_GIF_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      if (params.mode === "composited") {
        const background = params.background ?? "palette";
        const { report, png } = await exportCompositedGifFramePng(bytesInput(inputs), params.frameIndex, background, ctx.signal);
        ctx.diagnostic(`Exported composited GIF frame ${params.frameIndex} as PNG using the ${background} background.`);
        return { data: bytesFrom(png), report: structuredValue({ frame: report.frames[params.frameIndex], logicalWidth: report.width, logicalHeight: report.height, mode: params.mode, background, composited: true }) };
      }
      const { report, png, transparentPixels } = await exportGifFramePng(bytesInput(inputs), params.frameIndex, params.mode === "raw", ctx.signal);
      ctx.diagnostic(`Exported GIF frame ${params.frameIndex} as PNG with ${transparentPixels} transparent palette pixel(s) in ${params.mode} mode.`);
      return { data: bytesFrom(png), report: structuredValue({ frame: report.frames[params.frameIndex], logicalWidth: report.width, logicalHeight: report.height, transparentPixels, mode: params.mode, composited: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const gifFramesCompare = defineOperation<{ firstIndex: number; secondIndex: number; mode: "difference" | "xor"; background: "palette" | "transparent" }>({
  spec: {
    id: "image.gif.frames.compare", version: "1.0.0", title: "Compare GIF frames", category: "Image",
    description: "Export the absolute RGB difference or XOR of two disposal-aware GIF composites as PNG, with a changed-pixel count and explicit background.",
    keywords: ["gif", "animation", "frames", "difference", "xor", "disposal", "stego"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        firstIndex: { type: "integer", title: "First frame index", minimum: 0, maximum: 63, default: 0 },
        secondIndex: { type: "integer", title: "Second frame index", minimum: 0, maximum: 63, default: 1 },
        mode: { type: "string", title: "Comparison", enum: ["difference", "xor"], default: "difference" },
        background: { type: "string", title: "Composite background", enum: ["palette", "transparent"], default: "palette" },
      },
      required: ["firstIndex", "secondIndex", "mode", "background"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_GIF_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const { png, ...report } = await compareGifFrames(bytesInput(inputs), params.firstIndex, params.secondIndex, params.mode, params.background, ctx.signal);
      ctx.diagnostic(`Compared GIF frames ${params.firstIndex} and ${params.secondIndex}; ${report.changedPixels} pixel(s) changed.`);
      return { data: bytesFrom(png), report: structuredValue({ ...report, firstIndex: params.firstIndex, secondIndex: params.secondIndex, mode: params.mode, background: params.background }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
