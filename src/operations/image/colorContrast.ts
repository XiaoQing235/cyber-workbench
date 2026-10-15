import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { colorContrastCrop, colorContrastStrip } from "../../formats/colorContrast";
import { bytesInput, MiB } from "../util";

export const colorContrastIsolate = defineOperation<{ left: number; top: number; width: number; height: number; threshold: number }>({
  spec: {
    id: "image.color-contrast.crop", version: "1.0.0", title: "Isolate coloured image region", category: "Image",
    description: "Crop an intact PNG/BMP and render pixels above an RGB channel-contrast threshold as black on white. Useful for a separate OCR pass; this is a visual candidate, not text recognition.",
    keywords: ["crop", "color", "colour", "contrast", "ink", "ocr", "image"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "image", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      left: { type: "integer", title: "Left pixel", minimum: 0, default: 0 },
      top: { type: "integer", title: "Top pixel", minimum: 0, default: 0 },
      width: { type: "integer", title: "Crop width", minimum: 1, maximum: 2000, default: 256 },
      height: { type: "integer", title: "Crop height", minimum: 1, maximum: 2000, default: 256 },
      threshold: { type: "integer", title: "RGB contrast threshold", minimum: 1, maximum: 255, default: 120 },
    }, required: ["left", "top", "width", "height", "threshold"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const { image, coloredPixels } = await colorContrastCrop(bytesInput(inputs), params.left, params.top,
        params.width, params.height, params.threshold, ctx.signal);
      ctx.diagnostic(`${coloredPixels} chromatic pixel(s) in the selected ${params.width}×${params.height} region; recognition requires a separate OCR or visual check.`);
      return { image: bytesFrom(image), report: structuredValue({ coloredPixels, width: params.width, height: params.height,
        threshold: params.threshold, textRecovered: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const colorContrastTextStrip = defineOperation<{ left: number; top: number; width: number; height: number; threshold: number }>({
  spec: {
    ...colorContrastIsolate.spec,
    id: "image.color-contrast.text-strip",
    title: "Arrange coloured text as a strip",
    description: "Isolate chromatic pixels in a crop, group nearby rows and columns, and arrange the regions left-to-right for visual inspection or OCR. Region coordinates retain source-image evidence; no characters are guessed. Closely spaced lines or disconnected glyphs may require separate crops.",
  },
  async run(ctx, inputs, params) {
    try {
      const { image, regions } = await colorContrastStrip(bytesInput(inputs), params.left, params.top,
        params.width, params.height, params.threshold, ctx.signal);
      return { image: bytesFrom(image), report: structuredValue({ regions, textRecovered: false,
        ordering: "row bands then columns", maxScale: 3, maxRegionHeight: 40, aspectRatioPreserved: true }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
