import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { textValue } from "../../core/value";
import { importPack } from "../../runtimes/files";
import { MiB } from "../util";
import { recognitionPixels } from "./pixels";

const LAYOUTS: Record<string, number> = { auto: 3, column: 4, block: 6, line: 7, word: 8, character: 10, sparse: 11 };
const MAX_PIXELS = 40_000_000;

/** Luminance over a white background (so transparent PNG text reads as dark on light). */
function grayscale(rgba: Uint8ClampedArray, count: number): Uint8Array {
  const gray = new Uint8Array(count);
  for (let p = 0; p < count; p++) {
    const alpha = rgba[p * 4 + 3] / 255;
    const luma = 0.299 * rgba[p * 4] + 0.587 * rgba[p * 4 + 1] + 0.114 * rgba[p * 4 + 2];
    gray[p] = Math.round(luma * alpha + 255 * (1 - alpha));
  }
  return gray;
}

function upscale(gray: Uint8Array, width: number, height: number, factor: number): Uint8Array {
  const out = new Uint8Array(width * factor * height * factor);
  for (let y = 0; y < height * factor; y++) {
    const sy = Math.min(height - 1, Math.max(0, (y + 0.5) / factor - 0.5));
    const y0 = Math.floor(sy);
    const y1 = Math.min(height - 1, y0 + 1);
    const fy = sy - y0;
    for (let x = 0; x < width * factor; x++) {
      const sx = Math.min(width - 1, Math.max(0, (x + 0.5) / factor - 0.5));
      const x0 = Math.floor(sx);
      const x1 = Math.min(width - 1, x0 + 1);
      const fx = sx - x0;
      const top = gray[y0 * width + x0] * (1 - fx) + gray[y0 * width + x1] * fx;
      const bottom = gray[y1 * width + x0] * (1 - fx) + gray[y1 * width + x1] * fx;
      out[y * width * factor + x] = Math.round(top * (1 - fy) + bottom * fy);
    }
  }
  return out;
}

export const ocrRecognize = defineOperation<{ layout: string; whitelist: string; invert: "auto" | "yes" | "no"; scale: number }>({
  spec: {
    id: "ocr.recognize",
    version: "1.0.0",
    title: "Recognise text (OCR)",
    category: "Image",
    description:
      "Read printed text from an image with Tesseract (English, LSTM). Light text on a dark background is inverted automatically; small text reads better scaled up.",
    keywords: ["ocr", "tesseract", "text", "recognise", "recognize", "read", "screenshot", "scan", "image to text"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: {
        layout: { type: "string", title: "Layout", enum: Object.keys(LAYOUTS), default: "auto" },
        whitelist: { type: "string", title: "Only these characters (empty = any)", default: "", maxLength: 500 },
        invert: { type: "string", title: "Invert colours", enum: ["auto", "yes", "no"], default: "auto" },
        scale: { type: "integer", title: "Scale up", minimum: 1, maximum: 4, default: 1 },
      },
      required: ["layout", "whitelist", "invert", "scale"],
      additionalProperties: false,
    },
    runtime: "wasm",
    deterministic: true,
    sideEffects: "none",
    streaming: false,
    cost: "high",
    limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs, params) {
    const { rgba, width, height, via } = await recognitionPixels(inputs);
    if (width * height * params.scale * params.scale > MAX_PIXELS) {
      throw new OperationError("INVALID_PARAMS", `${width}×${height} scaled ${params.scale}× is more than ${MAX_PIXELS.toLocaleString()} pixels`);
    }
    let gray = grayscale(rgba, width * height);
    const mean = gray.reduce((sum, value) => sum + value, 0) / gray.length;
    if (params.invert === "yes" || (params.invert === "auto" && mean < 128)) {
      for (let i = 0; i < gray.length; i++) gray[i] = 255 - gray[i];
      ctx.diagnostic(params.invert === "auto" ? "Mostly dark image: inverted so the text is dark on light." : "Inverted.");
    }
    if (params.scale > 1) gray = upscale(gray, width, height, params.scale);

    const { loadOcr, recognize } = await importPack("OCR", () => import("../../runtimes/ocr"));
    const ocr = await loadOcr();
    ctx.throwIfAborted();
    const { text, confidence } = recognize(ocr, gray, width * params.scale, height * params.scale, LAYOUTS[params.layout], params.whitelist);
    const trimmed = text.replace(/\s+$/, "");
    ctx.diagnostic(
      trimmed
        ? `Mean confidence ${confidence}% (${via}). Check characters that look alike (0/O, 1/l/I, {/(), _ in fonts).`
        : "No text found. Try another layout, inverting, or scaling up.",
    );
    return { text: textValue(trimmed) };
  },
});
