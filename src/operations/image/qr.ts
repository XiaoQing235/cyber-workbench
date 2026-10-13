import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, textValue, type Value } from "../../core/value";
import { encodeBmp24 } from "../../formats/bmp/encode";
import { decodeImage } from "../../formats/decode";
import { ImageDecodeError, type DecodedImage } from "../../formats/image";
import type { Grid, Inversion } from "../../formats/qr";
import { bytesInput, MiB, textInput } from "../util";
import { recognitionPixels } from "./pixels";

// jsQR is loaded only when a QR operation runs (in the worker), keeping it out of the main bundle.
const loadQr = () => import("../../formats/qr");

const COMMON = { runtime: "ts", deterministic: true, sideEffects: "none", streaming: false, cost: "low" } as const;
const INVERSION = { type: "string", title: "Try inverted colours", enum: ["attemptBoth", "dontInvert", "onlyInvert", "invertFirst"], default: "attemptBoth" } as const;

async function rawImage(inputs: Readonly<Record<string, Value>>): Promise<DecodedImage> {
  try {
    return (await decodeImage(bytesInput(inputs), { maxPixels: 50_000_000 })).image;
  } catch (error) {
    if (error instanceof ImageDecodeError) throw new OperationError("INVALID_INPUT", error.message);
    throw error;
  }
}

async function grid(text: string): Promise<Grid> {
  const qr = await loadQr();
  try {
    return qr.parseGrid(text);
  } catch (error) {
    if (error instanceof qr.QrError) throw new OperationError("INVALID_INPUT", error.message);
    throw error;
  }
}

export const qrDecode = defineOperation<{ inversion: Inversion }>({
  spec: {
    ...COMMON,
    id: "qr.decode",
    version: "1.0.0",
    title: "Decode QR code",
    category: "Image",
    description: "Find and decode a QR code in an image (PNG and BMP decoded raw; other formats by the browser).",
    keywords: ["qr", "qrcode", "barcode", "scan", "zbar"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: { type: "object", properties: { inversion: INVERSION }, required: ["inversion"], additionalProperties: false },
    limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs, params) {
    const { rgba, width, height, via } = await recognitionPixels(inputs);
    const result = (await loadQr()).decodeRgba(rgba, width, height, params.inversion);
    if (!result) {
      throw new OperationError("INVALID_INPUT", 'No readable QR code. If it is damaged, run "QR code to module grid" and repair it.');
    }
    ctx.diagnostic(`Version ${result.version}, ${result.bytes.length} data bytes (${via}).`);
    return { text: textValue(result.text) };
  },
});

export const qrToGrid = defineOperation<{ size: number }>({
  spec: {
    ...COMMON,
    id: "qr.to-grid",
    version: "1.0.0",
    title: "QR code to module grid",
    category: "Image",
    description: "Sample a clean, upright QR image into a text grid (# dark, . light) that can be edited by hand and decoded again.",
    keywords: ["qr", "grid", "modules", "repair", "recover", "damaged"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: { size: { type: "integer", title: "Modules per side (0 = estimate)", minimum: 0, maximum: 177, default: 0 } },
      required: ["size"],
      additionalProperties: false,
    },
    limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs, params) {
    const qr = await loadQr();
    let modules: Grid;
    try {
      modules = qr.imageToGrid(await rawImage(inputs), params.size);
    } catch (error) {
      if (error instanceof qr.QrError) throw new OperationError("INVALID_INPUT", error.message);
      throw error;
    }
    ctx.diagnostic(`${modules.length}×${modules.length} modules (version ${(modules.length - 17) / 4}), sampled from the dark area's bounding box.`);
    return { text: textValue(qr.gridToText(modules)) };
  },
});

export const qrFromGrid = defineOperation<{ restore: boolean; tryFormats: boolean; inversion: Inversion }>({
  spec: {
    ...COMMON,
    id: "qr.from-grid",
    version: "1.0.0",
    title: "Decode QR module grid",
    category: "Image",
    description:
      "Decode a QR code given as text rows (# or 1 dark, . or 0 light), optionally restoring finder, timing and alignment patterns and trying all 32 format settings when the format bits are damaged.",
    keywords: ["qr", "grid", "repair", "recover", "finder", "format", "mask", "damaged", "qrazybox"],
    inputs: [{ name: "text", type: "text" }],
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: {
        restore: { type: "boolean", title: "Restore finder, timing and alignment patterns", default: true },
        tryFormats: { type: "boolean", title: "Try every error-correction level and mask", default: true },
        inversion: INVERSION,
      },
      required: ["restore", "tryFormats", "inversion"],
      additionalProperties: false,
    },
  },
  async run(ctx, inputs, params) {
    const qr = await loadQr();
    const original = await grid(textInput(inputs));
    const repaired = params.restore ? qr.restoreFunctionPatterns(original) : original;
    const changed = repaired.flat().filter((dark, i) => dark !== original.flat()[i]).length;
    if (params.restore) ctx.diagnostic(`Restored function patterns: ${changed} module(s) changed.`);
    const direct = qr.decodeGrid(repaired, params.inversion);
    if (direct) return { text: textValue(direct.text) };
    if (params.tryFormats) {
      const found = qr.decodeWithAnyFormat(repaired, params.inversion);
      if (found) {
        ctx.diagnostic(`The format information was unreadable; error correction ${found.level} with mask ${found.mask} decodes.`);
        return { text: textValue(found.result.text) };
      }
    }
    throw new OperationError("INVALID_INPUT", "Still unreadable: too many data modules are wrong for error correction to recover.");
  },
});

export const qrDrawGrid = defineOperation<{ restore: boolean; scale: number }>({
  spec: {
    ...COMMON,
    id: "qr.draw-grid",
    version: "1.0.0",
    title: "Draw QR module grid",
    category: "Image",
    description: "Render a text grid of QR modules as an image (with quiet zone), optionally restoring the function patterns first.",
    keywords: ["qr", "grid", "render", "draw", "image"],
    inputs: [{ name: "text", type: "text" }],
    outputs: [{ name: "image", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        restore: { type: "boolean", title: "Restore finder, timing and alignment patterns", default: false },
        scale: { type: "integer", title: "Pixels per module", minimum: 1, maximum: 32, default: 8 },
      },
      required: ["restore", "scale"],
      additionalProperties: false,
    },
  },
  async run(_ctx, inputs, params) {
    const qr = await loadQr();
    const original = await grid(textInput(inputs));
    const { width, height, rgba } = qr.renderGrid(params.restore ? qr.restoreFunctionPatterns(original) : original, params.scale);
    const rgb = new Uint8Array(width * height * 3);
    for (let p = 0; p < width * height; p++) rgb.set(rgba.subarray(p * 4, p * 4 + 3), p * 3);
    return { image: bytesFrom(encodeBmp24(width, height, rgb)) };
  },
});
