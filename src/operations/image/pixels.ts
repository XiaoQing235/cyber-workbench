import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import type { Value } from "../../core/value";
import { decodeImage } from "../../formats/decode";
import { ImageDecodeError, toRgba } from "../../formats/image";
import { bytesInput } from "../util";

export interface Pixels {
  rgba: Uint8ClampedArray;
  width: number;
  height: number;
  via: string;
}

/**
 * Pixels for recognition (QR, OCR), where exact values do not matter. PNG and BMP use the raw decoder;
 * other formats (JPEG, GIF, WebP…) use the browser's decoder in the worker.
 */
export async function recognitionPixels(inputs: Readonly<Record<string, Value>>): Promise<Pixels> {
  try {
    const { image } = await decodeImage(bytesInput(inputs), { maxPixels: 50_000_000 });
    return { rgba: toRgba(image, true), width: image.width, height: image.height, via: "raw decoder" };
  } catch (error) {
    if (!(error instanceof ImageDecodeError) || typeof createImageBitmap !== "function" || typeof OffscreenCanvas === "undefined") {
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
    const bitmap = await createImageBitmap(new Blob([await readAll(bytesInput(inputs))]));
    const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
    const context = canvas.getContext("2d");
    if (!context) throw new OperationError("INTERNAL", "No 2D canvas available");
    context.drawImage(bitmap, 0, 0);
    return { rgba: context.getImageData(0, 0, bitmap.width, bitmap.height).data, width: bitmap.width, height: bitmap.height, via: "browser decoder" };
  }
}
