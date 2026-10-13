import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { encodeBmp24 } from "./bmp/encode";
import { decodeImage } from "./decode";
import { toRgba } from "./image";

/** Crop raw PNG/BMP pixels and isolate strongly chromatic ink for a separate OCR pass. */
export async function colorContrastCrop(source: ByteSource, left: number, top: number, width: number, height: number,
  threshold: number, signal?: AbortSignal): Promise<{ image: Bytes; coloredPixels: number }> {
  if (![left, top, width, height, threshold].every(Number.isSafeInteger) || left < 0 || top < 0 || width < 1 || height < 1 ||
    width * height > 4_000_000 || threshold < 1 || threshold > 255) throw new Error("Color contrast crop bounds or threshold are invalid");
  const decoded = await decodeImage(source, { maxPixels: 4_000_000, signal });
  if (decoded.warnings.length || left + width > decoded.image.width || top + height > decoded.image.height) {
    throw new Error("Color contrast crop exceeds an intact image");
  }
  const rgba = toRgba(decoded.image, true);
  const result = new Uint8Array(width * height * 3);
  let coloredPixels = 0;
  for (let y = 0; y < height; y++) {
    if ((y & 31) === 0 && signal?.aborted) throw signal.reason;
    for (let x = 0; x < width; x++) {
      const index = ((top + y) * decoded.image.width + left + x) * 4;
      const red = rgba[index], green = rgba[index + 1], blue = rgba[index + 2];
      const colored = Math.max(red, green, blue) - Math.min(red, green, blue) > threshold;
      if (colored) coloredPixels++;
      result.fill(colored ? 0 : 255, (y * width + x) * 3, (y * width + x) * 3 + 3);
    }
  }
  return { image: encodeBmp24(width, height, result), coloredPixels };
}
