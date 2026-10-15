import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { MemorySource } from "../core/bytes/sources";
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

/** Compact chromatic text in reading order without recognizing or substituting characters. */
export async function colorContrastStrip(source: ByteSource, left: number, top: number, width: number, height: number,
  threshold: number, signal?: AbortSignal): Promise<{ image: Bytes; regions: { left: number; top: number; width: number; height: number }[] }> {
  const crop = await colorContrastCrop(source, left, top, width, height, threshold, signal);
  const decoded = await decodeImage(new MemorySource(crop.image), { maxPixels: 4_000_000, signal });
  const rgba = toRgba(decoded.image, true);
  const ink = (x: number, y: number) => {
    return rgba[(y * width + x) * 4] === 0;
  };
  const runs = (values: boolean[], gap: number) => {
    const result: { start: number; end: number }[] = [];
    for (let i = 0; i < values.length; i++) if (values[i]) {
      const last = result.at(-1);
      if (last && i - last.end <= gap + 1) last.end = i;
      else result.push({ start: i, end: i });
    }
    return result;
  };
  const rows = runs(Array.from({ length: height }, (_, y) => {
    for (let x = 0; x < width; x++) if (ink(x, y)) return true;
    return false;
  }), 3);
  const regions = rows.flatMap(row => runs(Array.from({ length: width }, (_, x) => {
    for (let y = row.start; y <= row.end; y++) if (ink(x, y)) return true;
    return false;
  }), 1).map(column => {
    let first = row.end, last = row.start;
    for (let y = row.start; y <= row.end; y++) for (let x = column.start; x <= column.end; x++) if (ink(x, y)) {
      first = Math.min(first, y); last = Math.max(last, y);
    }
    return { left: left + column.start, top: top + first, width: column.end - column.start + 1, height: last - first + 1 };
  }));
  if (!regions.length || regions.length > 256) throw new Error("Color text strip requires 1–256 bounded regions");
  const outHeight = 64;
  // Fit both axes with the same scale; tall regions must not be squashed vertically.
  const scales = regions.map(region => Math.min(3, 40 / region.height));
  const widths = regions.map((region, index) => Math.max(1, Math.round(region.width * scales[index])));
  const outWidth = widths.reduce((sum, value) => sum + value + 8, 8);
  if (outWidth * outHeight > 4_000_000) throw new Error("Color text strip exceeds pixel budget");
  const pixels = new Uint8Array(outWidth * outHeight * 3).fill(255);
  let offset = 8;
  for (const [index, region] of regions.entries()) {
    if (signal?.aborted) throw signal.reason;
    const scaledHeight = Math.max(1, Math.round(region.height * scales[index]));
    for (let y = 0; y < scaledHeight; y++) for (let x = 0; x < widths[index]; x++) {
      const sx = region.left - left + Math.floor(x * region.width / widths[index]);
      const sy = region.top - top + Math.floor(y * region.height / scaledHeight);
      if (ink(sx, sy)) pixels.fill(0, ((y + 52 - scaledHeight) * outWidth + offset + x) * 3, ((y + 52 - scaledHeight) * outWidth + offset + x) * 3 + 3);
    }
    offset += widths[index] + 8;
  }
  return { image: encodeBmp24(outWidth, outHeight, pixels), regions };
}
