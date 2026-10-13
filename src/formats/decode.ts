import type { ByteSource } from "../core/bytes/ByteSource";
import { decodeBmp, parseBmp } from "./bmp/bmp";
import { ImageDecodeError, sniffImageFormat, type DecodeResult } from "./image";
import { decodePng } from "./png/decode";
import { parsePng } from "./png/parse";

export interface DecodeOptions {
  maxPixels?: number;
  signal?: AbortSignal;
}

/** Decodes a PNG or BMP to raw samples, detected from the file signature. */
export async function decodeImage(source: ByteSource, options: DecodeOptions = {}): Promise<DecodeResult> {
  const format = sniffImageFormat(await source.read(0, 8));
  if (format === "png") return decodePng(source, await parsePng(source, options.signal), options);
  if (format === "bmp") return decodeBmp(source, await parseBmp(source), options.maxPixels);
  throw new ImageDecodeError("Unsupported image format (PNG and BMP are supported)");
}
