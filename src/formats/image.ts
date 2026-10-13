export type ImageFormat = "png" | "bmp";

/** Channel names: R G B A colour, Y greyscale, I palette index. */
export type ChannelName = "R" | "G" | "B" | "A" | "Y" | "I";

/**
 * Raw samples exactly as stored in the file, never passed through Canvas (which may alter
 * colour values). Rows are top-down regardless of the file's storage order.
 */
export interface DecodedImage {
  format: ImageFormat;
  width: number;
  height: number;
  /** Interleaving order of the samples, e.g. ["R","G","B","A"] or ["B","G","R"]. */
  channels: readonly ChannelName[];
  /** Bits per sample: 1, 2, 4, 8 or 16. */
  bitDepth: number;
  samples: Uint8Array | Uint16Array;
  /** RGBA quadruples, present when the image uses palette indices (channel "I"). */
  palette?: Uint8Array;
}

export interface DecodeResult {
  image: DecodedImage;
  /** Problems the decoder worked around, e.g. missing rows filled with zeros. */
  warnings: string[];
}

export class ImageDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ImageDecodeError";
  }
}

export function sniffImageFormat(head: Uint8Array): ImageFormat | null {
  if (head.length >= 8 && head[0] === 0x89 && head[1] === 0x50 && head[2] === 0x4e && head[3] === 0x47) return "png";
  if (head.length >= 2 && head[0] === 0x42 && head[1] === 0x4d) return "bmp";
  return null;
}

/** 8-bit RGBA for display only. Analysis must use `samples`. */
export function toRgba(image: DecodedImage, ignoreAlpha: boolean): Uint8ClampedArray<ArrayBuffer> {
  const { width, height, channels, samples, palette } = image;
  const count = channels.length;
  const at = (name: ChannelName) => channels.indexOf(name);
  const [r, g, b, a, y, index] = (["R", "G", "B", "A", "Y", "I"] as const).map(at);
  const scale = 255 / (2 ** image.bitDepth - 1);
  const out = new Uint8ClampedArray(width * height * 4);
  for (let p = 0, s = 0, o = 0; p < width * height; p++, s += count, o += 4) {
    if (index >= 0 && palette) {
      const entry = samples[s + index] * 4;
      out[o] = palette[entry] ?? 0;
      out[o + 1] = palette[entry + 1] ?? 0;
      out[o + 2] = palette[entry + 2] ?? 0;
      out[o + 3] = ignoreAlpha ? 255 : (palette[entry + 3] ?? 255);
      continue;
    }
    if (y >= 0) {
      out[o] = out[o + 1] = out[o + 2] = samples[s + y] * scale;
    } else {
      out[o] = r >= 0 ? samples[s + r] * scale : 0;
      out[o + 1] = g >= 0 ? samples[s + g] * scale : 0;
      out[o + 2] = b >= 0 ? samples[s + b] * scale : 0;
    }
    out[o + 3] = ignoreAlpha || a < 0 ? 255 : samples[s + a] * scale;
  }
  return out;
}

/** Black-and-white rendering of one bit of one channel (StegSolve-style), for display only. */
export function bitPlaneRgba(image: DecodedImage, channel: number, bit: number): Uint8ClampedArray<ArrayBuffer> {
  const { width, height, channels, samples } = image;
  const out = new Uint8ClampedArray(width * height * 4);
  for (let p = 0, s = channel, o = 0; p < width * height; p++, s += channels.length, o += 4) {
    out[o] = out[o + 1] = out[o + 2] = (samples[s] >> bit) & 1 ? 255 : 0;
    out[o + 3] = 255;
  }
  return out;
}
