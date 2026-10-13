import type { Bytes } from "../core/bytes/ByteSource";
import type { ChannelName, DecodedImage } from "./image";

export interface LsbOptions {
  /** Channel letters in extraction order, e.g. "RGB" or "BGR". */
  channels: string;
  bit: number;
  /** How extracted bits are packed into bytes. */
  bitOrder: "msb-first" | "lsb-first";
  scan: "rows" | "columns";
  startFrom: "top" | "bottom";
  signal?: AbortSignal;
}

export interface LsbResult {
  bytes: Bytes;
  /** Bits left over that did not fill a whole byte. */
  leftoverBits: number;
}

export class LsbError extends Error {}

/** Reads one bit plane from the selected channels, in pixel scan order. */
export function extractBits(image: DecodedImage, options: LsbOptions): LsbResult {
  const { width, height, samples } = image;
  const count = image.channels.length;
  const indices = [...options.channels].map((name) => {
    const index = image.channels.indexOf(name as ChannelName);
    if (index < 0) {
      throw new LsbError(`Channel "${name}" is not in this image (available: ${image.channels.join("")})`);
    }
    return index;
  });
  if (indices.length === 0) throw new LsbError("Choose at least one channel");
  if (options.bit < 0 || options.bit >= image.bitDepth) {
    throw new LsbError(`Bit ${options.bit} is out of range for ${image.bitDepth}-bit samples`);
  }

  const totalBits = width * height * indices.length;
  const out = new Uint8Array(totalBits >> 3);
  const msbFirst = options.bitOrder === "msb-first";
  let accumulator = 0;
  let filled = 0;
  let written = 0;

  const visit = (x: number, y: number) => {
    const base = (y * width + x) * count;
    for (const index of indices) {
      const bit = (samples[base + index] >> options.bit) & 1;
      accumulator = msbFirst ? (accumulator << 1) | bit : accumulator | (bit << filled);
      if (++filled === 8) {
        out[written++] = accumulator;
        accumulator = 0;
        filled = 0;
      }
    }
  };
  const row = (i: number) => (options.startFrom === "top" ? i : height - 1 - i);

  if (options.scan === "rows") {
    for (let i = 0; i < height; i++) {
      if ((i & 63) === 0) options.signal?.throwIfAborted();
      const y = row(i);
      for (let x = 0; x < width; x++) visit(x, y);
    }
  } else {
    for (let x = 0; x < width; x++) {
      if ((x & 63) === 0) options.signal?.throwIfAborted();
      for (let i = 0; i < height; i++) visit(x, row(i));
    }
  }
  return { bytes: out, leftoverBits: filled };
}
