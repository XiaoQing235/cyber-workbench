import type { ByteSource } from "../../core/bytes/ByteSource";
import { ConcatSource, SliceSource } from "../../core/bytes/sources";
import { inflate } from "../../core/compression/inflate";
import { ImageDecodeError, type ChannelName, type DecodeResult } from "../image";
import type { Ihdr, PngStructure } from "./parse";

export const CHANNELS_BY_COLOR_TYPE: Record<number, readonly ChannelName[]> = {
  0: ["Y"],
  2: ["R", "G", "B"],
  3: ["I"],
  4: ["Y", "A"],
  6: ["R", "G", "B", "A"],
};

interface Pass {
  x0: number;
  y0: number;
  dx: number;
  dy: number;
}

const SINGLE_PASS: readonly Pass[] = [{ x0: 0, y0: 0, dx: 1, dy: 1 }];
const ADAM7: readonly Pass[] = [
  { x0: 0, y0: 0, dx: 8, dy: 8 },
  { x0: 4, y0: 0, dx: 8, dy: 8 },
  { x0: 0, y0: 4, dx: 4, dy: 8 },
  { x0: 2, y0: 0, dx: 4, dy: 4 },
  { x0: 0, y0: 2, dx: 2, dy: 4 },
  { x0: 1, y0: 0, dx: 2, dy: 2 },
  { x0: 0, y0: 1, dx: 1, dy: 2 },
];

export interface PassLayout extends Pass {
  width: number;
  height: number;
  rowBytes: number;
}

/** Sub-image sizes for each (Adam7) pass; empty passes are omitted. */
export function passLayout(ihdr: Ihdr): PassLayout[] {
  const channels = CHANNELS_BY_COLOR_TYPE[ihdr.colorType];
  if (!channels) throw new ImageDecodeError(`Unsupported colour type ${ihdr.colorType}`);
  const bitsPerPixel = channels.length * ihdr.bitDepth;
  return (ihdr.interlace === 1 ? ADAM7 : SINGLE_PASS)
    .map((pass) => {
      const width = Math.ceil((ihdr.width - pass.x0) / pass.dx);
      const height = Math.ceil((ihdr.height - pass.y0) / pass.dy);
      return { ...pass, width, height, rowBytes: Math.ceil((width * bitsPerPixel) / 8) };
    })
    .filter((pass) => pass.width > 0 && pass.height > 0);
}

/** Size of the filtered scanline stream that the IHDR dimensions imply. */
export function expectedRawSize(ihdr: Ihdr): number {
  return passLayout(ihdr).reduce((sum, pass) => sum + pass.height * (pass.rowBytes + 1), 0);
}

export function idatSource(source: ByteSource, structure: PngStructure): ByteSource {
  return new ConcatSource(structure.idat.map((span) => new SliceSource(source, span.offset, span.length)));
}

function paeth(a: number, b: number, c: number): number {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

/** Reverses scanline filtering for one pass. Missing data is treated as zero bytes. */
function unfilterPass(raw: Uint8Array, start: number, pass: PassLayout, bpp: number, warnings: string[]): Uint8Array {
  const { rowBytes } = pass;
  const out = new Uint8Array(pass.height * rowBytes);
  const zero = new Uint8Array(rowBytes);
  let position = start;
  let badFilters = 0;
  for (let row = 0; row < pass.height; row++) {
    const filter = position < raw.length ? raw[position] : 0;
    const line = raw.subarray(position + 1, position + 1 + rowBytes);
    const current = out.subarray(row * rowBytes, (row + 1) * rowBytes);
    const previous = row > 0 ? out.subarray((row - 1) * rowBytes, row * rowBytes) : zero;
    for (let i = 0; i < rowBytes; i++) {
      const x = i < line.length ? line[i] : 0;
      const left = i >= bpp ? current[i - bpp] : 0;
      switch (filter) {
        case 0:
          current[i] = x;
          break;
        case 1:
          current[i] = x + left;
          break;
        case 2:
          current[i] = x + previous[i];
          break;
        case 3:
          current[i] = x + ((left + previous[i]) >> 1);
          break;
        case 4:
          current[i] = x + paeth(left, previous[i], i >= bpp ? previous[i - bpp] : 0);
          break;
        default:
          current[i] = x;
      }
    }
    if (filter > 4) badFilters++;
    position += rowBytes + 1;
  }
  if (badFilters > 0) warnings.push(`${badFilters} row(s) used an invalid filter type and were read unfiltered`);
  return out;
}

export interface PngDecodeOptions {
  maxPixels?: number;
  signal?: AbortSignal;
}

export async function decodePng(
  source: ByteSource,
  structure: PngStructure,
  options: PngDecodeOptions = {},
): Promise<DecodeResult> {
  const { ihdr } = structure;
  if (!ihdr) throw new ImageDecodeError("No valid IHDR chunk");
  const channels = CHANNELS_BY_COLOR_TYPE[ihdr.colorType];
  if (!channels) throw new ImageDecodeError(`Unsupported colour type ${ihdr.colorType}`);
  if (ihdr.compression !== 0 || ihdr.filter !== 0 || ihdr.interlace > 1) {
    throw new ImageDecodeError("Unsupported compression, filter or interlace method");
  }
  const maxPixels = options.maxPixels ?? 100_000_000;
  if (ihdr.width * ihdr.height > maxPixels) {
    throw new ImageDecodeError(`${ihdr.width}×${ihdr.height} exceeds the ${maxPixels.toLocaleString()} pixel limit`);
  }
  if (structure.idat.length === 0) throw new ImageDecodeError("No IDAT data");

  const warnings: string[] = [];
  const expected = expectedRawSize(ihdr);
  const inflated = await inflate(idatSource(source, structure), "zlib", {
    maxOutputBytes: expected + (1 << 20),
    stopAfter: expected,
    signal: options.signal,
  });
  if (inflated.error) warnings.push(`Image data stream error: ${inflated.error}`);
  if (inflated.bytes.length < expected) {
    warnings.push(`Image data is short: ${inflated.bytes.length} of ${expected} bytes; missing pixels are zero`);
  }

  const { bitDepth } = ihdr;
  const count = channels.length;
  const bpp = Math.max(1, (count * bitDepth) >> 3);
  const samples = bitDepth === 16 ? new Uint16Array(ihdr.width * ihdr.height * count) : new Uint8Array(ihdr.width * ihdr.height * count);
  const mask = (1 << Math.min(bitDepth, 8)) - 1;

  let position = 0;
  for (const pass of passLayout(ihdr)) {
    options.signal?.throwIfAborted();
    const data = unfilterPass(inflated.bytes, position, pass, bpp, warnings);
    position += pass.height * (pass.rowBytes + 1);
    for (let row = 0; row < pass.height; row++) {
      const line = data.subarray(row * pass.rowBytes, (row + 1) * pass.rowBytes);
      const y = pass.y0 + row * pass.dy;
      for (let column = 0; column < pass.width; column++) {
        const x = pass.x0 + column * pass.dx;
        const target = (y * ihdr.width + x) * count;
        for (let c = 0; c < count; c++) {
          const sample = column * count + c;
          let value: number;
          if (bitDepth === 16) value = (line[sample * 2] << 8) | line[sample * 2 + 1];
          else if (bitDepth === 8) value = line[sample];
          else {
            const bit = sample * bitDepth;
            value = (line[bit >> 3] >> (8 - bitDepth - (bit & 7))) & mask;
          }
          samples[target + c] = value;
        }
      }
    }
  }

  let palette: Uint8Array | undefined;
  if (ihdr.colorType === 3) {
    if (!structure.palette) warnings.push("Palette image without a PLTE chunk");
    const entries = structure.palette ? Math.floor(structure.palette.length / 3) : 0;
    palette = new Uint8Array(256 * 4);
    for (let i = 0; i < 256; i++) palette[i * 4 + 3] = 255;
    for (let i = 0; i < entries; i++) {
      palette.set(structure.palette!.subarray(i * 3, i * 3 + 3), i * 4);
      palette[i * 4 + 3] = structure.transparency?.[i] ?? 255;
    }
  }

  return {
    image: {
      format: "png",
      width: ihdr.width,
      height: ihdr.height,
      channels,
      bitDepth,
      samples,
      ...(palette ? { palette } : {}),
    },
    warnings,
  };
}
