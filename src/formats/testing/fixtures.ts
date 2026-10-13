import type { Bytes } from "../../core/bytes/ByteSource";
import { crc32 } from "../../core/checksum/crc32";

/** Test-only builders that produce real files byte by byte. */

export function concat(...parts: Uint8Array[]): Bytes {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export async function compress(bytes: Bytes, format: CompressionFormat = "deflate"): Promise<Bytes> {
  const stream = new Blob([bytes]).stream().pipeThrough(new CompressionStream(format));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

const u32be = (value: number) => Uint8Array.of(value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
const ascii = (text: string) => Uint8Array.from(text, (c) => c.charCodeAt(0));

export function pngChunk(type: string, data: Uint8Array, crcOverride?: number): Bytes {
  const body = concat(ascii(type), data);
  return concat(u32be(data.length), body, u32be(crcOverride ?? crc32(body)));
}

function paeth(a: number, b: number, c: number): number {
  const p = a + b - c;
  const pa = Math.abs(p - a);
  const pb = Math.abs(p - b);
  const pc = Math.abs(p - c);
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

/** Applies PNG scanline filters (the encoder side), prefixing each row with its filter byte. */
export function filterRows(raw: Uint8Array, rowBytes: number, bpp: number, filters: readonly number[]): Bytes {
  const rows = raw.length / rowBytes;
  const out = new Uint8Array(rows * (rowBytes + 1));
  for (let row = 0; row < rows; row++) {
    const filter = filters[row % filters.length];
    const current = raw.subarray(row * rowBytes, (row + 1) * rowBytes);
    const previous = row > 0 ? raw.subarray((row - 1) * rowBytes, row * rowBytes) : new Uint8Array(rowBytes);
    out[row * (rowBytes + 1)] = filter;
    for (let i = 0; i < rowBytes; i++) {
      const left = i >= bpp ? current[i - bpp] : 0;
      const up = previous[i];
      const upLeft = i >= bpp ? previous[i - bpp] : 0;
      const predictor = [0, left, up, (left + up) >> 1, paeth(left, up, upLeft)][filter];
      out[row * (rowBytes + 1) + 1 + i] = (current[i] - predictor) & 255;
    }
  }
  return out;
}

const ADAM7 = [
  [0, 0, 8, 8],
  [4, 0, 8, 8],
  [0, 4, 4, 8],
  [2, 0, 4, 4],
  [0, 2, 2, 4],
  [1, 0, 2, 2],
  [0, 1, 1, 2],
] as const;

export interface PngOptions {
  width: number;
  height: number;
  colorType: number;
  bitDepth: number;
  /** Packed scanlines without filter bytes (height × rowBytes), top-down. */
  pixels: Uint8Array;
  filters?: readonly number[];
  /** Adam7 interlacing; supported for bit depths of 8 and 16 only. */
  interlace?: boolean;
  palette?: Uint8Array;
  extraChunks?: readonly [string, Uint8Array][];
  trailing?: Uint8Array;
}

const CHANNELS: Record<number, number> = { 0: 1, 2: 3, 3: 1, 4: 2, 6: 4 };

export async function makePng(options: PngOptions): Promise<Bytes> {
  const { width, height, colorType, bitDepth, pixels } = options;
  const bitsPerPixel = CHANNELS[colorType] * bitDepth;
  const bpp = Math.max(1, bitsPerPixel >> 3);
  const rowBytes = Math.ceil((width * bitsPerPixel) / 8);
  const filters = options.filters ?? [0];

  let stream: Bytes;
  if (!options.interlace) {
    stream = filterRows(pixels, rowBytes, bpp, filters);
  } else {
    const passes: Bytes[] = [];
    for (const [x0, y0, dx, dy] of ADAM7) {
      const passWidth = Math.ceil((width - x0) / dx);
      const passHeight = Math.ceil((height - y0) / dy);
      if (passWidth <= 0 || passHeight <= 0) continue;
      const passRaw = new Uint8Array(passWidth * passHeight * bpp);
      for (let r = 0; r < passHeight; r++) {
        for (let c = 0; c < passWidth; c++) {
          const from = (y0 + r * dy) * rowBytes + (x0 + c * dx) * bpp;
          passRaw.set(pixels.subarray(from, from + bpp), (r * passWidth + c) * bpp);
        }
      }
      passes.push(filterRows(passRaw, passWidth * bpp, bpp, filters));
    }
    stream = concat(...passes);
  }

  const ihdr = concat(u32be(width), u32be(height), Uint8Array.of(bitDepth, colorType, 0, 0, options.interlace ? 1 : 0));
  return concat(
    Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a),
    pngChunk("IHDR", ihdr),
    ...(options.palette ? [pngChunk("PLTE", options.palette)] : []),
    ...(options.extraChunks ?? []).map(([type, data]) => pngChunk(type, data)),
    pngChunk("IDAT", await compress(stream)),
    pngChunk("IEND", new Uint8Array(0)),
    options.trailing ?? new Uint8Array(0),
  );
}

/** Overwrites IHDR width/height in a built PNG without touching the CRC (simulated tampering). */
export function tamperDimensions(png: Uint8Array, width: number, height: number): Bytes {
  const copy = new Uint8Array(png);
  copy.set(u32be(width), 16);
  copy.set(u32be(height), 20);
  return copy;
}

/** 24-bit bottom-up BMP from top-down RGB pixels. `extraRows` appends hidden rows after the declared ones. */
export function makeBmp24(width: number, height: number, rgbTopDown: Uint8Array, extraRows = 0): Bytes {
  const stride = Math.floor((24 * width + 31) / 32) * 4;
  const storedRows = height + extraRows;
  const pixelBytes = stride * storedRows;
  const file = new Uint8Array(54 + pixelBytes);
  const view = new DataView(file.buffer);
  file.set(ascii("BM"), 0);
  view.setUint32(2, file.length, true);
  view.setUint32(10, 54, true);
  view.setUint32(14, 40, true);
  view.setInt32(18, width, true);
  view.setInt32(22, height, true);
  view.setUint16(26, 1, true);
  view.setUint16(28, 24, true);
  view.setUint32(34, pixelBytes, true);
  // Visible rows are stored bottom-up. Rows from index `height` on are stored after them, as in a BMP whose
  // height was reduced: once the height is restored they appear above the visible part.
  for (let y = 0; y < storedRows; y++) {
    const storedIndex = y < height ? height - 1 - y : y;
    for (let x = 0; x < width; x++) {
      const from = (y * width + x) * 3;
      const to = 54 + storedIndex * stride + x * 3;
      file[to] = rgbTopDown[from + 2] ?? 0;
      file[to + 1] = rgbTopDown[from + 1] ?? 0;
      file[to + 2] = rgbTopDown[from] ?? 0;
    }
  }
  return file;
}
