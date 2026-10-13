import jsQR from "jsqr";
import type { DecodedImage } from "./image";
import { toRgba } from "./image";

/** Modules by row then column; true is dark. */
export type Grid = boolean[][];
export type Inversion = "dontInvert" | "onlyInvert" | "attemptBoth" | "invertFirst";
export type ErrorCorrection = "L" | "M" | "Q" | "H";

export class QrError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "QrError";
  }
}

export interface QrResult {
  text: string;
  bytes: Uint8Array;
  version: number;
}

export function decodeRgba(rgba: Uint8ClampedArray, width: number, height: number, inversion: Inversion): QrResult | null {
  const result = jsQR(rgba, width, height, { inversionAttempts: inversion });
  return result ? { text: result.data, bytes: Uint8Array.from(result.binaryData), version: result.version } : null;
}

const DARK = new Set(["1", "#", "X", "x", "*", "█", "■"]);
const LIGHT = new Set(["0", ".", " ", "_", "-", "□", "░"]);

export function parseGrid(text: string): Grid {
  const lines = text.split(/\r?\n/).map((line) => line.replace(/\s+$/, "")).filter((line) => line.length > 0);
  const size = lines.length;
  if (size < 21 || size > 177 || (size - 17) % 4 !== 0) {
    throw new QrError(`A QR code is 21, 25, 29 \u2026 177 modules square; this grid has ${size} rows`);
  }
  return lines.map((line, row) => {
    const chars = [...line];
    if (chars.length > size) throw new QrError(`Row ${row + 1} has ${chars.length} modules; expected at most ${size}`);
    return Array.from({ length: size }, (_, column) => {
      const char = chars[column] ?? ".";
      if (DARK.has(char)) return true;
      if (LIGHT.has(char)) return false;
      throw new QrError(`Unexpected "${char}" at row ${row + 1}, column ${column + 1}; use # or 1 for dark and . or 0 for light`);
    });
  });
}

export const gridToText = (grid: Grid) => grid.map((row) => row.map((dark) => (dark ? "#" : ".")).join("")).join("\n");

const copy = (grid: Grid) => grid.map((row) => [...row]);

function alignmentPositions(version: number): number[] {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const size = version * 4 + 17;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const positions = [6];
  for (let pos = size - 7; positions.length < count; pos -= step) positions.splice(1, 0, pos);
  return positions;
}

/** Rewrites finder, separator, timing and alignment patterns, version information and the dark module from the spec. */
export function restoreFunctionPatterns(grid: Grid): Grid {
  const out = copy(grid);
  const size = out.length;
  const version = (size - 17) / 4;
  const set = (x: number, y: number, dark: boolean) => {
    if (x >= 0 && y >= 0 && x < size && y < size) out[y][x] = dark;
  };
  for (let i = 8; i < size - 8; i++) {
    set(6, i, i % 2 === 0);
    set(i, 6, i % 2 === 0);
  }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const distance = Math.max(Math.abs(dx), Math.abs(dy));
        set(cx + dx, cy + dy, distance !== 2 && distance !== 4);
      }
    }
  }
  const positions = alignmentPositions(version);
  positions.forEach((y, i) =>
    positions.forEach((x, j) => {
      const last = positions.length - 1;
      if ((i === 0 && j === 0) || (i === 0 && j === last) || (i === last && j === 0)) return;
      for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }),
  );
  if (version >= 7) {
    let remainder = version;
    for (let i = 0; i < 12; i++) remainder = (remainder << 1) ^ ((remainder >>> 11) * 0x1f25);
    const bits = (version << 12) | remainder;
    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) === 1;
      set(size - 11 + (i % 3), Math.floor(i / 3), dark);
      set(Math.floor(i / 3), size - 11 + (i % 3), dark);
    }
  }
  set(8, size - 8, true);
  return out;
}

const EC_BITS: Record<ErrorCorrection, number> = { L: 1, M: 0, Q: 3, H: 2 };

export function formatBits(level: ErrorCorrection, mask: number): number {
  const data = (EC_BITS[level] << 3) | mask;
  let remainder = data;
  for (let i = 0; i < 10; i++) remainder = (remainder << 1) ^ ((remainder >>> 9) * 0x537);
  return ((data << 10) | remainder) ^ 0x5412;
}

/** Writes both copies of the 15-bit format information. */
export function writeFormat(grid: Grid, bits: number): Grid {
  const out = copy(grid);
  const size = out.length;
  const set = (x: number, y: number, i: number) => (out[y][x] = ((bits >>> i) & 1) === 1);
  for (let i = 0; i <= 5; i++) set(8, i, i);
  set(8, 7, 6);
  set(8, 8, 7);
  set(7, 8, 8);
  for (let i = 9; i < 15; i++) set(14 - i, 8, i);
  for (let i = 0; i < 8; i++) set(size - 1 - i, 8, i);
  for (let i = 8; i < 15; i++) set(8, size - 15 + i, i);
  out[size - 8][8] = true;
  return out;
}

/** RGBA pixels with a 4-module quiet zone, `scale` pixels per module. */
export function renderGrid(grid: Grid, scale: number): { width: number; height: number; rgba: Uint8ClampedArray<ArrayBuffer> } {
  const side = (grid.length + 8) * scale;
  const rgba = new Uint8ClampedArray(side * side * 4).fill(255);
  grid.forEach((row, y) =>
    row.forEach((dark, x) => {
      if (!dark) return;
      for (let py = 0; py < scale; py++) {
        const start = (((y + 4) * scale + py) * side + (x + 4) * scale) * 4;
        for (let px = 0; px < scale; px++) rgba.fill(0, start + px * 4, start + px * 4 + 3);
      }
    }),
  );
  return { width: side, height: side, rgba };
}

export function decodeGrid(grid: Grid, inversion: Inversion = "attemptBoth"): QrResult | null {
  const { width, height, rgba } = renderGrid(grid, 4);
  return decodeRgba(rgba, width, height, inversion);
}

/** Tries every error-correction level and mask for damaged format information. */
export function decodeWithAnyFormat(grid: Grid, inversion: Inversion): { result: QrResult; level: ErrorCorrection; mask: number } | null {
  // Strongest first: a code also reads as any weaker level (its Reed–Solomon generator divides the stronger one).
  for (const level of ["H", "Q", "M", "L"] as const) {
    for (let mask = 0; mask < 8; mask++) {
      const result = decodeGrid(writeFormat(grid, formatBits(level, mask)), inversion);
      if (result) return { result, level, mask };
    }
  }
  return null;
}

/** Samples a clean, axis-aligned code (the usual CTF image) into modules. `size` 0 estimates it from the finder pattern. */
export function imageToGrid(image: DecodedImage, size: number): Grid {
  const rgba = toRgba(image, true);
  const { width, height } = image;
  const luma = new Float32Array(width * height);
  let min = 255;
  let max = 0;
  for (let p = 0; p < luma.length; p++) {
    luma[p] = 0.299 * rgba[p * 4] + 0.587 * rgba[p * 4 + 1] + 0.114 * rgba[p * 4 + 2];
    min = Math.min(min, luma[p]);
    max = Math.max(max, luma[p]);
  }
  const threshold = (min + max) / 2;
  const dark = (x: number, y: number) => luma[y * width + x] < threshold;
  let [left, top, right, bottom] = [width, height, -1, -1];
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      if (!dark(x, y)) continue;
      left = Math.min(left, x);
      right = Math.max(right, x);
      top = Math.min(top, y);
      bottom = Math.max(bottom, y);
    }
  }
  if (right < 0) throw new QrError("The image has no dark pixels");
  const spanX = right - left + 1;
  const spanY = bottom - top + 1;
  let modules = size;
  if (modules === 0) {
    let run = 0;
    while (left + run <= right && dark(left + run, top)) run++;
    const estimate = Math.round(spanX / (run / 7));
    modules = Math.min(177, Math.max(21, 17 + 4 * Math.round((estimate - 17) / 4)));
  }
  return Array.from({ length: modules }, (_, row) =>
    Array.from({ length: modules }, (_, column) => {
      const x = Math.min(right, Math.floor(left + ((column + 0.5) * spanX) / modules));
      const y = Math.min(bottom, Math.floor(top + ((row + 0.5) * spanY) / modules));
      return dark(x, y);
    }),
  );
}
