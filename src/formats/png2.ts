import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { inflate } from "../core/compression/inflate";
import { idatSource } from "./png/decode";
import { encodeRgbaPng } from "./png/encode";
import { parsePng } from "./png/parse";

const MAX_SIDE = 1024;
const FILTERS = new Set([0, 1, 2, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7]);

export interface Png2Report {
  width: number;
  height: number;
  inflatedBytes: number;
  filterCounts: Record<string, number>;
  chunkCrcsValid: true;
  outputFormat: "PNG RGBA";
}

function hilbertCoordinate(side: number, index: number): [number, number] {
  let position = index;
  let x = 0;
  let y = 0;
  for (let size = 1; size < side; size *= 2) {
    const right = 1 & (position >> 1);
    const up = 1 & (position ^ right);
    if (up === 0) {
      if (right === 1) { x = size - 1 - x; y = size - 1 - y; }
      [x, y] = [y, x];
    }
    x += size * right;
    y += size * up;
    position = Math.floor(position / 4);
  }
  return [x, y];
}

function unfilter(filter: number, current: number, left: number, top: number, topLeft: number, left2: number, left3: number): number {
  switch (filter) {
    case 0: return current;
    case 1: return (current + left) & 255;
    case 2: return (current + top) & 255;
    case 0xe0: return current ^ left;
    case 0xe1: return current ^ top;
    case 0xe2: return current ^ top ^ left ^ topLeft;
    case 0xe3: return (current + left2) & 255;
    case 0xe4: return (current + left3) & 255;
    case 0xe5: return current ^ left2;
    case 0xe6: return current ^ left3;
    case 0xe7: return current ^ left ^ left2 ^ left3;
    default: throw new Error(`Unsupported PNG2 row filter 0x${filter.toString(16)}`);
  }
}

export async function decodePng2(source: ByteSource, signal?: AbortSignal): Promise<{ png: Bytes; report: Png2Report }> {
  if (signal?.aborted) throw signal.reason;
  const structure = await parsePng(source, signal);
  const header = structure.ihdr;
  if (!structure.signatureValid || !header || header.width !== header.height || header.width < 1 || header.width > MAX_SIDE ||
    (header.width & (header.width - 1)) !== 0 || header.bitDepth !== 8 || header.colorType !== 2 ||
    header.compression !== 0 || header.filter !== 0xc0 || header.interlace !== 0xde ||
    structure.idat.length === 0 || structure.endOffset !== source.size ||
    structure.chunks.some((chunk) => chunk.storedCrc !== chunk.computedCrc) ||
    structure.findings.some((finding) => finding.id !== "png.ihdr.methods")) {
    throw new Error("PNG2 requires complete CRC-valid chunks and custom 8-bit RGB filter/interlace markers");
  }
  const side = header.width;
  const rowBytes = side * 3 + 1;
  const expected = side * rowBytes;
  const inflated = await inflate(idatSource(source, structure), "zlib", { maxOutputBytes: expected, signal });
  if (inflated.error || inflated.stoppedEarly || inflated.bytes.length !== expected) throw new Error("PNG2 IDAT stream is incomplete or its filtered pixel size is invalid");
  const filtered = inflated.bytes;
  const pixels = new Uint8Array(side * side * 3);
  const output = new Uint8Array(side * side * 4);
  const filterCounts: Record<string, number> = {};
  for (let row = 0; row < side; row++) {
    if ((row & 31) === 0 && signal?.aborted) throw signal.reason;
    const filter = filtered[row * rowBytes];
    if (!FILTERS.has(filter)) throw new Error(`PNG2 row ${row} has an unsupported filter 0x${filter.toString(16)}`);
    const label = `0x${filter.toString(16).padStart(2, "0")}`;
    filterCounts[label] = (filterCounts[label] ?? 0) + 1;
    for (let column = 0; column < side; column++) {
      const pixel = (row * side + column) * 3;
      for (let color = 0; color < 3; color++) {
        const current = filtered[row * rowBytes + 1 + column * 3 + color];
        const left = column ? pixels[pixel - 3 + color] : 0;
        const top = row ? pixels[pixel - side * 3 + color] : 0;
        const topLeft = column && row ? pixels[pixel - (side + 1) * 3 + color] : 0;
        const left2 = column > 1 ? pixels[pixel - 6 + color] : 0;
        const left3 = column > 2 ? pixels[pixel - 9 + color] : 0;
        pixels[pixel + color] = unfilter(filter, current, left, top, topLeft, left2, left3);
      }
      const [x, y] = hilbertCoordinate(side, row * side + column);
      output.set(pixels.subarray(pixel, pixel + 3), (y * side + x) * 4);
      output[(y * side + x) * 4 + 3] = 255;
    }
  }
  return { png: await encodeRgbaPng(side, side, output, signal), report: { width: side, height: side, inflatedBytes: expected,
    filterCounts, chunkCrcsValid: true, outputFormat: "PNG RGBA" } };
}