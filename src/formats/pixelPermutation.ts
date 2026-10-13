import { Random, MersenneTwister19937 } from "random-js";
import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { readAll, MemorySource } from "../core/bytes/sources";
import { readZip, zipEntryData } from "../core/archive/zip";
import { decodePng } from "./png/decode";
import { encodeRgbaPng } from "./png/encode";
import { parsePng } from "./png/parse";
import { toRgba } from "./image";

const MAX_ARCHIVE_BYTES = 1 * 1024 * 1024;
const SIDE = 64;
const PIXELS = SIDE * SIDE;
const MAX_TOTAL_ATTEMPTS = 10_000_000;
const yieldForCancellation = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

export interface PermutationReport {
  images: string[];
  selectedImage: string;
  width: number;
  height: number;
  seed: number;
  iterations: number;
  accepted: number;
  initialScore: number;
  finalScore: number;
  flagRecovered: false;
}

function neighbors(index: number): number[] {
  const row = Math.floor(index / SIDE);
  const column = index % SIDE;
  return [row > 0 ? index - SIDE : -1, row + 1 < SIDE ? index + SIDE : -1,
    column > 0 ? index - 1 : -1, column + 1 < SIDE ? index + 1 : -1].filter((value) => value >= 0);
}

function scoreAt(images: Uint8ClampedArray[], index: number): number {
  let score = 0;
  const nearby = neighbors(index);
  for (const image of images) {
    for (const other of nearby) {
      for (let channel = 0; channel < 4; channel++) {
        const difference = image[index * 4 + channel] - image[other * 4 + channel];
        score += difference * difference;
      }
    }
  }
  return score;
}

function globalScore(images: Uint8ClampedArray[]): number {
  let score = 0;
  for (let index = 0; index < PIXELS; index++) score += scoreAt(images, index);
  return score;
}

export async function improveSharedPermutation(source: ByteSource, seed: number, iterations: number, signal?: AbortSignal, imageIndex = 0,
  resumeMap = "", previousIterations = 0): Promise<{ png: Bytes; map: number[]; report: PermutationReport }> {
  if (!Number.isSafeInteger(seed) || seed < 0 || seed > 0xffffffff || !Number.isSafeInteger(iterations) || iterations < 1 || iterations > 100_000) {
    throw new Error("Shared pixel permutation seed or iteration budget is invalid");
  }
  if (!Number.isSafeInteger(imageIndex) || imageIndex < 0 || imageIndex >= 64) throw new Error("Shared permutation selected image index exceeds its budget");
  if (!Number.isSafeInteger(previousIterations) || previousIterations < 0 || previousIterations > MAX_TOTAL_ATTEMPTS - iterations ||
    (resumeMap === "") !== (previousIterations === 0)) throw new Error("Shared permutation resume map and previous iteration count must be supplied together (up to ten million cumulative attempts)");
  let positions: number[] | null = null;
  if (resumeMap) {
    if (resumeMap.length > 24_000) throw new Error("Shared permutation resume map exceeds its text budget");
    try { positions = JSON.parse(resumeMap); } catch { throw new Error("Shared permutation resume map must be JSON"); }
    if (!Array.isArray(positions) || positions.length !== PIXELS || positions.some((index) => !Number.isInteger(index) || index < 0 || index >= PIXELS) ||
      new Set(positions).size !== PIXELS) throw new Error("Shared permutation resume map must contain every position exactly once");
  }
  if (signal?.aborted) throw signal.reason;
  const archive = new Blob([await readAll(source, MAX_ARCHIVE_BYTES)]);
  const entries = await readZip(archive);
  if (entries.length < 2 || entries.length > 64 || entries.some((entry) => entry.size > 64 * 1024 || !/^[a-zA-Z0-9._-]+\.png$/i.test(entry.name))) {
    throw new Error("Shared permutation needs 2 to 64 flat PNG files of at most 64 KiB each");
  }
  if (imageIndex >= entries.length) throw new Error("Shared permutation selected image is outside the ZIP");
  const images: Uint8ClampedArray[] = [];
  for (const entry of entries) {
    if (signal?.aborted) throw signal.reason;
    const data = new MemorySource(new Uint8Array(await (await zipEntryData(entry, 64 * 1024)).arrayBuffer()));
    const structure = await parsePng(data, signal);
    if (!structure.signatureValid || structure.findings.length || structure.chunks.some((chunk) => chunk.storedCrc !== chunk.computedCrc) ||
      structure.ihdr?.width !== SIDE || structure.ihdr.height !== SIDE || structure.ihdr.bitDepth !== 8 || structure.ihdr.colorType !== 6) {
      throw new Error(`Image ${entry.name} is not an intact ${SIDE}x${SIDE} 8-bit RGBA PNG`);
    }
    const decoded = await decodePng(data, structure, { maxPixels: PIXELS, signal });
    if (decoded.warnings.length) throw new Error(`Image ${entry.name} could not be decoded without warnings`);
    const pixels = toRgba(decoded.image, false);
    if (positions) {
      const mapped = pixels.slice();
      for (let index = 0; index < PIXELS; index++) mapped.set(pixels.subarray(positions[index] * 4, positions[index] * 4 + 4), index * 4);
      images.push(mapped);
    } else images.push(pixels);
  }
  const initialScore = globalScore(images);
  const random = new Random(MersenneTwister19937.seed(seed));
  // output position -> original encrypted position, matching replayPixelPermutation's inverse mode.
  const map = positions ? positions.slice() : Array.from({ length: PIXELS }, (_, index) => index);
  for (let iteration = 0; iteration < previousIterations; iteration++) {
    if ((iteration & 0x3fff) === 0) {
      if (signal?.aborted) throw signal.reason;
      await yieldForCancellation();
    }
    const row = random.integer(0, SIDE - 1);
    const column = random.integer(0, SIDE - 1);
    random.integer(Math.max(0, row - 10), Math.min(SIDE - 1, row + 10));
    random.integer(Math.max(0, column - 10), Math.min(SIDE - 1, column + 10));
  }
  let accepted = 0;
  for (let iteration = 0; iteration < iterations; iteration++) {
    if ((iteration & 0x3ff) === 0) {
      if (signal?.aborted) throw signal.reason;
      await yieldForCancellation();
    }
    const row = random.integer(0, SIDE - 1);
    const column = random.integer(0, SIDE - 1);
    const otherRow = random.integer(Math.max(0, row - 10), Math.min(SIDE - 1, row + 10));
    const otherColumn = random.integer(Math.max(0, column - 10), Math.min(SIDE - 1, column + 10));
    const first = row * SIDE + column;
    const second = otherRow * SIDE + otherColumn;
    if (first === second) continue;
    const affected = new Set([first, second, ...neighbors(first), ...neighbors(second)]);
    const score = () => [...affected].reduce((sum, index) => sum + scoreAt(images, index), 0);
    const previous = score();
    for (const image of images) {
      for (let channel = 0; channel < 4; channel++) {
        const from = first * 4 + channel;
        const to = second * 4 + channel;
        [image[from], image[to]] = [image[to], image[from]];
      }
    }
    if (score() < previous) {
      accepted++;
      [map[first], map[second]] = [map[second], map[first]];
    }
    else for (const image of images) for (let channel = 0; channel < 4; channel++) {
      const from = first * 4 + channel;
      const to = second * 4 + channel;
      [image[from], image[to]] = [image[to], image[from]];
    }
  }
  const finalScore = globalScore(images);
  return { png: await encodeRgbaPng(SIDE, SIDE, new Uint8Array(images[imageIndex]), signal), map, report: {
    images: entries.map((entry) => entry.name), selectedImage: entries[imageIndex].name,
    width: SIDE, height: SIDE, seed, iterations, accepted, initialScore, finalScore, flagRecovered: false,
  } };
}

/** Replay a known position map on one intact 64x64 RGBA PNG, preserving raw decoded samples. */
export async function replayPixelPermutation(source: ByteSource, mapping: string, signal?: AbortSignal, inverse = false): Promise<{ png: Bytes; pixels: number }> {
  if (mapping.length > 24_000) throw new Error("Pixel permutation map exceeds its text budget");
  let positions: unknown;
  try { positions = JSON.parse(mapping); } catch { throw new Error("Pixel permutation map must be JSON"); }
  if (!Array.isArray(positions) || positions.length !== PIXELS || positions.some((index) => !Number.isInteger(index) || index < 0 || index >= PIXELS) ||
    new Set(positions).size !== PIXELS) throw new Error("Pixel permutation map must contain every position exactly once");
  if (signal?.aborted) throw signal.reason;
  const structure = await parsePng(source, signal);
  if (!structure.signatureValid || structure.findings.length || structure.chunks.some((chunk) => chunk.storedCrc !== chunk.computedCrc) ||
    structure.ihdr?.width !== SIDE || structure.ihdr.height !== SIDE || structure.ihdr.bitDepth !== 8 || structure.ihdr.colorType !== 6) {
    throw new Error("Pixel permutation input must be an intact 64x64 8-bit RGBA PNG");
  }
  const decoded = await decodePng(source, structure, { maxPixels: PIXELS, signal });
  if (decoded.warnings.length) throw new Error("Pixel permutation input could not be decoded without warnings");
  const pixels = toRgba(decoded.image, false);
  const output = new Uint8Array(pixels.length);
  for (let index = 0; index < PIXELS; index++) {
    if ((index & 0x3ff) === 0 && signal?.aborted) throw signal.reason;
    const destination = inverse ? index : positions[index] as number;
    const origin = inverse ? positions[index] as number : index;
    output.set(pixels.subarray(origin * 4, origin * 4 + 4), destination * 4);
  }
  return { png: await encodeRgbaPng(SIDE, SIDE, output, signal), pixels: PIXELS };
}
