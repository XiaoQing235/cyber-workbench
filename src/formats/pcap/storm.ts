import type { Bytes } from "../../core/bytes/ByteSource";
import { parseCapture } from "./capture";

const WIDTH = 256;
const HEIGHT = 256;
const STORM_OFFSET = 14 + 3 + 30;

export interface StormPylonMap {
  mask: Uint8Array<ArrayBuffer>;
  packets: number;
  matches: number;
  uniquePoints: number;
  outOfBounds: number;
  clusters: { left: number; top: number; right: number; bottom: number; points: number }[];
}

const GLYPHS: Readonly<Record<string, string>> = {
  "..#.#.#.#../#.........#/.........../#........../.........../#...#.#..../..#.....#../#.........#/.........../#.........#/..#.#.#.#..": "6",
  "#.#.#../......./#.....#/......./#.....#/..#.#../#....../......./#....../......./#......": "P",
  "..#.#../..#.#../#.....#/......./#.....#/......./..#.#..": "o",
  "..#.#../......./#.....#/......./#.....#/......./..#.#..": "o",
  "#..../...../#..../...../#..../...../#..../...../#...#/..#..": "l",
};

/** Read only exact sparse glyph shapes from a plotted Storm map. Unknown points remain unreadable. */
export function readStormPylonText(mask: Uint8Array): { text: string | null; markerPoints: number; unreadableGlyphs: number } {
  if (mask.length !== WIDTH * HEIGHT) throw new Error("Storm pylon map must be 256x256");
  const columns = new Array<number>(WIDTH).fill(0);
  for (let y = 0; y < HEIGHT; y++) for (let x = 0; x < WIDTH; x++) if (mask[x + y * WIDTH]) columns[x]++;
  const groups: { left: number; right: number }[] = [];
  let left = -1;
  let last = -1;
  for (let x = 0; x < WIDTH; x++) {
    if (!columns[x]) continue;
    if (left >= 0 && x - last > 2) { groups.push({ left, right: last }); left = -1; }
    if (left < 0) left = x;
    last = x;
  }
  if (left >= 0) groups.push({ left, right: last });
  let markerPoints = 0;
  let unreadableGlyphs = 0;
  const decoded: string[] = [];
  for (const group of groups) {
    let top = HEIGHT;
    let bottom = -1;
    let points = 0;
    for (let y = 0; y < HEIGHT; y++) for (let x = group.left; x <= group.right; x++) if (mask[x + y * WIDTH]) {
      top = Math.min(top, y); bottom = Math.max(bottom, y); points++;
    }
    const shape = Array.from({ length: bottom - top + 1 }, (_, row) => Array.from({ length: group.right - group.left + 1 }, (_, column) =>
      mask[group.left + column + (top + row) * WIDTH] ? "#" : ".").join("")).join("/");
    if (shape === "#.#/.../#.#" && points === 4) { markerPoints += points; continue; }
    const letter = GLYPHS[shape];
    if (!letter) unreadableGlyphs++;
    else decoded.push(letter);
  }
  return { text: decoded.length && unreadableGlyphs === 0 ? decoded.join("") : null, markerPoints, unreadableGlyphs };
}

export function plotStormPylons(bytes: Bytes, buildingId = 0x9c, signal?: AbortSignal): StormPylonMap {
  if (!Number.isSafeInteger(buildingId) || buildingId < 0 || buildingId > 255) throw new Error("Storm building ID must be one byte");
  if (bytes.length > 8 * 1024 * 1024) throw new Error("Storm capture exceeds 8 MiB");
  const capture = parseCapture(bytes, 50_000);
  if (capture.warnings.length > 0) throw new Error(`Storm capture has unreadable or truncated packets: ${capture.warnings[0]}`);
  const mask = new Uint8Array(WIDTH * HEIGHT);
  let matches = 0;
  let uniquePoints = 0;
  let outOfBounds = 0;
  for (const packet of capture.packets) {
    if (signal?.aborted) throw signal.reason;
    const data = packet.data;
    if (packet.linkType !== 1 || data.length < STORM_OFFSET + 26 || (data[12] << 8 | data[13]) >= 1536 ||
      data[14] !== 0xe0 || data[15] !== 0xe0 || data[16] !== 0x03) continue;
    const offset = STORM_OFFSET;
    if (data[offset + 12] !== 0x37 || data[offset + 19] !== 0x0c || data[offset + 25] !== buildingId) continue;
    matches++;
    const x = data[offset + 21] | data[offset + 22] << 8;
    const y = data[offset + 23] | data[offset + 24] << 8;
    if (x >= WIDTH || y >= HEIGHT) { outOfBounds++; continue; }
    const index = x + y * WIDTH;
    if (mask[index] === 0) uniquePoints++;
    mask[index] = 255;
  }
  const columns = new Array<number>(WIDTH).fill(0);
  for (let y = 0; y < HEIGHT; y++) for (let x = 0; x < WIDTH; x++) if (mask[x + y * WIDTH]) columns[x]++;
  const clusters: StormPylonMap["clusters"] = [];
  // Columns separated by at least three empty x positions form candidate visual groups.
  let left = -1;
  let last = -1;
  const add = (right: number) => {
    let top = HEIGHT;
    let bottom = -1;
    let points = 0;
    for (let y = 0; y < HEIGHT; y++) for (let x = left; x <= right; x++) if (mask[x + y * WIDTH]) {
      top = Math.min(top, y);
      bottom = Math.max(bottom, y);
      points++;
    }
    if (points) clusters.push({ left, top, right, bottom, points });
  };
  for (let x = 0; x < WIDTH; x++) {
    if (!columns[x]) continue;
    if (left >= 0 && x - last > 3) { add(last); left = -1; }
    if (left < 0) left = x;
    last = x;
  }
  if (left >= 0) add(last);
  return { mask, packets: capture.packets.length, matches, uniquePoints, outOfBounds, clusters };
}
