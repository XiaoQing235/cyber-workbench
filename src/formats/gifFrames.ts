import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";
import { encodeRgbaPng } from "./png/encode";

export const MAX_GIF_BYTES = 4 * 1024 * 1024;
const MAX_LOGICAL_PIXELS = 2_000_000;
const MAX_FRAME_PIXELS = 4_000_000;
const MAX_FRAMES = 64;

export interface GifFrameInfo {
  index: number;
  left: number;
  top: number;
  width: number;
  height: number;
  delayMs: number;
  disposal: number;
  transparentIndex: number | null;
  transparentRgb: [number, number, number] | null;
}

export interface GifFrameReport {
  version: string;
  width: number;
  height: number;
  frameCount: number;
  frames: GifFrameInfo[];
}

async function readGif(source: ByteSource, signal?: AbortSignal) {
  if (signal?.aborted) throw signal.reason;
  const bytes = await readAll(source, MAX_GIF_BYTES);
  if (bytes.length < 14 || bytes[0] !== 0x47 || bytes[1] !== 0x49 || bytes[2] !== 0x46 || bytes.at(-1) !== 0x3b) throw new Error("Input is not a complete GIF image");
  const { parseGIF, decompressFrame } = await import("gifuct-js");
  const parsed = parseGIF(bytes.buffer);
  const { width, height } = parsed.lsd;
  if (width < 1 || height < 1 || width > 4096 || height > 4096 || width * height > MAX_LOGICAL_PIXELS) throw new Error("GIF logical screen exceeds the 2-million-pixel limit");
  const frames = parsed.frames.filter((entry): entry is Extract<typeof entry, { image: unknown }> => "image" in entry);
  if (frames.length < 1 || frames.length > MAX_FRAMES) throw new Error("GIF must contain 1 to 64 image frames");
  let totalPixels = 0;
  const infos: GifFrameInfo[] = frames.map((frame, index) => {
    const rect = frame.image.descriptor;
    if (rect.width < 1 || rect.height < 1 || rect.left + rect.width > width || rect.top + rect.height > height) throw new Error(`GIF frame ${index} rectangle exceeds the logical screen`);
    totalPixels += rect.width * rect.height;
    if (totalPixels > MAX_FRAME_PIXELS) throw new Error("GIF image frames exceed the 4-million-pixel budget");
    const transparentIndex = frame.gce?.extras?.transparentColorGiven ? frame.gce.transparentColorIndex : null;
    const localTable = (frame.image as typeof frame.image & { lct?: ArrayLike<ArrayLike<number>> }).lct;
    const table = frame.image.descriptor.lct.exists ? localTable : parsed.gct;
    const color = transparentIndex === null ? null : table?.[transparentIndex];
    if (transparentIndex !== null && (!color || color.length !== 3)) throw new Error(`GIF frame ${index} transparent index is missing from its palette`);
    return {
      index, left: rect.left, top: rect.top, width: rect.width, height: rect.height,
      delayMs: frame.gce?.delay === undefined ? 0 : frame.gce.delay * 10,
      disposal: frame.gce?.extras?.disposal ?? 0,
      transparentIndex,
      transparentRgb: color ? [color[0], color[1], color[2]] : null,
    };
  });
  if (signal?.aborted) throw signal.reason;
  return { parsed, frames, infos, decompressFrame, report: { version: parsed.header.version, width, height, frameCount: frames.length, frames: infos } };
}

export async function inspectGifFrames(source: ByteSource, signal?: AbortSignal): Promise<GifFrameReport> {
  return (await readGif(source, signal)).report;
}

/** Preserve the raw frame delays as a reproducible local animation sequence. */
export async function gifFrameTimeline(source: ByteSource, signal?: AbortSignal): Promise<{
  frames: { index: number; startMs: number; delayMs: number; disposal: number }[]; durationMs: number;
}> {
  const report = await inspectGifFrames(source, signal);
  let durationMs = 0;
  const frames = report.frames.map((frame) => {
    const entry = { index: frame.index, startMs: durationMs, delayMs: frame.delayMs, disposal: frame.disposal };
    durationMs += frame.delayMs;
    return entry;
  });
  return { frames, durationMs };
}

export async function extractGifFrameRgba(source: ByteSource, frameIndex: number, revealTransparentRgb: boolean, signal?: AbortSignal): Promise<{ report: GifFrameReport; rgba: Bytes; transparentPixels: number }> {
  const { parsed, frames, infos, decompressFrame, report } = await readGif(source, signal);
  if (!Number.isSafeInteger(frameIndex) || frameIndex < 0 || frameIndex >= frames.length) throw new Error(`GIF frame ${frameIndex} does not exist`);
  const frame = decompressFrame(frames[frameIndex], parsed.gct, false);
  const info = infos[frameIndex];
  if (frame.pixels.length !== info.width * info.height) throw new Error(`GIF frame ${frameIndex} has incomplete decoded pixels`);
  const rgba = new Uint8Array(report.width * report.height * 4);
  let transparentPixels = 0;
  for (let index = 0; index < frame.pixels.length; index++) {
    const paletteIndex = frame.pixels[index];
    const color = frame.colorTable?.[paletteIndex];
    if (!color || color.length !== 3) throw new Error(`GIF frame ${frameIndex} palette index ${paletteIndex} is invalid`);
    const position = ((info.top + Math.floor(index / info.width)) * report.width + info.left + (index % info.width)) * 4;
    rgba.set(color, position);
    const transparent = paletteIndex === info.transparentIndex;
    if (transparent) transparentPixels++;
    rgba[position + 3] = transparent && !revealTransparentRgb ? 0 : 255;
    if (index % 65_536 === 0 && signal?.aborted) throw signal.reason;
  }
  return { report, rgba, transparentPixels };
}

export async function compositeGifFrameRgba(source: ByteSource, frameIndex: number, background: "palette" | "transparent", signal?: AbortSignal): Promise<{ report: GifFrameReport; rgba: Bytes }> {
  const { parsed, frames, infos, decompressFrame, report } = await readGif(source, signal);
  if (!Number.isSafeInteger(frameIndex) || frameIndex < 0 || frameIndex >= frames.length) throw new Error(`GIF frame ${frameIndex} does not exist`);
  const backgroundColor = parsed.gct?.[parsed.lsd.backgroundColorIndex];
  if (background === "palette" && (!backgroundColor || backgroundColor.length !== 3)) throw new Error("GIF logical screen has no valid palette background");
  const fill = background === "palette" ? [backgroundColor[0], backgroundColor[1], backgroundColor[2], 255] : [0, 0, 0, 0];
  const rgba = new Uint8Array(report.width * report.height * 4);
  const fillRect = (info: GifFrameInfo) => {
    for (let row = info.top; row < info.top + info.height; row++) {
      for (let column = info.left; column < info.left + info.width; column++) rgba.set(fill, (row * report.width + column) * 4);
    }
  };
  fillRect({ ...infos[0], top: 0, left: 0, width: report.width, height: report.height });
  let previous: { info: GifFrameInfo; saved: Bytes | null } | null = null;
  for (let frameNumber = 0; frameNumber <= frameIndex; frameNumber++) {
    if (previous?.info.disposal === 2) fillRect(previous.info);
    if (previous?.info.disposal === 3 && previous.saved) rgba.set(previous.saved);
    const info = infos[frameNumber];
    const frame = decompressFrame(frames[frameNumber], parsed.gct, false);
    if (frame.pixels.length !== info.width * info.height) throw new Error(`GIF frame ${frameNumber} has incomplete decoded pixels`);
    const saved = info.disposal === 3 ? rgba.slice() : null;
    for (let index = 0; index < frame.pixels.length; index++) {
      const paletteIndex = frame.pixels[index];
      if (paletteIndex === info.transparentIndex) continue;
      const color = frame.colorTable?.[paletteIndex];
      if (!color || color.length !== 3) throw new Error(`GIF frame ${frameNumber} palette index ${paletteIndex} is invalid`);
      const position = ((info.top + Math.floor(index / info.width)) * report.width + info.left + (index % info.width)) * 4;
      rgba.set(color, position);
      rgba[position + 3] = 255;
      if (index % 65_536 === 0 && signal?.aborted) throw signal.reason;
    }
    previous = { info, saved };
  }
  return { report, rgba };
}

export async function exportGifFramePng(source: ByteSource, frameIndex: number, revealTransparentRgb: boolean, signal?: AbortSignal): Promise<{ report: GifFrameReport; png: Bytes; transparentPixels: number }> {
  const { report, rgba, transparentPixels } = await extractGifFrameRgba(source, frameIndex, revealTransparentRgb, signal);
  const png = await encodeRgbaPng(report.width, report.height, rgba, signal);
  return { report, png, transparentPixels };
}

export async function exportCompositedGifFramePng(source: ByteSource, frameIndex: number, background: "palette" | "transparent", signal?: AbortSignal): Promise<{ report: GifFrameReport; png: Bytes }> {
  const { report, rgba } = await compositeGifFrameRgba(source, frameIndex, background, signal);
  return { report, png: await encodeRgbaPng(report.width, report.height, rgba, signal) };
}

export async function compareGifFrames(source: ByteSource, firstIndex: number, secondIndex: number, mode: "difference" | "xor", background: "palette" | "transparent", signal?: AbortSignal): Promise<{ png: Bytes; changedPixels: number; width: number; height: number }> {
  if (firstIndex === secondIndex) throw new Error("GIF frame comparison requires two different indexes");
  const first = await compositeGifFrameRgba(source, firstIndex, background, signal);
  const second = await compositeGifFrameRgba(source, secondIndex, background, signal);
  const rgba = new Uint8Array(first.rgba.length);
  let changedPixels = 0;
  for (let pixel = 0; pixel < rgba.length; pixel += 4) {
    let changed = false;
    for (let channel = 0; channel < 4; channel++) {
      if (first.rgba[pixel + channel] !== second.rgba[pixel + channel]) changed = true;
    }
    if (changed) changedPixels++;
    for (let channel = 0; channel < 3; channel++) {
      rgba[pixel + channel] = mode === "difference"
        ? Math.abs(first.rgba[pixel + channel] - second.rgba[pixel + channel])
        : first.rgba[pixel + channel] ^ second.rgba[pixel + channel];
    }
    if (changed && rgba[pixel] === 0 && rgba[pixel + 1] === 0 && rgba[pixel + 2] === 0) rgba[pixel] = Math.abs(first.rgba[pixel + 3] - second.rgba[pixel + 3]);
    rgba[pixel + 3] = 255;
    if (pixel % (65_536 * 4) === 0 && signal?.aborted) throw signal.reason;
  }
  return { png: await encodeRgbaPng(first.report.width, first.report.height, rgba, signal), changedPixels, width: first.report.width, height: first.report.height };
}
