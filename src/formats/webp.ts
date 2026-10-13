import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";

export const MAX_ANIMATED_WEBP_BYTES = 8 * 1024 * 1024;

export interface WebpFrame {
  index: number;
  left: number;
  top: number;
  width: number;
  height: number;
  durationMs: number;
  blend: "over" | "source";
  dispose: "none" | "background";
  encoding: "VP8" | "VP8L";
  alpha: boolean;
  encodedBytes: number;
}

export interface WebpAnimationReport {
  width: number;
  height: number;
  plays: number;
  frameCount: number;
  frames: WebpFrame[];
}

interface FrameChunks { info: WebpFrame; chunks: { offset: number; size: number }[] }

const utf8 = new TextEncoder();
const le24 = (bytes: Bytes, offset: number): number => bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16);
const ascii = (bytes: Bytes, offset: number, length: number): string => String.fromCharCode(...bytes.subarray(offset, offset + length));

function chunk(bytes: Bytes, start: number, limit: number): { name: string; start: number; end: number; paddedEnd: number; length: number } {
  if (start + 8 > limit) throw new Error("WebP chunk header is truncated");
  const length = new DataView(bytes.buffer, bytes.byteOffset + start + 4, 4).getUint32(0, true);
  const end = start + 8 + length;
  const paddedEnd = end + (length & 1);
  if (paddedEnd > limit) throw new Error("WebP chunk payload or padding is truncated");
  return { name: ascii(bytes, start, 4), start, end, paddedEnd, length };
}

async function parseAnimatedWebp(source: ByteSource, signal?: AbortSignal): Promise<{ bytes: Bytes; report: WebpAnimationReport; frames: FrameChunks[] }> {
  if (signal?.aborted) throw signal.reason;
  const bytes = await readAll(source, MAX_ANIMATED_WEBP_BYTES);
  if (bytes.length < 30 || ascii(bytes, 0, 4) !== "RIFF" || ascii(bytes, 8, 4) !== "WEBP" ||
    new DataView(bytes.buffer, bytes.byteOffset + 4, 4).getUint32(0, true) !== bytes.length - 8) throw new Error("Animated WebP requires an exact RIFF/WEBP envelope");
  let width = 0;
  let height = 0;
  let plays = 0;
  let animation = false;
  let animationFlag = false;
  let totalPixels = 0;
  let chunks = 0;
  const frames: FrameChunks[] = [];
  for (let offset = 12; offset < bytes.length;) {
    if (signal?.aborted) throw signal.reason;
    if (++chunks > 2_048) throw new Error("WebP chunk count exceeds the budget");
    const item = chunk(bytes, offset, bytes.length);
    if (item.name === "VP8X") {
      if (width || item.length !== 10 || frames.length || animation || bytes[item.start + 9] || bytes[item.start + 10] || bytes[item.start + 11]) throw new Error("WebP extended header is invalid");
      animationFlag = (bytes[item.start + 8] & 0x02) !== 0;
      width = le24(bytes, item.start + 12) + 1;
      height = le24(bytes, item.start + 15) + 1;
      if (width * height > 2_000_000) throw new Error("WebP canvas exceeds the pixel budget");
    } else if (item.name === "ANIM") {
      if (!animationFlag || animation || item.length !== 6 || frames.length) throw new Error("WebP animation control is invalid");
      plays = bytes[item.start + 12] | (bytes[item.start + 13] << 8);
      animation = true;
    } else if (item.name === "ANMF") {
      if (!animation || item.length < 24 || frames.length >= 64) throw new Error("WebP frame count or animation order is invalid");
      const left = le24(bytes, item.start + 8) * 2;
      const top = le24(bytes, item.start + 11) * 2;
      const frameWidth = le24(bytes, item.start + 14) + 1;
      const frameHeight = le24(bytes, item.start + 17) + 1;
      const durationMs = le24(bytes, item.start + 20);
      const flags = bytes[item.start + 23];
      if (flags & 0xfc || left + frameWidth > width || top + frameHeight > height) throw new Error("WebP frame rectangle or flags are invalid");
      totalPixels += frameWidth * frameHeight;
      if (totalPixels > 8_000_000) throw new Error("WebP frame pixels exceed the budget");
      const parts: FrameChunks["chunks"] = [];
      let encoding: WebpFrame["encoding"] | null = null;
      let alpha = false;
      for (let inner = item.start + 24; inner < item.end;) {
        if (++chunks > 2_048) throw new Error("WebP chunk count exceeds the budget");
        const sub = chunk(bytes, inner, item.end);
        if (sub.name === "ALPH" && !alpha && !encoding && sub.length > 0) alpha = true;
        else if (sub.name === "VP8 " && !encoding && sub.length >= 10) {
          encoding = "VP8";
          if (bytes[sub.start + 11] !== 0x9d || bytes[sub.start + 12] !== 0x01 || bytes[sub.start + 13] !== 0x2a ||
            ((bytes[sub.start + 14] | (bytes[sub.start + 15] << 8)) & 0x3fff) !== frameWidth ||
            ((bytes[sub.start + 16] | (bytes[sub.start + 17] << 8)) & 0x3fff) !== frameHeight) throw new Error("WebP lossy frame dimensions differ from ANMF");
        } else if (sub.name === "VP8L" && !encoding && !alpha && sub.length >= 5) {
          encoding = "VP8L";
          const header = new DataView(bytes.buffer, bytes.byteOffset + sub.start + 9, 4).getUint32(0, true);
          if (bytes[sub.start + 8] !== 0x2f || (header & 0x3fff) + 1 !== frameWidth || ((header >>> 14) & 0x3fff) + 1 !== frameHeight || header >>> 29 !== 0) {
            throw new Error("WebP lossless frame dimensions differ from ANMF");
          }
          alpha = ((header >>> 28) & 1) !== 0;
        } else throw new Error("WebP frame subchunks are unsupported or out of order");
        parts.push({ offset: inner, size: sub.paddedEnd - inner });
        inner = sub.paddedEnd;
      }
      if (!encoding) throw new Error("WebP frame image data is missing");
      frames.push({ info: { index: frames.length, left, top, width: frameWidth, height: frameHeight, durationMs,
        blend: (flags & 2) ? "source" : "over", dispose: (flags & 1) ? "background" : "none", encoding, alpha,
        encodedBytes: parts.reduce((sum, part) => sum + part.size, 0) }, chunks: parts });
    }
    offset = item.paddedEnd;
  }
  if (!animationFlag || !animation || frames.length === 0) throw new Error("WebP animation controls or frames are missing");
  return { bytes, report: { width, height, plays, frameCount: frames.length, frames: frames.map((frame) => frame.info) }, frames };
}

export async function inspectAnimatedWebp(source: ByteSource, signal?: AbortSignal): Promise<WebpAnimationReport> {
  return (await parseAnimatedWebp(source, signal)).report;
}

export async function extractAnimatedWebpFrame(source: ByteSource, frameIndex: number, signal?: AbortSignal): Promise<{ webp: Bytes; frame: WebpFrame }> {
  const { bytes, frames } = await parseAnimatedWebp(source, signal);
  if (!Number.isSafeInteger(frameIndex) || frameIndex < 0 || frameIndex >= frames.length) throw new Error(`WebP frame ${frameIndex} does not exist`);
  const { info, chunks } = frames[frameIndex];
  const result = new Uint8Array(12 + 18 + info.encodedBytes);
  result.set(utf8.encode("RIFF"), 0);
  new DataView(result.buffer).setUint32(4, result.length - 8, true);
  result.set(utf8.encode("WEBPVP8X"), 8);
  new DataView(result.buffer).setUint32(16, 10, true);
  result[20] = info.alpha ? 0x10 : 0;
  for (let index = 0; index < 3; index++) {
    result[24 + index] = ((info.width - 1) >>> (index * 8)) & 0xff;
    result[27 + index] = ((info.height - 1) >>> (index * 8)) & 0xff;
  }
  let offset = 30;
  for (const part of chunks) { result.set(bytes.subarray(part.offset, part.offset + part.size), offset); offset += part.size; }
  return { webp: result, frame: info };
}