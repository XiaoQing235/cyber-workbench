import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { MemorySource, readAll } from "../core/bytes/sources";
import { decodePng } from "./png/decode";
import { encodeRgbaPng, pngChunk } from "./png/encode";
import { PNG_SIGNATURE } from "./png/parse";
import { parsePng, type PngChunk } from "./png/parse";

export const MAX_APNG_BYTES = 8 * 1024 * 1024;

export interface ApngFrame {
  index: number;
  width: number;
  height: number;
  left: number;
  top: number;
  delayMs: number;
  disposal: 0 | 1 | 2;
  blend: 0 | 1;
  compressedBytes: number;
}

export interface ApngReport {
  width: number;
  height: number;
  plays: number;
  frameCount: number;
  frames: ApngFrame[];
}

interface InternalFrame {
  info: ApngFrame;
  data: PngChunk[];
}

function uint32(bytes: Bytes, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(offset);
}

async function parseApng(source: ByteSource, signal?: AbortSignal): Promise<{ bytes: Bytes; frames: InternalFrame[]; report: ApngReport }> {
  if (signal?.aborted) throw signal.reason;
  const bytes = await readAll(source, MAX_APNG_BYTES);
  const structure = await parsePng(new MemorySource(bytes), signal);
  const { ihdr } = structure;
  if (!structure.signatureValid || !ihdr || ihdr.colorType !== 6 || ihdr.bitDepth !== 8 || ihdr.interlace !== 0 || ihdr.compression !== 0 || ihdr.filter !== 0) throw new Error("APNG export currently supports non-interlaced 8-bit RGBA images only");
  if (ihdr.width < 1 || ihdr.height < 1 || ihdr.width * ihdr.height > 2_000_000) throw new Error("APNG logical screen exceeds the 2-million-pixel limit");
  if (structure.endOffset !== bytes.length || structure.chunks.some((chunk) => chunk.storedCrc !== chunk.computedCrc) || structure.findings.some((finding) => finding.severity === "strong" || finding.severity === "medium")) throw new Error("APNG chunks are incomplete or failed CRC/structure validation");
  if (structure.chunks.length > 2_000) throw new Error("APNG has too many chunks");

  let expectedFrames = 0;
  let plays = 0;
  let expectedSequence = 0;
  let hasDefaultImage = false;
  let totalFramePixels = 0;
  const frames: InternalFrame[] = [];
  for (const chunk of structure.chunks) {
    const content = bytes.subarray(chunk.offset + 8, chunk.offset + 8 + chunk.length);
    if (chunk.type === "acTL") {
      if (expectedFrames !== 0 || hasDefaultImage || frames.length > 0 || chunk.length !== 8) throw new Error("APNG animation control is missing, repeated, or out of order");
      expectedFrames = uint32(content, 0);
      plays = uint32(content, 4);
      if (expectedFrames < 1 || expectedFrames > 64) throw new Error("APNG requires 1 to 64 declared frames");
    } else if (chunk.type === "fcTL") {
      if (expectedFrames === 0 || chunk.length !== 26 || (frames.length === 0 && hasDefaultImage)) throw new Error("APNG frame control is invalid or the default image is separate");
      if (uint32(content, 0) !== expectedSequence++) throw new Error("APNG frame sequence number is invalid");
      const width = uint32(content, 4);
      const height = uint32(content, 8);
      const left = uint32(content, 12);
      const top = uint32(content, 16);
      if (width < 1 || height < 1 || left + width > ihdr.width || top + height > ihdr.height) throw new Error("APNG frame rectangle exceeds the logical screen");
      totalFramePixels += width * height;
      if (totalFramePixels > 8_000_000) throw new Error("APNG frame pixels exceed the 8-million-pixel budget");
      if (frames.length === 0 && (width !== ihdr.width || height !== ihdr.height || left !== 0 || top !== 0)) throw new Error("APNG first controlled frame must cover the default image");
      const view = new DataView(content.buffer, content.byteOffset, content.byteLength);
      const numerator = view.getUint16(20);
      const denominator = view.getUint16(22) || 100;
      const disposal = content[24];
      const blend = content[25];
      if (disposal > 2 || blend > 1) throw new Error("APNG frame disposal or blend method is unsupported");
      frames.push({ info: { index: frames.length, width, height, left, top, delayMs: numerator * 1_000 / denominator, disposal: disposal as 0 | 1 | 2, blend: blend as 0 | 1, compressedBytes: 0 }, data: [] });
    } else if (chunk.type === "IDAT") {
      if (frames.length !== 1) throw new Error("APNG IDAT must belong to the first controlled frame");
      hasDefaultImage = true;
      frames[0].data.push(chunk);
      frames[0].info.compressedBytes += chunk.length;
    } else if (chunk.type === "fdAT") {
      if (frames.length < 2 || chunk.length < 4 || uint32(content, 0) !== expectedSequence++) throw new Error("APNG frame data is out of order or has an invalid sequence number");
      frames[frames.length - 1].data.push(chunk);
      frames[frames.length - 1].info.compressedBytes += chunk.length - 4;
    }
    if (signal?.aborted) throw signal.reason;
  }
  if (frames.length !== expectedFrames || frames.some((frame) => frame.data.length === 0) || !hasDefaultImage) throw new Error("APNG declared frames do not match the image data");
  return { bytes, frames, report: { width: ihdr.width, height: ihdr.height, plays, frameCount: frames.length, frames: frames.map((frame) => frame.info) } };
}

export async function inspectApng(source: ByteSource, signal?: AbortSignal): Promise<ApngReport> {
  return (await parseApng(source, signal)).report;
}

async function reconstructFrame(bytes: Bytes, frame: InternalFrame, signal?: AbortSignal): Promise<{ png: Bytes; rgba: Bytes }> {
  const ihdr = new Uint8Array(13);
  const view = new DataView(ihdr.buffer);
  view.setUint32(0, frame.info.width);
  view.setUint32(4, frame.info.height);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const compressed = new Uint8Array(frame.info.compressedBytes);
  let offset = 0;
  for (const chunk of frame.data) {
    const payloadStart = chunk.offset + 8 + (chunk.type === "fdAT" ? 4 : 0);
    const payloadEnd = chunk.offset + 8 + chunk.length;
    const payload = bytes.subarray(payloadStart, payloadEnd);
    compressed.set(payload, offset);
    offset += payload.length;
  }
  const parts = [PNG_SIGNATURE, pngChunk("IHDR", ihdr), pngChunk("IDAT", compressed), pngChunk("IEND", new Uint8Array(0))];
  const png = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  offset = 0;
  for (const part of parts) { png.set(part, offset); offset += part.length; }
  const reconstructed = new MemorySource(png);
  const parsed = await parsePng(reconstructed, signal);
  if (parsed.findings.length > 0) throw new Error(`APNG frame ${frame.info.index} could not be rebuilt as a valid PNG`);
  const decoded = await decodePng(reconstructed, parsed, { maxPixels: 2_000_000, signal });
  if (decoded.warnings.length > 0) throw new Error(`APNG frame ${frame.info.index} has incomplete or corrupt pixel data`);
  return { png, rgba: Uint8Array.from(decoded.image.samples) };
}

export async function extractApngFramePng(source: ByteSource, frameIndex: number, signal?: AbortSignal): Promise<{ png: Bytes; report: ApngReport }> {
  const { bytes, frames, report } = await parseApng(source, signal);
  if (!Number.isSafeInteger(frameIndex) || frameIndex < 0 || frameIndex >= frames.length) throw new Error(`APNG frame ${frameIndex} does not exist`);
  return { png: (await reconstructFrame(bytes, frames[frameIndex], signal)).png, report };
}

export async function compositeApngFramePng(source: ByteSource, frameIndex: number, signal?: AbortSignal): Promise<{ png: Bytes; report: ApngReport }> {
  const { bytes, frames, report } = await parseApng(source, signal);
  if (!Number.isSafeInteger(frameIndex) || frameIndex < 0 || frameIndex >= frames.length) throw new Error(`APNG frame ${frameIndex} does not exist`);
  const canvas = new Uint8Array(report.width * report.height * 4);
  let previous: { info: ApngFrame; saved: Bytes | null } | null = null;
  for (let number = 0; number <= frameIndex; number++) {
    if (previous?.info.disposal === 1 || (previous?.info.disposal === 2 && !previous.saved)) {
      for (let row = previous.info.top; row < previous.info.top + previous.info.height; row++) {
        canvas.fill(0, (row * report.width + previous.info.left) * 4, (row * report.width + previous.info.left + previous.info.width) * 4);
      }
    } else if (previous?.info.disposal === 2 && previous.saved) canvas.set(previous.saved);
    const frame = frames[number];
    const { rgba } = await reconstructFrame(bytes, frame, signal);
    const { info } = frame;
    const saved = info.disposal === 2 && number !== 0 ? canvas.slice() : null;
    for (let pixel = 0; pixel < info.width * info.height; pixel++) {
      const dest = ((info.top + Math.floor(pixel / info.width)) * report.width + info.left + (pixel % info.width)) * 4;
      const from = pixel * 4;
      if (info.blend === 0) canvas.set(rgba.subarray(from, from + 4), dest);
      else {
        const sourceAlpha = rgba[from + 3];
        const destinationAlpha = canvas[dest + 3];
        const alphaNumerator = sourceAlpha * 255 + destinationAlpha * (255 - sourceAlpha);
        for (let channel = 0; channel < 3; channel++) {
          canvas[dest + channel] = alphaNumerator === 0 ? 0
            : Math.round((rgba[from + channel] * sourceAlpha * 255 + canvas[dest + channel] * destinationAlpha * (255 - sourceAlpha)) / alphaNumerator);
        }
        canvas[dest + 3] = Math.round(alphaNumerator / 255);
      }
      if (pixel % 65_536 === 0 && signal?.aborted) throw signal.reason;
    }
    previous = { info, saved };
  }
  return { png: await encodeRgbaPng(report.width, report.height, canvas, signal), report };
}