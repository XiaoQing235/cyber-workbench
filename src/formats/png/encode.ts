import type { Bytes } from "../../core/bytes/ByteSource";
import { crc32 } from "../../core/checksum/crc32";
import { PNG_SIGNATURE } from "./parse";

export function pngChunk(type: string, data: Bytes): Bytes {
  const bytes = new Uint8Array(12 + data.length);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, data.length);
  for (let index = 0; index < 4; index++) bytes[4 + index] = type.charCodeAt(index);
  bytes.set(data, 8);
  view.setUint32(8 + data.length, crc32(bytes.subarray(4, 8 + data.length)));
  return bytes;
}

export async function encodeRgbaPng(width: number, height: number, rgba: Bytes, signal?: AbortSignal): Promise<Bytes> {
  if (!Number.isSafeInteger(width) || !Number.isSafeInteger(height) || width < 1 || height < 1 || width * height > 2_000_000 || rgba.length !== width * height * 4) throw new Error("PNG RGBA dimensions or sample length are invalid");
  const raw = new Uint8Array(height * (width * 4 + 1));
  for (let row = 0; row < height; row++) {
    raw.set(rgba.subarray(row * width * 4, (row + 1) * width * 4), row * (width * 4 + 1) + 1);
    if (row % 128 === 0 && signal?.aborted) throw signal.reason;
  }
  const compressed = new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new CompressionStream("deflate"))).arrayBuffer());
  if (signal?.aborted) throw signal.reason;
  const header = new Uint8Array(13);
  const view = new DataView(header.buffer);
  view.setUint32(0, width);
  view.setUint32(4, height);
  header[8] = 8;
  header[9] = 6;
  const parts = [PNG_SIGNATURE, pngChunk("IHDR", header), pngChunk("IDAT", compressed), pngChunk("IEND", new Uint8Array(0))];
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}