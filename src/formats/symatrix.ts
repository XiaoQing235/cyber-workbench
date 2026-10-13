import type { ByteSource } from "../core/bytes/ByteSource";
import { decodePng } from "./png/decode";
import { parsePng } from "./png/parse";

/** Decode mirrored RGB blue-channel deltas as in the original Google CTF Symatrix solver. */
export async function decodeSymatrix(source: ByteSource, signal?: AbortSignal): Promise<{
  candidate: string; bits: number; differingPairs: number; width: number; height: number; verifiedFlag: false;
}> {
  if (!Number.isSafeInteger(source.size) || source.size > 4 * 1024 * 1024) throw new Error("Symatrix input exceeds 4 MiB");
  const structure = await parsePng(source, signal);
  const header = structure.ihdr;
  if (!structure.signatureValid || !header || header.width < 2 || header.width > 4096 || header.width % 2 ||
    header.height < 1 || header.height > 4096 || header.width * header.height > 4_000_000 ||
    header.bitDepth !== 8 || ![2, 6].includes(header.colorType) || structure.endOffset !== source.size ||
    structure.findings.length || structure.chunks.some((chunk) => chunk.storedCrc !== chunk.computedCrc)) {
    throw new Error("Symatrix requires a complete CRC-valid even-width 8-bit RGB/RGBA PNG");
  }
  const decoded = await decodePng(source, structure, { maxPixels: 4_000_000, signal });
  if (decoded.warnings.length || decoded.image.channels[2] !== "B") throw new Error("Symatrix image could not be decoded without warnings");
  const samples = decoded.image.samples;
  const channels = decoded.image.channels.length;
  const bits: number[] = [];
  for (let y = 0; y < header.height; y++) {
    if ((y & 31) === 0 && signal?.aborted) throw signal.reason;
    for (let x = 0; x < header.width / 2; x++) {
      const left = (y * header.width + x) * channels;
      const right = (y * header.width + header.width - 1 - x) * channels;
      let different = false;
      for (let channel = 0; channel < channels; channel++) if (samples[left + channel] !== samples[right + channel]) different = true;
      if (!different) continue;
      const bit = samples[right + 2] - samples[left + 2];
      if (bit !== 0 && bit !== 1) throw new Error("Symatrix mirrored blue difference is not a binary digit");
      bits.push(bit);
      if (bits.length > 16_384) throw new Error("Symatrix bitstream exceeds its budget");
    }
  }
  if (bits.length < 8 || bits.length % 8) throw new Error("Symatrix bitstream is empty or not byte-aligned");
  const output = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bits.length; i++) output[i >> 3] = (output[i >> 3] << 1) | bits[i];
  const candidate = new TextDecoder("utf-8", { fatal: true }).decode(output);
  return { candidate, bits: bits.length, differingPairs: bits.length, width: header.width, height: header.height,
    verifiedFlag: false };
}
