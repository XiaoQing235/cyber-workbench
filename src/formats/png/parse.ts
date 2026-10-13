import type { Finding } from "../../core/analysis/finding";
import type { ByteSource, Bytes } from "../../core/bytes/ByteSource";
import { MemorySource } from "../../core/bytes/sources";
import type { SourceSpan } from "../../core/bytes/span";
import { CRC32_INITIAL, crc32Finish, crc32Update } from "../../core/checksum/crc32";
import { inflate } from "../../core/compression/inflate";

export const PNG_SIGNATURE = Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a);

const KNOWN_CHUNKS = new Set([
  "IHDR", "PLTE", "IDAT", "IEND", "tRNS", "cHRM", "gAMA", "iCCP", "sBIT", "sRGB", "cICP", "mDCV",
  "cLLI", "tEXt", "zTXt", "iTXt", "bKGD", "hIST", "pHYs", "sPLT", "eXIf", "tIME", "acTL", "fcTL",
  "fdAT", "oFFs", "pCAL", "sCAL", "sTER", "dSIG", "gIFg", "gIFx",
]);

const VALID_BIT_DEPTHS: Record<number, readonly number[]> = {
  0: [1, 2, 4, 8, 16],
  2: [8, 16],
  3: [1, 2, 4, 8],
  4: [8, 16],
  6: [8, 16],
};

const MAX_CHUNKS = 100_000;
const MAX_TEXT_INFLATE = 1 << 20;
const CRC_READ_CHUNK = 1 << 20;

export interface PngChunk {
  type: string;
  /** Offset of the chunk's length field. */
  offset: number;
  length: number;
  storedCrc: number;
  computedCrc: number;
}

export interface Ihdr {
  width: number;
  height: number;
  bitDepth: number;
  colorType: number;
  compression: number;
  filter: number;
  interlace: number;
}

export interface PngText {
  chunk: "tEXt" | "zTXt" | "iTXt";
  keyword: string;
  text: string;
  offset: number;
}

export interface PngStructure {
  signatureValid: boolean;
  chunks: PngChunk[];
  ihdr?: Ihdr;
  /** PLTE data: RGB triplets. */
  palette?: Bytes;
  /** tRNS data (meaning depends on the colour type). */
  transparency?: Bytes;
  /** Data spans of the IDAT chunks, in file order. */
  idat: SourceSpan[];
  texts: PngText[];
  /** Offset just past the IEND chunk, when present. */
  endOffset?: number;
  findings: Finding[];
}

export function chunkDataSpan(chunk: PngChunk): SourceSpan {
  return { offset: chunk.offset + 8, length: chunk.length };
}

function isChunkTypeByte(byte: number): boolean {
  return (byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a);
}

function u32(bytes: Uint8Array, at: number): number {
  return ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0;
}

function latin1(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 8192) out += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return out;
}

async function chunkCrc(source: ByteSource, offset: number, length: number, signal?: AbortSignal): Promise<number> {
  // The CRC covers the 4-byte type and the data, not the length field.
  let register = crc32Update(CRC32_INITIAL, await source.read(offset + 4, 4));
  const dataStart = offset + 8;
  for (let at = 0; at < length; at += CRC_READ_CHUNK) {
    signal?.throwIfAborted();
    register = crc32Update(register, await source.read(dataStart + at, Math.min(CRC_READ_CHUNK, length - at)));
  }
  return crc32Finish(register);
}

async function inflateText(bytes: Bytes): Promise<Bytes> {
  return (await inflate(new MemorySource(bytes), "zlib", { maxOutputBytes: MAX_TEXT_INFLATE })).bytes;
}

async function parseText(source: ByteSource, chunk: PngChunk): Promise<PngText | undefined> {
  const data = await source.read(chunk.offset + 8, Math.min(chunk.length, 4 * MAX_TEXT_INFLATE));
  const nul = data.indexOf(0);
  if (nul < 0) return undefined;
  const keyword = latin1(data.subarray(0, nul));
  const type = chunk.type as PngText["chunk"];
  const base = { chunk: type, keyword, offset: chunk.offset };
  if (type === "tEXt") return { ...base, text: latin1(data.subarray(nul + 1)) };
  // zTXt: keyword \0 method stream
  if (type === "zTXt") return { ...base, text: latin1(await inflateText(data.slice(nul + 2))) };
  // iTXt: keyword \0 flag method language \0 translated-keyword \0 text
  const compressed = data[nul + 1] === 1;
  const languageEnd = data.indexOf(0, nul + 3);
  const translatedEnd = languageEnd < 0 ? -1 : data.indexOf(0, languageEnd + 1);
  if (translatedEnd < 0) return undefined;
  const body = data.slice(translatedEnd + 1);
  const utf8 = new TextDecoder("utf-8", { fatal: false });
  return { ...base, text: utf8.decode(compressed ? await inflateText(body) : body) };
}

function validateIhdr(ihdr: Ihdr, offset: number, findings: Finding[]): void {
  const span = { offset: offset + 8, length: 13 };
  if (ihdr.width === 0 || ihdr.height === 0 || ihdr.width > 0x7fffffff || ihdr.height > 0x7fffffff) {
    findings.push({ id: "png.ihdr.dimensions", severity: "strong", message: `Invalid dimensions ${ihdr.width}×${ihdr.height}`, span });
  }
  const depths = VALID_BIT_DEPTHS[ihdr.colorType];
  if (!depths) {
    findings.push({ id: "png.ihdr.colortype", severity: "strong", message: `Invalid colour type ${ihdr.colorType}`, span });
  } else if (!depths.includes(ihdr.bitDepth)) {
    findings.push({
      id: "png.ihdr.bitdepth",
      severity: "strong",
      message: `Bit depth ${ihdr.bitDepth} is not allowed for colour type ${ihdr.colorType}`,
      span,
    });
  }
  if (ihdr.compression !== 0 || ihdr.filter !== 0 || ihdr.interlace > 1) {
    findings.push({
      id: "png.ihdr.methods",
      severity: "strong",
      message: `Unsupported compression/filter/interlace method (${ihdr.compression}/${ihdr.filter}/${ihdr.interlace})`,
      span,
    });
  }
}

/** Walks the chunk list, verifying every CRC. Damaged files yield what parsed plus findings. */
export async function parsePng(source: ByteSource, signal?: AbortSignal): Promise<PngStructure> {
  const structure: PngStructure = { signatureValid: false, chunks: [], idat: [], texts: [], findings: [] };
  const { findings } = structure;
  const head = await source.read(0, 8);
  structure.signatureValid = head.length === 8 && head.every((byte, i) => byte === PNG_SIGNATURE[i]);
  if (!structure.signatureValid) {
    const partial = head.length >= 4 && head[0] === 0x89 && head[1] === 0x50 && head[2] === 0x4e && head[3] === 0x47;
    findings.push({
      id: "png.signature",
      severity: "strong",
      message: partial
        ? "PNG signature is damaged after \"\\x89PNG\" (line-ending conversion is a common cause)"
        : "Not a PNG signature",
      span: { offset: 0, length: Math.min(8, source.size) },
    });
    if (!partial) return structure;
  }

  let offset = 8;
  let lastWasIdat = false;
  let idatRunEnded = false;
  while (offset + 8 <= source.size && structure.chunks.length < MAX_CHUNKS) {
    signal?.throwIfAborted();
    const header = await source.read(offset, 8);
    const length = u32(header, 0);
    const typeBytes = header.subarray(4, 8);
    if (!typeBytes.every(isChunkTypeByte)) {
      findings.push({
        id: "png.chunk.type",
        severity: "strong",
        message: `Invalid chunk type at offset ${offset}; parsing stopped`,
        span: { offset: offset + 4, length: 4 },
      });
      break;
    }
    const type = latin1(typeBytes);
    if (length > 0x7fffffff || offset + 12 + length > source.size) {
      findings.push({
        id: "png.chunk.truncated",
        severity: "strong",
        message: `Chunk ${type} at offset ${offset} declares ${length} bytes but the file ends first`,
        span: { offset, length: source.size - offset },
      });
      break;
    }
    const storedCrc = u32(await source.read(offset + 8 + length, 4), 0);
    const computedCrc = await chunkCrc(source, offset, length, signal);
    const chunk: PngChunk = { type, offset, length, storedCrc, computedCrc };
    structure.chunks.push(chunk);

    if (storedCrc !== computedCrc) {
      const isIhdr = type === "IHDR";
      const crcSpan = { offset: offset + 8 + length, length: 4 };
      findings.push({
        id: `png.crc.${type}`,
        ruleId: "png.crc",
        severity: isIhdr ? "strong" : "medium",
        message: isIhdr
          ? "IHDR CRC mismatch: width or height may have been altered"
          : `CRC mismatch in ${type} chunk at offset ${offset}`,
        span: crcSpan,
        evidence: [
          {
            kind: "integrity",
            tier: "strong",
            detail: `Stored CRC 0x${storedCrc.toString(16).padStart(8, "0")} differs from the CRC of the chunk, 0x${computedCrc.toString(16).padStart(8, "0")}`,
            span: crcSpan,
          },
          ...(isIhdr
            ? [{ kind: "consistency" as const, tier: "weak" as const, detail: "A CRC that no longer matches IHDR is the usual trace of edited width or height" }]
            : []),
        ],
        suggestion: isIhdr
          ? { operationId: "png.find-dimensions", label: "Search for dimensions matching the CRC" }
          : { operationId: "png.fix-crcs", label: "Recompute chunk CRCs" },
      });
    }

    if (type === "IDAT") {
      if (idatRunEnded) {
        findings.push({
          id: "png.idat.split",
          severity: "medium",
          message: `IDAT chunks are not consecutive (another chunk precedes offset ${offset})`,
          span: { offset, length: 12 + length },
        });
      }
      structure.idat.push(chunkDataSpan(chunk));
      lastWasIdat = true;
    } else {
      if (lastWasIdat) idatRunEnded = true;
      lastWasIdat = false;
    }

    if (type === "IHDR") {
      if (structure.chunks.length !== 1) {
        findings.push({ id: "png.ihdr.order", severity: "strong", message: "IHDR is not the first chunk", span: { offset, length: 12 + length } });
      }
      if (length !== 13) {
        findings.push({ id: "png.ihdr.length", severity: "strong", message: `IHDR length is ${length}, expected 13`, span: { offset, length: 4 } });
      } else {
        const data = await source.read(offset + 8, 13);
        structure.ihdr = {
          width: u32(data, 0),
          height: u32(data, 4),
          bitDepth: data[8],
          colorType: data[9],
          compression: data[10],
          filter: data[11],
          interlace: data[12],
        };
        validateIhdr(structure.ihdr, offset, findings);
      }
    } else if (type === "PLTE") {
      structure.palette = await source.read(offset + 8, Math.min(length, 768));
    } else if (type === "tRNS") {
      structure.transparency = await source.read(offset + 8, Math.min(length, 256));
    } else if (type === "tEXt" || type === "zTXt" || type === "iTXt") {
      try {
        const text = await parseText(source, chunk);
        if (text) structure.texts.push(text);
      } catch {
        findings.push({ id: `png.text.${offset}`, severity: "weak", message: `Could not decode ${type} chunk at offset ${offset}`, span: { offset, length: 12 + length } });
      }
    } else if (!KNOWN_CHUNKS.has(type)) {
      findings.push({
        id: `png.chunk.unknown.${offset}`,
        ruleId: "png.chunk-type",
        severity: "weak",
        message: `Unusual chunk "${type}" (${length} bytes) at offset ${offset}`,
        span: { offset, length: 12 + length },
        evidence: [{ kind: "structure", tier: "weak", detail: `"${type}" is not a chunk type defined by the PNG specification`, span: { offset: offset + 4, length: 4 } }],
        suggestion: { operationId: "bytes.slice", params: { offset: offset + 8, length }, label: "Extract chunk data" },
      });
    }

    offset += 12 + length;
    if (type === "IEND") {
      structure.endOffset = offset;
      break;
    }
  }

  if (structure.chunks.length > 0 && !structure.ihdr) {
    findings.push({ id: "png.ihdr.missing", severity: "strong", message: "No valid IHDR chunk" });
  }
  if (structure.idat.length === 0) {
    findings.push({ id: "png.idat.missing", severity: "strong", message: "No IDAT chunk: there is no image data" });
  }
  for (const text of structure.texts) {
    const chunk = structure.chunks.find((c) => c.offset === text.offset);
    findings.push({
      id: `png.text.${text.offset}`,
      severity: "weak",
      message: `${text.chunk} "${text.keyword}": ${text.text.length > 120 ? `${text.text.slice(0, 120)}…` : text.text}`,
      span: { offset: text.offset, length: chunk ? 12 + chunk.length : 8 },
    });
  }
  if (structure.endOffset === undefined) {
    if (structure.chunks.length > 0) {
      findings.push({ id: "png.iend.missing", severity: "medium", message: "No IEND chunk (file truncated?)" });
    }
  } else if (structure.endOffset < source.size) {
    const trailing = source.size - structure.endOffset;
    findings.push({
      id: "png.trailing",
      ruleId: "png.trailing",
      severity: "strong",
      message: `${trailing} byte(s) after IEND at offset ${structure.endOffset}`,
      span: { offset: structure.endOffset, length: trailing },
      evidence: [
        {
          kind: "structure",
          tier: "strong",
          detail: `IEND ends the image at offset ${structure.endOffset}; ${trailing} more byte(s) follow, which decoders ignore`,
          span: { offset: structure.endOffset, length: trailing },
        },
      ],
      suggestion: {
        operationId: "bytes.slice",
        params: { offset: structure.endOffset, length: -1 },
        label: "Extract trailing data",
      },
    });
  }
  return structure;
}
