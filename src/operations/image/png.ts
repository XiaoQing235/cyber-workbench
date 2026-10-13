import type { Finding } from "../../core/analysis/finding";
import type { ByteSource } from "../../core/bytes/ByteSource";
import { ConcatSource, MemorySource, SliceSource } from "../../core/bytes/sources";
import { CRC32_INITIAL, CRC32_TABLE, crc32, crc32Finish, crc32Update } from "../../core/checksum/crc32";
import { InflateLimitError, inflate } from "../../core/compression/inflate";
import { OperationError } from "../../core/operation/errors";
import type { OperationContext } from "../../core/operation/types";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { expectedRawSize, idatSource, passLayout } from "../../formats/png/decode";
import { parsePng, type PngChunk, type PngStructure } from "../../formats/png/parse";
import { bytesInput, MiB, yieldToEventLoop } from "../util";

const MAX_INSPECT_INFLATE = 256 * MiB;
const NO_SIDE_EFFECTS = { runtime: "ts", deterministic: true, sideEffects: "none" } as const;

async function requirePng(ctx: OperationContext, source: ByteSource): Promise<PngStructure> {
  const structure = await parsePng(source, ctx.signal);
  if (!structure.signatureValid && structure.chunks.length === 0) {
    throw new OperationError("INVALID_INPUT", "Not a PNG file");
  }
  return structure;
}

function requireIhdr(structure: PngStructure): PngChunk {
  const chunk = structure.chunks.find((c) => c.type === "IHDR" && c.length === 13);
  if (!chunk) throw new OperationError("INVALID_INPUT", "The PNG has no 13-byte IHDR chunk");
  return chunk;
}

function u32be(value: number): Uint8Array<ArrayBuffer> {
  return Uint8Array.of(value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255);
}

/** Rebuilds the source with some byte ranges replaced, without copying the rest. */
function patched(source: ByteSource, patches: { offset: number; bytes: Uint8Array<ArrayBuffer> }[]): ByteSource {
  const parts: ByteSource[] = [];
  let cursor = 0;
  for (const patch of [...patches].sort((a, b) => a.offset - b.offset)) {
    if (patch.offset > cursor) parts.push(new SliceSource(source, cursor, patch.offset - cursor));
    parts.push(new MemorySource(patch.bytes));
    cursor = patch.offset + patch.bytes.length;
  }
  if (cursor < source.size) parts.push(new SliceSource(source, cursor, source.size - cursor));
  return new ConcatSource(parts);
}

export const pngInspect = defineOperation<Record<string, never>>({
  spec: {
    ...NO_SIDE_EFFECTS,
    id: "png.inspect",
    version: "1.0.0",
    title: "Inspect PNG",
    category: "Image",
    description:
      "List chunks, verify CRCs, read text chunks, and compare the decompressed image data with the size IHDR implies (a reduced height shows up here).",
    keywords: ["png", "chunk", "crc", "ihdr", "idat", "height", "trailing", "structure"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    streaming: false,
    cost: "medium",
  },
  async run(ctx, inputs) {
    const source = bytesInput(inputs);
    const structure = await requirePng(ctx, source);
    const findings: Finding[] = [...structure.findings];
    let idat: Record<string, unknown> | undefined;

    const { ihdr } = structure;
    if (ihdr && structure.idat.length > 0 && findings.every((f) => !f.id.startsWith("png.ihdr."))) {
      const expected = expectedRawSize(ihdr);
      const compressed = structure.idat.reduce((sum, span) => sum + span.length, 0);
      try {
        const result = await inflate(idatSource(source, structure), "zlib", {
          maxOutputBytes: MAX_INSPECT_INFLATE,
          signal: ctx.signal,
        });
        const actual = result.bytes.length;
        idat = { chunks: structure.idat.length, compressedBytes: compressed, decompressedBytes: actual, expectedBytes: expected };
        if (result.error) {
          findings.push({ id: "png.idat.stream", severity: "medium", message: `Image data stream error after ${actual} bytes: ${result.error}` });
        }
        if (actual > expected && ihdr.interlace === 0) {
          const stride = passLayout(ihdr)[0].rowBytes + 1;
          const height = Math.floor(actual / stride);
          findings.push({
            id: "png.idat.extra",
            ruleId: "png.idat-size",
            severity: "strong",
            message: `Image data holds ${actual} bytes but ${ihdr.width}×${ihdr.height} needs ${expected}: the real height is probably ${height}`,
            evidence: [
              {
                kind: "consistency",
                tier: "strong",
                detail: `Decompressed IDAT is ${actual} bytes; IHDR ${ihdr.width}×${ihdr.height} implies ${expected}. At ${stride} bytes per row that is ${height} rows`,
                span: { offset: 16, length: 8 },
              },
            ],
            suggestion: { operationId: "png.set-ihdr", params: { height }, label: `Set height to ${height}` },
          });
        } else if (actual > expected) {
          findings.push({ id: "png.idat.extra", severity: "strong", message: `Image data holds ${actual - expected} more bytes than the dimensions need` });
        } else if (actual < expected) {
          findings.push({
            id: "png.idat.short",
            severity: "medium",
            message: `Image data is ${expected - actual} bytes short of what ${ihdr.width}×${ihdr.height} needs (dimensions too large, or data truncated)`,
          });
        }
      } catch (error) {
        if (!(error instanceof InflateLimitError)) throw error;
        findings.push({ id: "png.idat.bomb", severity: "strong", message: error.message });
      }
    }

    return {
      report: structuredValue({
        signatureValid: structure.signatureValid,
        ihdr,
        chunks: structure.chunks.map((c) => ({ type: c.type, offset: c.offset, length: c.length, crcOk: c.storedCrc === c.computedCrc })),
        texts: structure.texts,
        idat,
        endOffset: structure.endOffset,
        trailingBytes: structure.endOffset === undefined ? undefined : source.size - structure.endOffset,
        findings,
      }),
    };
  },
});

export const pngSetIhdr = defineOperation<{ width: number; height: number; fixCrc: boolean }>({
  spec: {
    ...NO_SIDE_EFFECTS,
    id: "png.set-ihdr",
    version: "1.0.0",
    title: "Set PNG dimensions",
    category: "Image",
    description: "Write a new width and/or height into IHDR and recompute its CRC. The original file is not changed.",
    keywords: ["png", "height", "width", "repair", "ihdr", "fix"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        width: { type: "integer", title: "Width (-1 = keep)", minimum: -1, maximum: 0x7fffffff, default: -1 },
        height: { type: "integer", title: "Height (-1 = keep)", minimum: -1, maximum: 0x7fffffff, default: -1 },
        fixCrc: { type: "boolean", title: "Recompute IHDR CRC", default: true },
      },
      required: ["width", "height", "fixCrc"],
      additionalProperties: false,
    },
    streaming: true,
    cost: "low",
  },
  async run(ctx, inputs, params) {
    if (params.width === 0 || params.height === 0) throw new OperationError("INVALID_PARAMS", "Dimensions must be at least 1");
    const source = bytesInput(inputs);
    const chunk = requireIhdr(await requirePng(ctx, source));
    const block = await source.read(chunk.offset, 25);
    if (params.width !== -1) block.set(u32be(params.width), 8);
    if (params.height !== -1) block.set(u32be(params.height), 12);
    if (params.fixCrc) block.set(u32be(crc32(block.subarray(4, 21))), 21);
    const view = new DataView(block.buffer);
    ctx.diagnostic(
      `IHDR is now ${view.getUint32(8)}×${view.getUint32(12)}${params.fixCrc ? " with a recomputed CRC" : " (CRC unchanged)"}.`,
    );
    return { data: bytesValue(patched(source, [{ offset: chunk.offset, bytes: block }])) };
  },
});

export const pngFixCrcs = defineOperation<Record<string, never>>({
  spec: {
    ...NO_SIDE_EFFECTS,
    id: "png.fix-crcs",
    version: "1.0.0",
    title: "Fix PNG chunk CRCs",
    category: "Image",
    description:
      "Recompute every chunk CRC that does not match. If IHDR's CRC is wrong because the dimensions were altered, find the real dimensions first.",
    keywords: ["png", "crc", "repair", "checksum"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    streaming: true,
    cost: "low",
  },
  async run(ctx, inputs) {
    const source = bytesInput(inputs);
    const structure = await requirePng(ctx, source);
    const broken = structure.chunks.filter((c) => c.storedCrc !== c.computedCrc);
    if (broken.length === 0) ctx.diagnostic("All chunk CRCs were already correct.");
    else ctx.diagnostic(`Fixed: ${broken.map((c) => `${c.type}@${c.offset}`).join(", ")}.`);
    const patches = broken.map((c) => ({ offset: c.offset + 8 + c.length, bytes: u32be(c.computedCrc) }));
    return { data: bytesValue(patched(source, patches)) };
  },
});

export const pngFindDimensions = defineOperation<{ maxDimension: number; maxMatches: number }>({
  spec: {
    ...NO_SIDE_EFFECTS,
    id: "png.find-dimensions",
    version: "1.0.0",
    title: "Find PNG dimensions from CRC",
    category: "Image",
    description:
      "Brute-force width and height until the IHDR CRC matches the stored CRC. Recovers dimensions that were altered to hide part of the image.",
    keywords: ["png", "crc", "height", "width", "brute force", "ihdr"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "result", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        maxDimension: { type: "integer", title: "Search up to (pixels)", minimum: 1, maximum: 16384, default: 4096 },
        maxMatches: { type: "integer", title: "Stop after matches", minimum: 1, maximum: 100, default: 8 },
      },
      required: ["maxDimension", "maxMatches"],
      additionalProperties: false,
    },
    streaming: false,
    cost: "high",
  },
  async run(ctx, inputs, params) {
    const source = bytesInput(inputs);
    const chunk = requireIhdr(await requirePng(ctx, source));
    const block = await source.read(chunk.offset, 25);
    const tail = block.subarray(16, 21);
    const stored = chunk.storedCrc;
    const view = new DataView(block.buffer);
    const current = { width: view.getUint32(8), height: view.getUint32(12) };
    const base = crc32Update(CRC32_INITIAL, block.subarray(4, 8));
    const step = (crc: number, byte: number) => CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);

    const matches: { width: number; height: number }[] = [];
    outer: for (let width = 1; width <= params.maxDimension; width++) {
      if ((width & 127) === 0) {
        await yieldToEventLoop();
        ctx.throwIfAborted();
      }
      let afterWidth = base;
      afterWidth = step(afterWidth, width >>> 24);
      afterWidth = step(afterWidth, (width >>> 16) & 255);
      afterWidth = step(afterWidth, (width >>> 8) & 255);
      afterWidth = step(afterWidth, width & 255);
      for (let height = 1; height <= params.maxDimension; height++) {
        let crc = step(afterWidth, height >>> 24);
        crc = step(crc, (height >>> 16) & 255);
        crc = step(crc, (height >>> 8) & 255);
        crc = step(crc, height & 255);
        for (let i = 0; i < 5; i++) crc = step(crc, tail[i]);
        if (crc32Finish(crc) === stored) {
          matches.push({ width, height });
          if (matches.length >= params.maxMatches) break outer;
        }
      }
    }

    const findings: Finding[] = matches.map((match, index) => ({
      id: `png.dimensions.${index}`,
      ruleId: "png.crc-search",
      severity: matches.length === 1 ? "strong" : "medium",
      message:
        match.width === current.width && match.height === current.height
          ? `${match.width}×${match.height} matches the CRC (these are the current dimensions)`
          : `${match.width}×${match.height} matches the stored CRC (currently ${current.width}×${current.height})`,
      evidence: [
        {
          kind: "integrity",
          tier: "strong",
          detail: `IHDR with ${match.width}×${match.height} has exactly the stored CRC. A CRC match proves only the CRC, so check the image`,
          span: { offset: 16, length: 8 },
        },
        ...(matches.length > 1 ? [{ kind: "consistency" as const, tier: "weak" as const, detail: `${matches.length} sizes match; each is equally supported` }] : []),
      ],
      suggestion: { operationId: "png.set-ihdr", params: { ...match, fixCrc: false }, label: `Use ${match.width}×${match.height}` },
    }));
    if (matches.length === 0) ctx.diagnostic(`No dimensions up to ${params.maxDimension} match; try a larger search.`);
    return {
      result: structuredValue({
        storedCrc: `0x${stored.toString(16).padStart(8, "0")}`,
        current,
        searchedUpTo: params.maxDimension,
        matches,
        findings,
      }),
    };
  },
});
