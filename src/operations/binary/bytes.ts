import { SliceSource, readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, bytesValue, structuredValue } from "../../core/value";
import { bytesInput, mapChunks, MiB, parseHex } from "../util";

const BIT_REVERSED = Uint8Array.from({ length: 256 }, (_, byte) => {
  let reversed = 0;
  for (let bit = 0; bit < 8; bit++) reversed |= ((byte >> bit) & 1) << (7 - bit);
  return reversed;
});

const COMMON = {
  runtime: "ts",
  deterministic: true,
  sideEffects: "none",
  cost: "low",
} as const;

export const bytesReverse = defineOperation<{ groupSize: number; remainder: "keep" | "reverse" | "error" }>({
  spec: {
    ...COMMON,
    id: "bytes.reverse",
    version: "1.0.0",
    title: "Reverse bytes",
    category: "Binary",
    description:
      "Reverse the whole byte sequence (group size 0), or reverse bytes within each group, e.g. 4 to swap the endianness of 32-bit words.",
    keywords: ["endianness", "swap", "byteswap"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        groupSize: { type: "integer", title: "Group size (0 = whole input)", minimum: 0, maximum: MiB, default: 0 },
        remainder: {
          type: "string",
          title: "Incomplete final group",
          enum: ["keep", "reverse", "error"],
          default: "keep",
        },
      },
      required: ["groupSize", "remainder"],
      additionalProperties: false,
    },
    streaming: false,
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs, params) {
    const data = await readAll(bytesInput(inputs));
    const { groupSize } = params;
    if (groupSize === 0) return { data: bytesFrom(data.reverse()) };

    const full = data.length - (data.length % groupSize);
    for (let i = 0; i < full; i += groupSize) data.subarray(i, i + groupSize).reverse();
    const rest = data.length - full;
    if (rest > 0) {
      if (params.remainder === "error") {
        throw new OperationError("INVALID_INPUT", `${rest} trailing byte(s) do not fill a group of ${groupSize}`);
      }
      if (params.remainder === "reverse") {
        data.subarray(full).reverse();
      } else {
        ctx.diagnostic(`${rest} trailing byte(s) do not fill a group of ${groupSize} and were left unchanged.`);
      }
    }
    return { data: bytesFrom(data) };
  },
});

export const bitsReverse = defineOperation<Record<string, never>>({
  spec: {
    ...COMMON,
    id: "bits.reverse",
    version: "1.0.0",
    title: "Reverse bits in each byte",
    category: "Binary",
    description: "Mirror the bit order inside every byte (MSB ↔ LSB).",
    keywords: ["bit order", "mirror", "msb", "lsb"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    streaming: true,
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs) {
    const out = await mapChunks(ctx, bytesInput(inputs), (chunk) => {
      for (let i = 0; i < chunk.length; i++) chunk[i] = BIT_REVERSED[chunk[i]];
    });
    return { data: bytesFrom(out) };
  },
});

export const bytesNot = defineOperation<Record<string, never>>({
  spec: {
    ...COMMON,
    id: "bytes.not",
    version: "1.0.0",
    title: "Invert bits (NOT)",
    category: "Binary",
    description: "Flip every bit of every byte.",
    keywords: ["not", "invert", "complement"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    streaming: true,
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs) {
    const out = await mapChunks(ctx, bytesInput(inputs), (chunk) => {
      for (let i = 0; i < chunk.length; i++) chunk[i] = ~chunk[i] & 0xff;
    });
    return { data: bytesFrom(out) };
  },
});

export const bytesXor = defineOperation<{ key: string; keyFormat: "hex" | "utf-8" }>({
  spec: {
    ...COMMON,
    id: "bytes.xor",
    version: "1.0.0",
    title: "XOR",
    category: "Binary",
    description: "XOR the data with a repeating key. The key restarts at offset 0 of the input.",
    keywords: ["xor", "key", "cipher"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        key: { type: "string", title: "Key", minLength: 1, default: "" },
        keyFormat: { type: "string", title: "Key format", enum: ["hex", "utf-8"], default: "hex" },
      },
      required: ["key", "keyFormat"],
      additionalProperties: false,
    },
    streaming: true,
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs, params) {
    const key = params.keyFormat === "hex" ? parseHex(params.key, true) : new TextEncoder().encode(params.key);
    if (key.length === 0) throw new OperationError("INVALID_PARAMS", "The key is empty");
    const out = await mapChunks(ctx, bytesInput(inputs), (chunk, offset) => {
      for (let i = 0; i < chunk.length; i++) chunk[i] ^= key[(offset + i) % key.length];
    });
    return { data: bytesFrom(out) };
  },
});

export const badByteXorKeys = defineOperation<{ forbidden: string; maxKeys: number; maxHits: number }>({
  spec: {
    ...COMMON,
    id: "binary.badbytes.xor-keys", version: "1.0.0", title: "Find bad-byte-free XOR keys", category: "Binary",
    description: "Find 1-byte XOR keys whose encoded input avoids selected forbidden bytes. Report original bad-byte offsets; apply a returned key using the existing XOR operation. The key byte itself is not checked for transport constraints.",
    keywords: ["bad bytes", "shellcode", "xor", "encoder", "constraint", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        forbidden: { type: "string", title: "Forbidden bytes (hex)", maxLength: 128, default: "00 0a" },
        maxKeys: { type: "integer", title: "Maximum keys to show", minimum: 1, maximum: 255, default: 32 },
        maxHits: { type: "integer", title: "Maximum original offsets to show", minimum: 1, maximum: 1_024, default: 32 },
      },
      required: ["forbidden", "maxKeys", "maxHits"], additionalProperties: false,
    },
    streaming: false, limits: { maxInputBytes: MiB },
  },
  async run(ctx, inputs, params) {
    const forbidden = [...new Set(parseHex(params.forbidden, true))];
    if (forbidden.length < 1 || forbidden.length > 32) throw new OperationError("INVALID_PARAMS", "Specify 1 to 32 distinct forbidden bytes");
    const input = await readAll(bytesInput(inputs), MiB);
    if (input.length === 0) throw new OperationError("INVALID_INPUT", "Bad-byte search needs at least one input byte");
    const present = new Uint8Array(256);
    const bad = new Uint8Array(256);
    for (const byte of forbidden) bad[byte] = 1;
    const firstBadOffsets: number[] = [];
    let originalBadCount = 0;
    for (const [offset, byte] of input.entries()) {
      if ((offset & 0x3fff) === 0) ctx.throwIfAborted();
      present[byte] = 1;
      if (bad[byte]) {
        originalBadCount++;
        if (firstBadOffsets.length < params.maxHits) firstBadOffsets.push(offset);
      }
    }
    const disallowedKey = new Uint8Array(256);
    for (let byte = 0; byte < 256; byte++) if (present[byte]) {
      for (const forbiddenByte of forbidden) disallowedKey[byte ^ forbiddenByte] = 1;
    }
    const candidates: string[] = [];
    for (let key = 1; key < 256; key++) if (!disallowedKey[key]) candidates.push(key.toString(16).padStart(2, "0"));
    ctx.diagnostic(`Found ${candidates.length} 1-byte XOR key(s) avoiding ${forbidden.length} forbidden byte(s); ${originalBadCount} original bad-byte occurrence(s).`);
    return { report: structuredValue({ scannedBytes: input.length,
      forbidden: forbidden.map((byte) => byte.toString(16).padStart(2, "0")),
      originalBadCount, firstBadOffsets, validKeyCount: candidates.length,
      keys: candidates.slice(0, params.maxKeys), truncated: candidates.length > params.maxKeys,
      keyByteChecked: false }) };
  },
});

export const bytesSlice = defineOperation<{ offset: number; length: number }>({
  spec: {
    ...COMMON,
    id: "bytes.slice",
    version: "1.0.0",
    title: "Slice bytes",
    category: "Binary",
    description: "Take a byte range without copying. Length -1 means up to the end.",
    keywords: ["cut", "range", "substring", "skip", "take"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        offset: { type: "integer", title: "Offset", minimum: 0, default: 0 },
        length: { type: "integer", title: "Length (-1 = to end)", minimum: -1, default: -1 },
      },
      required: ["offset", "length"],
      additionalProperties: false,
    },
    streaming: true,
  },
  async run(_ctx, inputs, params) {
    const source = bytesInput(inputs);
    if (params.offset > source.size) {
      throw new OperationError("INVALID_INPUT", `Offset ${params.offset} is beyond the end (${source.size} bytes)`);
    }
    const length = params.length === -1 ? source.size - params.offset : params.length;
    if (params.offset + length > source.size) {
      throw new OperationError(
        "INVALID_INPUT",
        `Range ${params.offset}+${length} exceeds the input size of ${source.size} bytes`,
      );
    }
    return { data: bytesValue(new SliceSource(source, params.offset, length)) };
  },
});
