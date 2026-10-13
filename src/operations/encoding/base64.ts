import type { Bytes } from "../../core/bytes/ByteSource";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, textValue } from "../../core/value";
import { bytesInput, forEachChunk, MiB, textInput } from "../util";

const STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
// A multiple of 3, so every chunk except the last encodes without padding.
const ENCODE_CHUNK = 3 * 256 * 1024;

type Alphabet = "standard" | "url";

export function encodeBase64(bytes: Uint8Array, alphabet: Alphabet, padding: boolean): string {
  const chars = alphabet === "url" ? URL_SAFE : STANDARD;
  const full = bytes.length - (bytes.length % 3);
  let out = "";
  for (let i = 0; i < full; i += 3) {
    const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += chars[(n >> 18) & 63] + chars[(n >> 12) & 63] + chars[(n >> 6) & 63] + chars[n & 63];
  }
  const rest = bytes.length - full;
  if (rest === 1) {
    const n = bytes[full] << 16;
    out += chars[(n >> 18) & 63] + chars[(n >> 12) & 63] + (padding ? "==" : "");
  } else if (rest === 2) {
    const n = (bytes[full] << 16) | (bytes[full + 1] << 8);
    out += chars[(n >> 18) & 63] + chars[(n >> 12) & 63] + chars[(n >> 6) & 63] + (padding ? "=" : "");
  }
  return out;
}

export interface DecodedBase64 {
  bytes: Bytes;
  /** The final character carries unused bits that are not zero (a known stego channel). */
  nonZeroTrailingBits: boolean;
}

function isAsciiWhitespace(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d || code === 0x0c;
}

export function decodeBase64(input: string, alphabet: Alphabet, requirePadding: boolean): DecodedBase64 {
  const table = new Int8Array(128).fill(-1);
  const chars = alphabet === "url" ? URL_SAFE : STANDARD;
  for (let i = 0; i < 64; i++) table[chars.charCodeAt(i)] = i;

  const values = new Uint8Array(input.length);
  let count = 0;
  let padding = 0;
  for (let i = 0; i < input.length; i++) {
    const code = input.charCodeAt(i);
    if (isAsciiWhitespace(code)) continue;
    if (code === 0x3d) {
      padding++;
      continue;
    }
    if (padding > 0) {
      throw new OperationError("INVALID_INPUT", `Data after padding at position ${i}`);
    }
    const value = code < 128 ? table[code] : -1;
    if (value < 0) {
      const hint = alphabet === "standard" && (code === 0x2d || code === 0x5f) ? " (URL-safe alphabet?)" : "";
      throw new OperationError(
        "INVALID_INPUT",
        `Invalid Base64 character ${JSON.stringify(input[i])} at position ${i}${hint}`,
      );
    }
    values[count++] = value;
  }

  const rest = count % 4;
  if (rest === 1) {
    throw new OperationError("INVALID_INPUT", "Truncated Base64: one leftover character cannot encode a byte");
  }
  if (padding > 0 && (padding > 2 || (count + padding) % 4 !== 0)) {
    throw new OperationError("INVALID_INPUT", "Incorrect Base64 padding");
  }
  if (requirePadding && rest !== 0 && padding === 0) {
    throw new OperationError("INVALID_INPUT", "Missing Base64 padding");
  }

  const out = new Uint8Array((count >> 2) * 3 + (rest === 0 ? 0 : rest - 1));
  const full = count - rest;
  let o = 0;
  for (let i = 0; i < full; i += 4) {
    const n = (values[i] << 18) | (values[i + 1] << 12) | (values[i + 2] << 6) | values[i + 3];
    out[o++] = (n >> 16) & 255;
    out[o++] = (n >> 8) & 255;
    out[o++] = n & 255;
  }
  let nonZeroTrailingBits = false;
  if (rest === 2) {
    out[o++] = ((values[full] << 2) | (values[full + 1] >> 4)) & 255;
    nonZeroTrailingBits = (values[full + 1] & 0x0f) !== 0;
  } else if (rest === 3) {
    const n = (values[full] << 18) | (values[full + 1] << 12) | (values[full + 2] << 6);
    out[o++] = (n >> 16) & 255;
    out[o++] = (n >> 8) & 255;
    nonZeroTrailingBits = (values[full + 2] & 0x03) !== 0;
  }
  return { bytes: out, nonZeroTrailingBits };
}

const ALPHABET_PARAM = {
  type: "string",
  title: "Alphabet",
  enum: ["standard", "url"],
  default: "standard",
} as const;

export const base64Encode = defineOperation<{ alphabet: Alphabet; padding: boolean }>({
  spec: {
    id: "base64.encode",
    version: "1.0.0",
    title: "To Base64",
    category: "Encoding",
    description: "Encode bytes as Base64 text (RFC 4648).",
    keywords: ["b64", "encode"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: {
        alphabet: ALPHABET_PARAM,
        padding: { type: "boolean", title: "Padding (=)", default: true },
      },
      required: ["alphabet", "padding"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "low",
    limits: { maxInputBytes: 256 * MiB },
  },
  async run(ctx, inputs, params) {
    let text = "";
    await forEachChunk(
      ctx,
      bytesInput(inputs),
      (chunk) => {
        text += encodeBase64(chunk, params.alphabet, params.padding);
      },
      ENCODE_CHUNK,
    );
    return { text: textValue(text) };
  },
});

export const base64Decode = defineOperation<{ alphabet: Alphabet; requirePadding: boolean }>({
  spec: {
    id: "base64.decode",
    version: "1.0.0",
    title: "From Base64",
    category: "Encoding",
    description: "Decode Base64 text to bytes. Whitespace is ignored; invalid characters are errors.",
    keywords: ["b64", "decode"],
    inputs: [{ name: "text", type: "text" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        alphabet: ALPHABET_PARAM,
        requirePadding: { type: "boolean", title: "Require padding", default: false },
      },
      required: ["alphabet", "requirePadding"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "low",
  },
  async run(ctx, inputs, params) {
    const decoded = decodeBase64(textInput(inputs), params.alphabet, params.requirePadding);
    if (decoded.nonZeroTrailingBits) {
      ctx.diagnostic("The unused bits of the final character are not zero (possible Base64 steganography).");
    }
    return { data: bytesFrom(decoded.bytes) };
  },
});
