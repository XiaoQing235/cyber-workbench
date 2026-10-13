import type { Bytes } from "../../core/bytes/ByteSource";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, textValue } from "../../core/value";
import { bytesInput, forEachChunk, MiB, textInput } from "../util";

type Charset = "utf-8" | "utf-16le" | "utf-16be" | "latin1";
const CHARSETS: readonly Charset[] = ["utf-8", "utf-16le", "utf-16be", "latin1"];

/** Index of the first unpaired UTF-16 surrogate, or -1. */
export function findLoneSurrogate(text: string): number {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++;
        continue;
      }
      return i;
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) return i;
  }
  return -1;
}

export function encodeText(text: string, charset: Charset, strict: boolean): Bytes {
  switch (charset) {
    case "utf-8": {
      const lone = findLoneSurrogate(text);
      if (strict && lone >= 0) {
        throw new OperationError("INVALID_INPUT", `Unpaired surrogate at index ${lone} cannot be encoded as UTF-8`);
      }
      return new TextEncoder().encode(text) as Bytes;
    }
    case "utf-16le":
    case "utf-16be": {
      const out = new Uint8Array(text.length * 2);
      const littleEndian = charset === "utf-16le";
      for (let i = 0; i < text.length; i++) {
        const unit = text.charCodeAt(i);
        out[2 * i + (littleEndian ? 0 : 1)] = unit & 255;
        out[2 * i + (littleEndian ? 1 : 0)] = unit >> 8;
      }
      return out;
    }
    case "latin1": {
      const out = new Uint8Array(text.length);
      for (let i = 0; i < text.length; i++) {
        const unit = text.charCodeAt(i);
        if (unit > 0xff) {
          if (strict) {
            throw new OperationError("INVALID_INPUT", `Character at index ${i} is outside Latin-1`);
          }
          out[i] = 0x3f;
        } else {
          out[i] = unit;
        }
      }
      return out;
    }
  }
}

export const textEncode = defineOperation<{ charset: Charset; onUnmappable: "error" | "replace" }>({
  spec: {
    id: "text.encode",
    version: "1.0.0",
    title: "Encode text",
    category: "Text",
    description: "Convert text to bytes with an explicit character set.",
    keywords: ["charset", "utf8", "utf16", "latin1", "string to bytes"],
    inputs: [{ name: "text", type: "text" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        charset: { type: "string", title: "Charset", enum: CHARSETS, default: "utf-8" },
        onUnmappable: {
          type: "string",
          title: "Unmappable characters",
          enum: ["error", "replace"],
          default: "error",
        },
      },
      required: ["charset", "onUnmappable"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "low",
  },
  async run(_ctx, inputs, params) {
    return { data: bytesFrom(encodeText(textInput(inputs), params.charset, params.onUnmappable === "error")) };
  },
});

export const textDecode = defineOperation<{ charset: Charset; onInvalid: "error" | "replace" }>({
  spec: {
    id: "text.decode",
    version: "1.0.0",
    title: "Decode text",
    category: "Text",
    description:
      "Convert bytes to text with an explicit character set. Latin-1 maps every byte to U+0000–U+00FF and never fails.",
    keywords: ["charset", "utf8", "utf16", "latin1", "bytes to string"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: {
        charset: { type: "string", title: "Charset", enum: CHARSETS, default: "utf-8" },
        onInvalid: { type: "string", title: "Invalid sequences", enum: ["error", "replace"], default: "error" },
      },
      required: ["charset", "onInvalid"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "low",
    limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs, params) {
    const source = bytesInput(inputs);
    let text = "";
    if (params.charset === "latin1") {
      // TextDecoder("latin1") is windows-1252 per the WHATWG spec, so map bytes directly.
      await forEachChunk(ctx, source, (chunk) => {
        for (let i = 0; i < chunk.length; i += 8192) {
          text += String.fromCharCode(...chunk.subarray(i, i + 8192));
        }
      });
      return { text: textValue(text) };
    }
    const decoder = new TextDecoder(params.charset, { fatal: params.onInvalid === "error", ignoreBOM: true });
    try {
      await forEachChunk(ctx, source, (chunk) => {
        text += decoder.decode(chunk, { stream: true });
      });
      text += decoder.decode();
    } catch (error) {
      if (error instanceof TypeError) {
        throw new OperationError("INVALID_INPUT", `Data is not valid ${params.charset}`);
      }
      throw error;
    }
    return { text: textValue(text) };
  },
});
