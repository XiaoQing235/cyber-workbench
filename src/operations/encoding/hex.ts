import { defineOperation } from "../../core/operation/types";
import { bytesFrom, textValue } from "../../core/value";
import { bytesInput, forEachChunk, MiB, parseHex, textInput } from "../util";

export const hexEncode = defineOperation<{ uppercase: boolean; separator: string }>({
  spec: {
    id: "hex.encode",
    version: "1.0.0",
    title: "To Hex",
    category: "Encoding",
    description: "Encode bytes as hexadecimal text.",
    keywords: ["base16", "encode"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: {
        uppercase: { type: "boolean", title: "Uppercase", default: false },
        separator: { type: "string", title: "Separator between bytes", default: "", maxLength: 8 },
      },
      required: ["uppercase", "separator"],
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
    const digits = params.uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    const table = Array.from({ length: 256 }, (_, b) => digits[b >> 4] + digits[b & 15]);
    let text = "";
    let first = true;
    await forEachChunk(ctx, bytesInput(inputs), (chunk) => {
      for (const byte of chunk) {
        text += first ? table[byte] : params.separator + table[byte];
        first = false;
      }
    });
    return { text: textValue(text) };
  },
});

export const hexDecode = defineOperation<{ ignoreSeparators: boolean }>({
  spec: {
    id: "hex.decode",
    version: "1.0.0",
    title: "From Hex",
    category: "Encoding",
    description:
      "Decode hexadecimal text to bytes. Whitespace is ignored. Optionally ignore 0x / \\x prefixes and : , ; - _ . separators.",
    keywords: ["base16", "decode"],
    inputs: [{ name: "text", type: "text" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        ignoreSeparators: { type: "boolean", title: "Ignore prefixes and separators", default: true },
      },
      required: ["ignoreSeparators"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "low",
  },
  async run(_ctx, inputs, params) {
    return { data: bytesFrom(parseHex(textInput(inputs), params.ignoreSeparators)) };
  },
});
