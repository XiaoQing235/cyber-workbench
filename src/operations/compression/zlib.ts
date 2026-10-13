import { InflateLimitError, inflate, type InflateFormat, type InflateResult } from "../../core/compression/inflate";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom } from "../../core/value";
import { bytesInput, MiB } from "../util";

export const zlibInflate = defineOperation<{ format: InflateFormat; maxOutputBytes: number; allowPartial: boolean }>({
  spec: {
    id: "zlib.inflate",
    version: "1.0.0",
    title: "Decompress (zlib / gzip / deflate)",
    category: "Compression",
    description:
      "Decompress a zlib, gzip or raw deflate stream with the browser's native decompressor. Output is capped to stop decompression bombs.",
    keywords: ["zlib", "gzip", "deflate", "inflate", "decompress", "gunzip"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        format: { type: "string", title: "Format", enum: ["zlib", "gzip", "deflate-raw"], default: "zlib" },
        maxOutputBytes: { type: "integer", title: "Maximum output (bytes)", minimum: 1, maximum: 1024 * MiB, default: 256 * MiB },
        allowPartial: { type: "boolean", title: "Keep output if the stream is damaged", default: false },
      },
      required: ["format", "maxOutputBytes", "allowPartial"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "medium",
  },
  async run(ctx, inputs, params) {
    let result: InflateResult;
    try {
      result = await inflate(bytesInput(inputs), params.format, { maxOutputBytes: params.maxOutputBytes, signal: ctx.signal });
    } catch (error) {
      if (error instanceof InflateLimitError) throw new OperationError("INVALID_INPUT", error.message);
      throw error;
    }
    if (result.error) {
      const produced = result.bytes.length;
      if (!params.allowPartial || produced === 0) {
        throw new OperationError(
          "INVALID_INPUT",
          `Decompression failed${produced > 0 ? ` after ${produced} bytes` : ""}: ${result.error}` +
            (produced > 0 ? ' (enable "Keep output if the stream is damaged" to keep them)' : ""),
        );
      }
      ctx.diagnostic(`The stream is damaged or has trailing data; kept ${produced} bytes decoded before the error.`);
    }
    return { data: bytesFrom(result.bytes) };
  },
});
