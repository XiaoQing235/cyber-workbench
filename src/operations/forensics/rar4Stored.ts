import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue } from "../../core/value";
import { extractRar4Stored, extractRar5Stored } from "../../formats/rar7z";
import { bytesInput, MiB } from "../util";

export const rar4StoredExtract = defineOperation<{ entryIndex: number }>({
  spec: {
    id: "archive.rar4.stored-extract", version: "1.0.0", title: "Extract RAR4 stored file", category: "Forensics",
    description: "Extract one indexed unencrypted, uncompressed RAR4 regular file after validating headers and member CRC. Split, compressed, encrypted, directory and symlink entries are unsupported.",
    keywords: ["rar", "rar4", "store", "archive", "extract"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      entryIndex: { type: "integer", title: "File index (zero-based)", minimum: 0, maximum: 9999, default: 0 },
    }, required: ["entryIndex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs, params) {
    try { return { data: bytesValue(await extractRar4Stored(bytesInput(inputs), params.entryIndex, ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const rar5StoredExtract = defineOperation<{ entryIndex: number }>({
  spec: {
    id: "archive.rar5.stored-extract", version: "1.0.0", title: "Extract RAR5 stored file", category: "Forensics",
    description: "Extract one indexed RAR5 stored regular file with header and member CRC validation. Compressed, encrypted, split, linked and directory members are unsupported.",
    keywords: ["rar", "rar5", "store", "archive", "extract"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      entryIndex: { type: "integer", title: "File index (zero-based)", minimum: 0, maximum: 9999, default: 0 },
    }, required: ["entryIndex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs, params) {
    try { return { data: bytesValue(await extractRar5Stored(bytesInput(inputs), params.entryIndex, ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
