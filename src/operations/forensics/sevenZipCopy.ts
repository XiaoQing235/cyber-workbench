import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractSevenZipCopy, inspectSevenZipCopy } from "../../formats/sevenZipCopy";
import { bytesInput, MiB } from "../util";

export const sevenZipCopyInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "archive.sevenzip.copy.inspect", version: "1.2.0", title: "Inspect 7z Copy files", category: "Forensics",
    description: "Inspect a bounded 7z archive with independent uncompressed Copy streams and optional empty files/directories. Verifies header CRCs; other compression and solid archives are unsupported.",
    keywords: ["7z", "7zip", "copy", "archive", "uncompressed"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs) {
    try { return { report: structuredValue(await inspectSevenZipCopy(bytesInput(inputs), ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const sevenZipCopyExtract = defineOperation<{ entryIndex: number }>({
  spec: {
    id: "archive.sevenzip.copy.extract", version: "1.2.0", title: "Extract 7z Copy file", category: "Forensics",
    description: "Extract one indexed uncompressed Copy regular file after verifying its 7z header and selected payload CRC. Directory entries are listed but cannot be extracted as files.",
    keywords: ["7z", "7zip", "copy", "archive", "extract"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      entryIndex: { type: "integer", title: "File index (zero-based)", minimum: 0, maximum: 127, default: 0 },
    }, required: ["entryIndex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 512 * MiB },
  },
  async run(ctx, inputs, params) {
    try { return { data: bytesValue(await extractSevenZipCopy(bytesInput(inputs), ctx.signal, params.entryIndex)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
