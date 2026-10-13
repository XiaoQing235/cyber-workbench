import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractAsarFile, inspectAsar } from "../../formats/asar";
import { bytesInput } from "../util";

export const asarInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.asar.inspect", version: "1.0.0", title: "Inspect Electron ASAR", category: "Reverse",
    description: "Inspect bounded ASAR header files, links, sidecar/unpacked flags, data offsets and declared SHA-256 values. File hashes are not called verified until extraction.",
    keywords: ["electron", "asar", "archive", "integrity", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectAsar(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`ASAR header lists ${report.files.length} item(s) and ${report.directories} director${report.directories === 1 ? "y" : "ies"}; file hashes have not been checked.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const asarExtract = defineOperation<{ path: string }>({
  spec: {
    id: "reverse.asar.extract", version: "1.0.0", title: "Extract ASAR file", category: "Reverse",
    description: "Extract a packed ASAR file by path, verifying its declared SHA-256 before returning bytes. Linked and sidecar/unpacked entries are not followed.",
    keywords: ["electron", "asar", "archive", "extract", "integrity", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: { path: { type: "string", title: "Packed file path", minLength: 1, maxLength: 1_024, default: "" } },
      required: ["path"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
  },
  async run(ctx, inputs, params) {
    try {
      const result = await extractAsarFile(bytesInput(inputs), params.path, ctx.signal);
      ctx.diagnostic(`Extracted ${params.path} (${result.data.size} bytes); declared SHA-256 ${result.integrityVerified ? "verified" : "not available"}.`);
      return { data: bytesValue(result.data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});