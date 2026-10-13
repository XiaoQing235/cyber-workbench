import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { MAX_EVTX_BYTES } from "../../formats/evtx";
import { evtxSubstitutions } from "../../formats/evtxSubstitutions";
import { bytesInput } from "../util";

export const evtxSubstitutionsInspect = defineOperation<{ chunkIndex: number; recordIndex: number }>({
  spec: {
    id: "forensics.windows.evtx.substitutions", version: "1.0.0", title: "Inspect EVTX substitutions", category: "Forensics",
    description: "Read typed substitution values and source byte offsets from one CRC-checked inline-template EVTX BinXML record. Values are indexed; template names, event fields, and nested payloads are not decoded. Unsupported value types are null.",
    keywords: ["evtx", "windows", "binxml", "substitution", "event log"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      chunkIndex: { type: "integer", title: "Chunk index (zero-based)", minimum: 0, maximum: 255, default: 0 },
      recordIndex: { type: "integer", title: "Record index within chunk (zero-based)", minimum: 0, maximum: 4095, default: 0 },
    }, required: ["chunkIndex", "recordIndex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: MAX_EVTX_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await evtxSubstitutions(bytesInput(inputs), params.chunkIndex, params.recordIndex, ctx.signal);
      ctx.diagnostic(`Decoded ${report.substitutions.length} indexed EVTX substitution(s); event fields are not mapped.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
