import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { MAX_EVTX_BYTES } from "../../formats/evtx";
import { evtxNestedSubstitutions } from "../../formats/evtxSubstitutions";
import { bytesInput } from "../util";

export const evtxNestedSubstitutionsInspect = defineOperation<{ chunkIndex: number; recordIndex: number; substitutionIndex: number }>({
  spec: {
    id: "forensics.windows.evtx.nested-substitutions", version: "1.0.0", title: "Inspect nested EVTX substitutions", category: "Forensics",
    description: "Decode indexed typed values inside a CRC-checked inline nested BinXML substitution. The parent must itself use a supported inline template; event-field names and other template forms are not decoded.",
    keywords: ["evtx", "binxml", "nested", "substitution", "event log"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      chunkIndex: { type: "integer", title: "Chunk index (zero-based)", minimum: 0, maximum: 255, default: 0 },
      recordIndex: { type: "integer", title: "Record index within chunk (zero-based)", minimum: 0, maximum: 4095, default: 0 },
      substitutionIndex: { type: "integer", title: "Nested substitution index (zero-based)", minimum: 0, maximum: 127, default: 0 },
    }, required: ["chunkIndex", "recordIndex", "substitutionIndex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: MAX_EVTX_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await evtxNestedSubstitutions(bytesInput(inputs), params.chunkIndex, params.recordIndex,
        params.substitutionIndex, ctx.signal);
      ctx.diagnostic(`Decoded ${report.substitutions.length} nested indexed substitution(s); event fields remain unmapped.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
