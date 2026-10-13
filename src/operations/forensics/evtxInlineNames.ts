import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { MAX_EVTX_BYTES } from "../../formats/evtx";
import { evtxInlineNames } from "../../formats/evtxTemplateNames";
import { bytesInput } from "../util";

export const evtxInlineNamesInspect = defineOperation<{ chunkIndex: number; recordIndex: number }>({
  spec: {
    id: "forensics.windows.evtx.inline-names", version: "1.0.0", title: "Inspect EVTX inline names", category: "Forensics",
    description: "Inventory bounded inline BinXML name candidates and source offsets in one CRC-checked EVTX record. This does not map substitutions to event fields or decode external name references.",
    keywords: ["evtx", "binxml", "inline", "template", "name"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      chunkIndex: { type: "integer", title: "Chunk index (zero-based)", minimum: 0, maximum: 255, default: 0 },
      recordIndex: { type: "integer", title: "Record index within chunk (zero-based)", minimum: 0, maximum: 4095, default: 0 },
    }, required: ["chunkIndex", "recordIndex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: MAX_EVTX_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await evtxInlineNames(bytesInput(inputs), params.chunkIndex, params.recordIndex, ctx.signal);
      ctx.diagnostic(`Found ${report.names.length} candidate inline EVTX name(s); event fields are not mapped.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
