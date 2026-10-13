import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue } from "../../core/value";
import { MAX_EVTX_BYTES } from "../../formats/evtx";
import { extractEvtxNestedSubstitution } from "../../formats/evtxSubstitutions";
import { bytesInput } from "../util";

export const evtxNestedExtract = defineOperation<{
  chunkIndex: number; recordIndex: number; parentIndex: number; nestedIndex: number;
}>({
  spec: {
    id: "forensics.windows.evtx.nested-extract", version: "1.0.0", title: "Extract nested EVTX value", category: "Forensics",
    description: "Export one indexed raw value inside a CRC-checked nested inline-template BinXML substitution. Binary contents are not interpreted and event fields are not mapped.",
    keywords: ["evtx", "binxml", "nested", "binary", "extract"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      chunkIndex: { type: "integer", title: "Chunk index (zero-based)", minimum: 0, maximum: 255, default: 0 },
      recordIndex: { type: "integer", title: "Record index within chunk (zero-based)", minimum: 0, maximum: 4095, default: 0 },
      parentIndex: { type: "integer", title: "Parent BinXML index (zero-based)", minimum: 0, maximum: 127, default: 19 },
      nestedIndex: { type: "integer", title: "Nested value index (zero-based)", minimum: 0, maximum: 127, default: 0 },
    }, required: ["chunkIndex", "recordIndex", "parentIndex", "nestedIndex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: MAX_EVTX_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      return { data: bytesValue(await extractEvtxNestedSubstitution(bytesInput(inputs), params.chunkIndex, params.recordIndex,
        params.parentIndex, params.nestedIndex, ctx.signal)) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
