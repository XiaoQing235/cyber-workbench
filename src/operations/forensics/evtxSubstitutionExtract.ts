import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue } from "../../core/value";
import { MAX_EVTX_BYTES } from "../../formats/evtx";
import { extractEvtxSubstitution } from "../../formats/evtxSubstitutions";
import { bytesInput } from "../util";

export const evtxSubstitutionExtract = defineOperation<{ chunkIndex: number; recordIndex: number; substitutionIndex: number }>({
  spec: {
    id: "forensics.windows.evtx.substitution-extract", version: "1.0.0", title: "Extract EVTX substitution bytes", category: "Forensics",
    description: "Export one indexed substitution's raw declared bytes from a CRC-checked inline-template EVTX record, including nested BinXML bytes. No template names, event fields or nested XML are decoded.",
    keywords: ["evtx", "binxml", "substitution", "bytes", "extract"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      chunkIndex: { type: "integer", title: "Chunk index (zero-based)", minimum: 0, maximum: 255, default: 0 },
      recordIndex: { type: "integer", title: "Record index within chunk (zero-based)", minimum: 0, maximum: 4095, default: 0 },
      substitutionIndex: { type: "integer", title: "Substitution index (zero-based)", minimum: 0, maximum: 127, default: 0 },
    }, required: ["chunkIndex", "recordIndex", "substitutionIndex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: MAX_EVTX_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      return { data: bytesValue(await extractEvtxSubstitution(bytesInput(inputs), params.chunkIndex,
        params.recordIndex, params.substitutionIndex, ctx.signal)) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
