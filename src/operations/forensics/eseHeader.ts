import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { inspectEseHeader, MAX_ESE_BYTES } from "../../formats/eseHeader";
import { bytesInput } from "../util";

export const eseHeaderInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.windows.ese.header", version: "1.0.0", title: "Inspect ESE database header", category: "Forensics",
    description: "Inspect bounded ESE/ESENT page size, state, version, primary header checksum and shadow header from a database such as SRUDB.dat. SRUM rows and ESE pages are not decoded.",
    keywords: ["srum", "sru", "esent", "ese", "edb", "windows", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_ESE_BYTES },
  },
  async run(ctx, inputs) {
    try { return { report: structuredValue(await inspectEseHeader(bytesInput(inputs), ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
