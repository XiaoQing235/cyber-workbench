import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { planFormatWrites } from "../../formats/formatString";
import { bytesInput } from "../util";

/** The bytes input anchors the report to an artifact; no bytes are executed or changed. */
export const formatStringWrites = defineOperation<{
  address: string; value: string; byteCount: number; firstArgument: number; paddingArgument: number; alreadyPrinted: number; writeWidthBytes: 1 | 2;
}>({
  spec: {
    id: "reverse.format-string.writes", version: "1.2.0", title: "Plan format-string byte writes", category: "Reverse",
    description: "Plan bounded positional %hhn byte or %hn halfword writes for a 1–8 byte little-endian value with argument 1 as a character and contiguous pointer arguments from 2. The report does not embed addresses, execute the format string, or establish an exploit.",
    keywords: ["format string", "hhn", "hn", "printf", "constraint", "write"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      address: { type: "string", title: "First write address (hex)", pattern: "^0[xX][0-9a-fA-F]+$", maxLength: 18, default: "0x0" },
      value: { type: "string", title: "Little-endian value (hex)", pattern: "^0[xX][0-9a-fA-F]+$", maxLength: 18, default: "0x0" },
      byteCount: { type: "integer", title: "Bytes to write", minimum: 1, maximum: 8, default: 4 },
      firstArgument: { type: "integer", title: "First pointer argument (2)", minimum: 2, maximum: 2, default: 2 },
      paddingArgument: { type: "integer", title: "Separate character argument (1)", minimum: 1, maximum: 1, default: 1 },
      alreadyPrinted: { type: "integer", title: "Characters already printed", minimum: 0, maximum: 1_000_000, default: 0 },
      writeWidthBytes: { type: "integer", title: "Bytes per write (1 = hhn, 2 = hn)", minimum: 1, maximum: 2, default: 1 },
    }, required: ["address", "value", "byteCount", "firstArgument", "paddingArgument", "alreadyPrinted", "writeWidthBytes"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 256 * 1024 * 1024 },
  },
  async run(ctx, inputs, params) {
    bytesInput(inputs);
    ctx.throwIfAborted();
    try { return { report: structuredValue(planFormatWrites(params.address, params.value, params.byteCount,
      params.firstArgument, params.paddingArgument, params.alreadyPrinted, params.writeWidthBytes)) }; }
    catch (error) { throw new OperationError("INVALID_PARAMS", error instanceof Error ? error.message : String(error)); }
  },
});
