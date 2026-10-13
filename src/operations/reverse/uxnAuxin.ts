import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { inspectAuxinPayload, inspectAuxinRom } from "../../formats/uxnAuxin";
import { bytesInput } from "../util";

export const uxnAuxinInspect = defineOperation<{ payloadHex: string }>({
  spec: {
    id: "reverse.uxn.auxin2", version: "1.0.0", title: "Inspect Auxin2 Uxn constraints", category: "Reverse",
    description: "Check the original 208-byte Google CTF Auxin2 ROM's fixed low-nibble rejection branches and a bounded hex payload against the published input envelope. Static analysis only: Uxn instructions and supplied payload are not executed, and no flag is recovered.",
    keywords: ["uxn", "auxin2", "rom", "shellcode", "bad byte", "constraint"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      payloadHex: { type: "string", title: "Payload bytes (lowercase hex, optional)", maxLength: 224, default: "" },
    }, required: ["payloadHex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low", limits: { maxInputBytes: 208 },
  },
  async run(ctx, inputs, params) {
    try {
      const rom = await inspectAuxinRom(bytesInput(inputs), ctx.signal);
      const payload = params.payloadHex ? inspectAuxinPayload(params.payloadHex) : null;
      ctx.diagnostic(`Inspected Auxin2 byte constraints${payload ? ` and ${payload.bytes} payload byte(s)` : ""}; no Uxn code was executed.`);
      return { report: structuredValue({ rom, payload }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
