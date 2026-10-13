import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { extractTensorBits, MAX_TENSOR_OUTPUT_BYTES } from "../../formats/tensorBits";
import { bytesInput } from "../util";

export const tensorBitsExtract = defineOperation<{ name: string; bit: number; bitOrder: "msb" | "lsb"; maxOutputBytes: number }>({
  spec: {
    id: "forensics.model.safetensors.bits", version: "1.1.0", title: "Extract tensor bit plane", category: "Forensics",
    description: "Extract one chosen bit from each stored SafeTensors element, including raw floating-point representation bits, packed to bytes. Uses bounded reads, leaves trailing partial-byte bits zero, and does not execute a model.",
    keywords: ["tensor", "safetensors", "steganography", "lsb", "bit plane", "model"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      name: { type: "string", title: "Tensor name", minLength: 1, maxLength: 512, default: "" },
      bit: { type: "integer", title: "Bit index in each stored element", minimum: 0, maximum: 63, default: 0 },
      bitOrder: { type: "string", title: "Bit order in output bytes", enum: ["msb", "lsb"], default: "msb" },
      maxOutputBytes: { type: "integer", title: "Maximum extracted bytes", minimum: 1, maximum: MAX_TENSOR_OUTPUT_BYTES, default: MAX_TENSOR_OUTPUT_BYTES },
    }, required: ["name", "bit", "bitOrder", "maxOutputBytes"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "medium",
  },
  async run(ctx, inputs, params) {
    try {
      const result = await extractTensorBits(bytesInput(inputs), params.name, params.bit, params.bitOrder, params.maxOutputBytes, ctx.signal);
      ctx.diagnostic(`Packed ${result.samples} tensor bit(s) into ${result.data.length} byte(s); trailing bits are zero padding.`);
      return { data: bytesFrom(new Uint8Array(result.data)), report: structuredValue({ tensor: params.name, samples: result.samples,
        bit: params.bit, bitOrder: params.bitOrder, outputBytes: result.data.length, verifiedPayload: false }) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
