import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { extractOnnxTensorBits } from "../../formats/onnx";
import { bytesInput, MiB } from "../util";

export const onnxTensorBits = defineOperation<{ name: string; bit: number; maxOutputBytes: number }>({
  spec: {
    id: "forensics.model.onnx.bits", version: "1.0.0", title: "Extract ONNX tensor bit plane", category: "Forensics",
    description: "Pack one selected bit from each fixed-width element of an embedded ONNX raw_data tensor. External tensor data is never fetched and no model is executed.",
    keywords: ["onnx", "tensor", "bit plane", "steganography", "model"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      name: { type: "string", title: "Initializer name", minLength: 1, maxLength: 512, default: "" },
      bit: { type: "integer", title: "Bit index in stored element", minimum: 0, maximum: 63, default: 0 },
      maxOutputBytes: { type: "integer", title: "Maximum extracted bytes", minimum: 1, maximum: MiB, default: MiB },
    }, required: ["name", "bit", "maxOutputBytes"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: 16 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const { data, samples, dataType } = await extractOnnxTensorBits(bytesInput(inputs), params.name, params.bit, params.maxOutputBytes, ctx.signal);
      return { data: bytesFrom(data), report: structuredValue({ samples, dataType, bit: params.bit, verifiedPayload: false }) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
