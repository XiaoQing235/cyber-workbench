import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractSafeTensor, inspectSafeTensors } from "../../formats/safeTensors";
import { bytesInput } from "../util";

export const safeTensorsInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.model.safetensors.inspect", version: "1.0.0", title: "Inspect SafeTensors model", category: "Forensics",
    description: "Inspect bounded SafeTensors headers, tensor shapes, dtype-sized ranges and metadata key names without loading tensors or returning metadata values. No model code executes.",
    keywords: ["model", "safetensors", "tensor", "dtype", "steganography", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectSafeTensors(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Validated ${report.tensorCount} SafeTensors tensor(s); metadata values and tensor bytes are not included in the report.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const safeTensorExtract = defineOperation<{ name: string }>({
  spec: {
    id: "forensics.model.safetensors.extract", version: "1.0.0", title: "Extract SafeTensors tensor", category: "Forensics",
    description: "Extract a named tensor's raw bytes as a bounded, lazy slice. This does not interpret floats, unpickle objects or execute model code.",
    keywords: ["model", "safetensors", "tensor", "extract", "bytes", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: { name: { type: "string", title: "Tensor name", minLength: 1, maxLength: 512, default: "" } },
      required: ["name"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs, params) {
    try {
      const data = await extractSafeTensor(bytesInput(inputs), params.name, ctx.signal);
      ctx.diagnostic(`Extracted ${params.name} (${data.size} tensor byte(s)) without interpreting values.`);
      return { data: bytesValue(data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});