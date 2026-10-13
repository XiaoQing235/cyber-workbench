import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractOnnxTensor, inspectOnnx } from "../../formats/onnx";
import { bytesInput, MiB } from "../util";

export const onnxInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.model.onnx.inspect", version: "1.0.0", title: "Inspect ONNX model", category: "Forensics",
    description: "Read bounded ONNX protobuf graph inputs, outputs, node operators, initializer shapes and raw-data lengths. External tensors are never fetched; the graph is not validated or executed.",
    keywords: ["onnx", "model", "protobuf", "graph", "tensor", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 16 * MiB },
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectOnnx(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Inventoried ${report.graph.nodes.length} ONNX node(s) and ${report.graph.initializers.length} initializer(s); no graph was validated or executed.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const onnxTensorExtract = defineOperation<{ name: string }>({
  spec: {
    id: "forensics.model.onnx.extract", version: "1.0.0", title: "Extract ONNX tensor bytes", category: "Forensics",
    description: "Extract up to 8 MiB of embedded ONNX initializer raw_data by exact tensor name. External references are never fetched, and numeric values are not interpreted.",
    keywords: ["onnx", "model", "tensor", "raw_data", "extract", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      name: { type: "string", title: "Initializer name", minLength: 1, maxLength: 512, default: "" },
    }, required: ["name"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 16 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const data = await extractOnnxTensor(bytesInput(inputs), params.name, ctx.signal);
      ctx.diagnostic(`Extracted ${data.size} embedded byte(s) from ONNX initializer ${params.name}; no numeric data was interpreted.`);
      return { data: bytesValue(data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
