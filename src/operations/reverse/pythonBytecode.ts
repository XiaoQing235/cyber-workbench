import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractPythonMarshal, inspectPythonBytecode } from "../../formats/pythonBytecode";
import { bytesInput } from "../util";

const PARAMETERS = { type: "object" as const, properties: {}, additionalProperties: false as const };

export const pythonBytecodeInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.python.pyc.inspect", version: "1.0.0", title: "Inspect Python bytecode", category: "Reverse",
    description: "Inspect a Python 3.11, 3.12 or 3.13 .pyc envelope from 16 header bytes. Timestamp/hash invalidation is reported without unmarshalling or executing bytecode.",
    keywords: ["python", "pyc", "bytecode", "marshal", "hash", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: PARAMETERS,
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectPythonBytecode(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Python ${report.pythonVersion} ${report.invalidation} bytecode; ${report.marshalBytes} marshal byte(s) remain unparsed and unexecuted.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const pythonMarshalExtract = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.python.pyc.marshal-extract", version: "1.0.0", title: "Extract Python marshal bytes", category: "Reverse",
    description: "Slice the raw marshal payload from a verified Python 3.11-3.13 .pyc envelope. Does not unmarshal or execute the payload.",
    keywords: ["python", "pyc", "bytecode", "marshal", "extract", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: PARAMETERS,
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs) {
    try {
      const data = await extractPythonMarshal(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Sliced ${data.size} marshal byte(s) without parsing or executing them.`);
      return { data: bytesValue(data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});