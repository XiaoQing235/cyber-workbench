import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { inspectDex, MAX_DEX_BYTES } from "../../formats/dex";
import { bytesInput } from "../util";

export const dexInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.android.dex.inspect", version: "1.0.0", title: "Inspect Android DEX", category: "Reverse",
    description: "Inspect DEX 035 header tables and the first ASCII class descriptor. Adler-32 and SHA-1 are verified; other versions and modified UTF-8 descriptors are not decoded. No code executes.",
    keywords: ["android", "dex", "apk", "class", "bytecode", "reverse"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_DEX_BYTES },
  },
  async run(ctx, inputs) {
    try {
      ctx.throwIfAborted();
      const report = await inspectDex(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`DEX ${report.version}: ${report.classes} class(es), ${report.methods} method ID(s); Adler-32 and SHA-1 verified. No bytecode executed.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});