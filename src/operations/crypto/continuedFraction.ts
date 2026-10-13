import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { continuedFraction } from "../../formats/continuedFraction";
import { textInput } from "../util";

export const continuedFractionExpand = defineOperation<{ maxTerms: number }>({
  spec: {
    id: "crypto.rational.continued-fraction", version: "1.0.0", title: "Expand continued fraction", category: "Crypto",
    description: "Calculate bounded exact Euclidean quotients and convergents for a JSON numerator/denominator pair. This does not recover hidden modular errors or factor the denominators.",
    keywords: ["continued fraction", "convergent", "euclidean", "rational", "lattice", "crypto"],
    inputs: [{ name: "fraction", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      maxTerms: { type: "integer", title: "Maximum convergents", minimum: 1, maximum: 128, default: 32 },
    }, required: ["maxTerms"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 4_096 },
  },
  async run(ctx, inputs, params) {
    try {
      const report = continuedFraction(textInput(inputs, "fraction"), params.maxTerms);
      ctx.diagnostic(`Computed ${report.terms.length} exact convergent(s).${report.truncated ? " Term limit reached." : ""}`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});