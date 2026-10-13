import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { correlateEntities } from "../../formats/entityCorrelation";
import { textInput } from "../util";

export const entityCorrelate = defineOperation<{ windowSeconds: number }>({
  spec: {
    id: "forensics.entities.correlate", version: "1.0.0", title: "Correlate forensic entities", category: "Forensics",
    description: "Link observed IP, domain, file and identity strings across bounded JSON event records by exact normalized value and UTC time window. Links are temporal associations, not proof of causation.",
    keywords: ["timeline", "entity", "identity", "ip", "file", "correlation", "forensics"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      windowSeconds: { type: "integer", title: "Correlation window (seconds)", minimum: 1, maximum: 3600, default: 60 },
    }, required: ["windowSeconds"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 2 * 1024 * 1024 },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    try {
      const report = correlateEntities(textInput(inputs), params.windowSeconds);
      ctx.diagnostic(`Linked ${report.links.length} matching entity observation(s)${report.truncated ? " (limit reached)" : ""}.`);
      return { report: structuredValue(report) };
    } catch (error) { throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
