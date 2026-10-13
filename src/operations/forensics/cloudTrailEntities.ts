import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { textValue } from "../../core/value";
import { cloudTrailEntityEvents } from "../../formats/entityCorrelation";
import { textInput } from "../util";

export const cloudTrailEntitiesExport = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.cloudtrail.entities", version: "1.0.0", title: "Export CloudTrail entities", category: "Forensics",
    description: "Convert bounded CloudTrail Records into explicit UTC entity-event JSON for cross-source correlation. Only observed IPs, principal and resource ARNs are included.",
    keywords: ["cloudtrail", "entity", "ip", "identity", "arn", "correlation"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "text", type: "text" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 2_000_000 },
  },
  async run(ctx, inputs) {
    try { ctx.throwIfAborted(); return { text: textValue(JSON.stringify(cloudTrailEntityEvents(textInput(inputs)))) }; }
    catch (error) { throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
