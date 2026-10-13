import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { inspectCloudTrail, observedRoleGraph } from "../../formats/cloudTrail";
import { textInput } from "../util";

const PARAMETERS = { type: "object" as const, properties: {}, additionalProperties: false as const };

export const cloudTrailInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.cloudtrail.inspect", version: "1.1.0", title: "Inspect CloudTrail events", category: "Forensics",
    description: "Inspect bounded offline CloudTrail JSON Records, a single event, or JSONL exports with @timestamp. Preserves event IDs, UTC microseconds, account/principal, targets, source addresses and errors; decompress .gz logs first.",
    keywords: ["aws", "cloudtrail", "iam", "role", "api", "audit", "forensics"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: PARAMETERS,
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs) {
    try {
      const report = inspectCloudTrail(textInput(inputs));
      ctx.throwIfAborted();
      ctx.diagnostic(`Inspected ${report.total} CloudTrail event(s) from ${report.services.length} service(s); ${report.duplicateEventIds} repeated event ID(s) retained.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const cloudTrailTimelineExport = defineOperation<{ hostname: string }>({
  spec: {
    id: "forensics.cloudtrail.timeline-export", version: "1.0.0", title: "Export CloudTrail timeline", category: "Forensics",
    description: "Export offline CloudTrail API events as Plaso-style JSONL for correlation. The host identifier is supplied explicitly; account and principal remain in each event message.",
    keywords: ["aws", "cloudtrail", "timeline", "plaso", "iam", "forensics"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      ...PARAMETERS,
      properties: { hostname: { type: "string", title: "Host identifier (optional)", maxLength: 256, default: "" } },
      required: ["hostname"],
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs, params) {
    try {
      const report = inspectCloudTrail(textInput(inputs));
      ctx.throwIfAborted();
      const lines = report.events.map((event) => JSON.stringify({
        timestamp: event.utc, parser: "cloudtrail", hostname: params.hostname,
        filename: event.targetRoleArn ?? event.resources[0] ?? "",
        message: `CloudTrail ${event.eventSource} ${event.eventName} by ${event.principal ?? "unknown principal"} in ${event.accountId ?? "unknown account"}${event.errorCode ? ` failed: ${event.errorCode}` : ""} (event ${event.eventId})`,
      }));
      ctx.diagnostic(`Exported ${lines.length} CloudTrail event(s) for timeline import; duplicate IDs are retained.`);
      return { text: textValue(lines.join("\n")) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const cloudTrailRoleGraph = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.cloudtrail.role-graph", version: "1.0.0", title: "Graph observed IAM role calls", category: "Forensics",
    description: "Group offline STS AssumeRole calls by caller and target role. Reported errors are separate and repeated event IDs count once. Observed calls do not prove IAM trust or effective permissions.",
    keywords: ["aws", "cloudtrail", "iam", "sts", "role", "graph", "forensics"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: PARAMETERS,
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs) {
    try {
      const graph = observedRoleGraph(inspectCloudTrail(textInput(inputs)));
      ctx.throwIfAborted();
      ctx.diagnostic(`Observed ${graph.edges.length} STS caller/role/outcome edge(s). Skipped ${graph.skippedDuplicateIds} duplicate ID(s) and ${graph.skippedMissingIdentity} call(s) lacking identity. This is not an authorization graph.`);
      return { report: structuredValue(graph) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
