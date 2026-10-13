import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { diffHarHeaders } from "../../formats/harDiff";
import { bytesInput, MiB } from "../util";

export const harHeaderDiff = defineOperation<{ baselinePage: string; candidatePage: string; ignoredHeaders: string; maxChanges: number; side: "request" | "response" }>({
  spec: {
    id: "network.har.header-diff", version: "1.1.0", title: "Compare HAR headers", category: "Network",
    description: "Compare bounded HAR request or response header names and duplicate counts between two pages. Explicit noise headers are excluded; header values, cookies and bodies are never returned.",
    keywords: ["har", "http", "request", "headers", "diff", "offline"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      baselinePage: { type: "string", title: "Baseline page (blank = first)", maxLength: 256, default: "" },
      candidatePage: { type: "string", title: "Candidate page (blank = second)", maxLength: 256, default: "" },
      ignoredHeaders: { type: "string", title: "Noise headers (comma-separated)", maxLength: 1024, default: "date,set-cookie,authorization" },
      maxChanges: { type: "integer", title: "Maximum changes", minimum: 1, maximum: 2000, default: 1000 },
      side: { type: "string", title: "Headers from", enum: ["request", "response"], default: "request" },
    }, required: ["baselinePage", "candidatePage", "ignoredHeaders", "maxChanges", "side"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: 8 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      ctx.throwIfAborted();
      const text = new TextDecoder("utf-8", { fatal: true }).decode(await readAll(bytesInput(inputs), 8 * MiB));
      const report = diffHarHeaders(text, params.baselinePage, params.candidatePage, params.ignoredHeaders, params.maxChanges, params.side);
      return { report: structuredValue(report) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
