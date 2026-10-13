import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { diffHar } from "../../formats/harDiff";
import { bytesInput, MiB } from "../util";

export const harDiff = defineOperation<{ baselinePage: string; candidatePage: string; ignoredQueryKeys: string; maxChanges: number }>({
  spec: {
    id: "network.har.diff", version: "1.0.0", title: "Compare HAR requests", category: "Network",
    description: "Compare two page captures within an offline HAR 1.2 file by method, origin, path and query-key names. Query values, headers, cookies and bodies are omitted; matching does not prove requests had identical values.",
    keywords: ["har", "burp", "http", "request", "response", "differential", "offline"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        baselinePage: { type: "string", title: "Baseline page ID (blank = first)", maxLength: 256, default: "" },
        candidatePage: { type: "string", title: "Candidate page ID (blank = second)", maxLength: 256, default: "" },
        ignoredQueryKeys: { type: "string", title: "Noise query keys (comma-separated)", maxLength: 1_024, default: "cb,utm_source,utm_medium,utm_campaign" },
        maxChanges: { type: "integer", title: "Maximum differences", minimum: 1, maximum: 2_000, default: 1_000 },
      },
      required: ["baselinePage", "candidatePage", "ignoredQueryKeys", "maxChanges"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 8 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      ctx.throwIfAborted();
      const text = new TextDecoder("utf-8", { fatal: true }).decode(await readAll(bytesInput(inputs), 8 * MiB));
      const report = diffHar(text, params.baselinePage, params.candidatePage, params.ignoredQueryKeys, params.maxChanges);
      ctx.throwIfAborted();
      ctx.diagnostic(`Compared ${report.matched} normalized HAR request pair(s): ${report.changed.length} changed, ${report.missing.length} missing, ${report.added.length} added. Query values and request/response bodies were not compared.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});