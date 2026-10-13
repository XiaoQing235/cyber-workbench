import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { diffBurp } from "../../formats/burpDiff";
import { bytesInput, MiB } from "../util";

export const burpDiff = defineOperation<{ baselineCount: number; ignoredQueryKeys: string; maxChanges: number }>({
  spec: {
    id: "network.burp.diff", version: "1.0.0", title: "Compare Burp requests", category: "Network",
    description: "Compare the first N items in an offline Burp XML export against the remaining items. Normalizes method, origin, path and query-key names; compares status only. Request/response payloads, secrets and response lengths are not decoded or returned.",
    keywords: ["burp", "xml", "http", "request", "response", "differential", "offline"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      baselineCount: { type: "integer", title: "Number of baseline items (remaining items are candidates)", minimum: 1, maximum: 4_999, default: 1 },
      ignoredQueryKeys: { type: "string", title: "Noise query keys (comma-separated)", maxLength: 1_024, default: "cb,utm_source,utm_medium,utm_campaign" },
      maxChanges: { type: "integer", title: "Maximum differences", minimum: 1, maximum: 2_000, default: 1_000 },
    }, required: ["baselineCount", "ignoredQueryKeys", "maxChanges"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 8 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      ctx.throwIfAborted();
      const text = new TextDecoder("utf-8", { fatal: true }).decode(await readAll(bytesInput(inputs), 8 * MiB));
      ctx.throwIfAborted();
      const report = await diffBurp(text, params.baselineCount, params.ignoredQueryKeys, params.maxChanges);
      ctx.diagnostic(`Compared ${report.matched} normalized Burp request pair(s). Only response statuses were compared; request/response payloads and response lengths were not compared.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
