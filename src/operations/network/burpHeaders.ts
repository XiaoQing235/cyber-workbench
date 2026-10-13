import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { diffBurpHeaders } from "../../formats/burpDiff";
import { bytesInput, MiB } from "../util";

export const burpHeaderDiff = defineOperation<{ baselineCount: number; ignoredHeaders: string; maxChanges: number; side: "request" | "response" }>({
  spec: {
    id: "network.burp.header-diff", version: "1.1.0", title: "Compare Burp headers", category: "Network",
    description: "Compare request or response header names and duplicate counts between ordered halves of a Burp XML export. Ignore specified noise headers; header values, cookies and bodies are never returned.",
    keywords: ["burp", "xml", "http", "request", "headers", "diff", "offline"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      baselineCount: { type: "integer", title: "Number of baseline items", minimum: 1, maximum: 4_999, default: 1 },
      ignoredHeaders: { type: "string", title: "Noise headers (comma-separated)", maxLength: 1024, default: "date,set-cookie,authorization" },
      maxChanges: { type: "integer", title: "Maximum differences", minimum: 1, maximum: 2000, default: 1000 },
      side: { type: "string", title: "Headers from", enum: ["request", "response"], default: "request" },
    }, required: ["baselineCount", "ignoredHeaders", "maxChanges", "side"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: 8 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      ctx.throwIfAborted();
      const text = new TextDecoder("utf-8", { fatal: true }).decode(await readAll(bytesInput(inputs), 8 * MiB));
      const report = await diffBurpHeaders(text, params.baselineCount, params.ignoredHeaders, params.maxChanges, params.side);
      ctx.throwIfAborted();
      return { report: structuredValue(report) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
