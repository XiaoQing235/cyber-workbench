import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { readBrowserHistory, type BrowserHistoryReport } from "../../formats/browserHistory";
import { MiB } from "../util";
import { openDatabase } from "../database/sqlite";

type HistoryParams = { browser: "auto" | "chromium" | "firefox"; maxVisits: number };

const PARAMETERS = {
  type: "object" as const,
  properties: {
    browser: { type: "string" as const, title: "Browser schema", enum: ["auto", "chromium", "firefox"], default: "auto" },
    maxVisits: { type: "integer" as const, title: "Maximum visits", minimum: 1, maximum: 5_000, default: 1_000 },
  },
  required: ["browser", "maxVisits"],
  additionalProperties: false as const,
};

async function history(inputs: Parameters<typeof openDatabase>[0], params: HistoryParams): Promise<BrowserHistoryReport & { walMode: boolean }> {
  const { db, header } = await openDatabase(inputs);
  try {
    return { ...readBrowserHistory(db, params.browser, params.maxVisits), walMode: header.writeVersion === 2 || header.readVersion === 2 };
  } finally { db.close(); }
}

export const browserHistoryInspect = defineOperation<HistoryParams>({
  spec: {
    id: "forensics.browser-history.inspect", version: "1.0.0", title: "Inspect browser history", category: "Forensics",
    description: "Inspect bounded Chromium or Firefox SQLite visits with exact UTC microseconds. A separate SQLite WAL file is not merged into the supplied database.",
    keywords: ["chrome", "chromium", "firefox", "history", "sqlite", "visits", "timeline"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: PARAMETERS,
    runtime: "wasm", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const report = await history(inputs, params);
    ctx.throwIfAborted();
    ctx.diagnostic(`Read ${report.visits.length} ${report.browser} visit(s).${report.truncated ? " Visit limit reached." : ""}${report.walMode ? " WAL mode: newer records may be in a separate -wal file." : ""}`);
    return { report: structuredValue(report) };
  },
});

export const browserHistoryTimelineExport = defineOperation<HistoryParams & { hostname: string }>({
  spec: {
    id: "forensics.browser-history.timeline-export", version: "1.0.0", title: "Export browser visits to timeline", category: "Forensics",
    description: "Export bounded Chrome/Firefox visit IDs, URLs, titles and precise timestamps as Plaso-style JSONL. Hostnames are supplied explicitly for later correlation.",
    keywords: ["chrome", "firefox", "history", "timeline", "plaso", "visits"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      ...PARAMETERS,
      properties: { ...PARAMETERS.properties, hostname: { type: "string", title: "Host identifier (optional)", maxLength: 256, default: "" } },
      required: [...PARAMETERS.required, "hostname"],
    },
    runtime: "wasm", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 64 * MiB },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const report = await history(inputs, params);
    ctx.throwIfAborted();
    const lines = report.visits.map((visit) => JSON.stringify({
      timestamp: visit.utc, parser: `${report.browser}_history`, hostname: params.hostname,
      filename: visit.url, message: `Visit ${visit.visitId}: ${visit.title}`,
    }));
    ctx.diagnostic(`Exported ${lines.length} ${report.browser} visit(s) to timeline JSONL.${report.walMode ? " A separate WAL may hold additional visits." : ""}`);
    return { text: textValue(lines.join("\n")) };
  },
});