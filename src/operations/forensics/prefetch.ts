import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { inspectPrefetch, MAX_PREFETCH_BYTES } from "../../formats/prefetch";
import { bytesInput } from "../util";

export const prefetchInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.windows.prefetch.inspect", version: "1.1.0", title: "Inspect Windows Prefetch", category: "Forensics",
    description: "Read bounded uncompressed SCCA v17/v23/v26/v30 executable, hash, run count and recorded FILETIMEs. Both known v30 file-information variants are supported; MAM-compressed files are not decoded.",
    keywords: ["prefetch", "scca", "windows", "run count", "filetime", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_PREFETCH_BYTES },
  },
  async run(ctx, inputs) {
    try { return { report: structuredValue(await inspectPrefetch(bytesInput(inputs), ctx.signal)) }; }
    catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const prefetchTimelineExport = defineOperation<{ hostname: string }>({
  spec: {
    id: "forensics.windows.prefetch.timeline-export", version: "1.0.0", title: "Export Prefetch timeline", category: "Forensics",
    description: "Export recorded uncompressed Prefetch run FILETIMEs as bounded Plaso-style JSONL for offline timeline correlation. A missing hostname stays blank.",
    keywords: ["prefetch", "timeline", "filetime", "windows", "plaso"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "text", type: "text" }],
    parametersSchema: { type: "object", properties: {
      hostname: { type: "string", title: "Host identifier (optional)", maxLength: 256, default: "" },
    }, required: ["hostname"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_PREFETCH_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const prefetch = await inspectPrefetch(bytesInput(inputs), ctx.signal);
      const times = [prefetch.lastRun, ...prefetch.olderRuns].filter((time): time is NonNullable<typeof prefetch.lastRun> => time !== null);
      if (!times.length) throw new Error("Prefetch has no recorded execution time to export");
      const records = times.map((time) => JSON.stringify({ timestamp: time.utc, parser: "prefetch", hostname: params.hostname,
        filename: prefetch.executable, message: `Prefetch execution (hash ${prefetch.hash})` }));
      ctx.diagnostic(`Exported ${records.length} Prefetch execution timestamp(s) to the offline timeline.`);
      return { text: textValue(records.join("\n")) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
