import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { importWindowsTimeline, type TimelineFormat } from "../../formats/windowsTimeline";
import { textInput } from "../util";

export const timelineImport = defineOperation<{ format: TimelineFormat; timezoneOffsetMinutes: number; windowSeconds: number }>({
  spec: {
    id: "forensics.timeline.import", version: "1.4.0", title: "Import forensic timeline", category: "Forensics",
    description: "Import Plaso JSONL, Hayabusa CSV/JSONL, KAPE/MFTECmd CSV, or a mixed JSON array of Plaso and Hayabusa; normalize UTC with an explicit naive-time offset, deduplicate, and link nearby host/path activity.",
    keywords: ["timeline", "plaso", "hayabusa", "mftecmd", "kape", "evtx", "sysmon", "windows", "correlation", "csv"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        format: { type: "string", title: "Input format", enum: ["plaso-jsonl", "hayabusa-csv", "hayabusa-jsonl", "mftecmd-csv", "mixed-json"], default: "plaso-jsonl" },
        timezoneOffsetMinutes: { type: "integer", title: "UTC offset for naive timestamps (minutes)", minimum: -720, maximum: 840, default: 0 },
        windowSeconds: { type: "integer", title: "Correlation window (seconds)", minimum: 1, maximum: 3_600, default: 60 },
      },
      required: ["format", "timezoneOffsetMinutes", "windowSeconds"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 2_000_000 },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const text = textInput(inputs);
    if (text.length > 2_000_000 || new TextEncoder().encode(text).length > 2_000_000) throw new OperationError("INPUT_TOO_LARGE", "Timeline input is limited to 2 MB of UTF-8 text");
    try {
      const report = await importWindowsTimeline(text, params.format, params.timezoneOffsetMinutes, params.windowSeconds);
      ctx.throwIfAborted();
      ctx.diagnostic(`Imported ${report.total} event(s), removed ${report.duplicates} duplicate(s), and linked ${report.linked} host/path event(s).${report.truncatedLinks ? " Link limit reached." : ""}`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
