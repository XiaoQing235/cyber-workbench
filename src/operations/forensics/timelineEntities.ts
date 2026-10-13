import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { textValue } from "../../core/value";
import { timelineEntityEvents } from "../../formats/entityCorrelation";
import type { TimelineFormat } from "../../formats/windowsTimeline";
import { textInput } from "../util";

export const timelineEntitiesExport = defineOperation<{ format: TimelineFormat; timezoneOffsetMinutes: number; sourceLabel: string }>({
  spec: {
    id: "forensics.timeline.entities", version: "1.4.0", title: "Export timeline entities", category: "Forensics",
    description: "Import Plaso JSONL, Hayabusa CSV/JSONL, or MFTECmd CSV and export observed absolute paths, valid IPv4 from SourceIp/DestinationIp, and bounded account/SID identities from explicit Hayabusa JSONL fields. Messages are not scanned for speculative entities.",
    keywords: ["timeline", "mftecmd", "hayabusa", "plaso", "file", "entity", "correlation"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "text", type: "text" }],
    parametersSchema: { type: "object", properties: {
      format: { type: "string", title: "Input format", enum: ["plaso-jsonl", "hayabusa-csv", "hayabusa-jsonl", "mftecmd-csv", "mixed-json"], default: "plaso-jsonl" },
      timezoneOffsetMinutes: { type: "integer", title: "UTC offset for naive timestamps (minutes)", minimum: -720, maximum: 840, default: 0 },
      sourceLabel: { type: "string", title: "Source label (unique per import)", maxLength: 64, default: "timeline" },
    }, required: ["format", "timezoneOffsetMinutes", "sourceLabel"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: 2_000_000 },
  },
  async run(ctx, inputs, params) {
    try {
      ctx.throwIfAborted();
      const events = await timelineEntityEvents(textInput(inputs), params.format, params.timezoneOffsetMinutes, params.sourceLabel);
      ctx.throwIfAborted();
      return { text: textValue(JSON.stringify(events)) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
