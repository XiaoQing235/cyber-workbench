import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue, textValue } from "../../core/value";
import { inspectLnk, MAX_LNK_BYTES } from "../../formats/lnk";
import { bytesInput } from "../util";

export const lnkInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.lnk.inspect", version: "1.0.0", title: "Inspect Windows shortcut", category: "Forensics",
    description: "Inspect bounded ShellLink flags, Unicode paths and target-file FILETIMEs. ID-list-only targets remain unresolved unless an explicit path field is present.",
    keywords: ["lnk", "shortcut", "shelllink", "windows", "filetime", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_LNK_BYTES },
  },
  async run(ctx, inputs) {
    try {
      return { report: structuredValue(await inspectLnk(bytesInput(inputs), ctx.signal)) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const lnkTimelineExport = defineOperation<{ hostname: string }>({
  spec: {
    id: "forensics.lnk.timeline-export", version: "1.0.0", title: "Export shortcut timeline", category: "Forensics",
    description: "Export ShellLink target-file creation, access, and modification FILETIMEs as Plaso-style JSONL. An unknown hostname stays blank for later correlation.",
    keywords: ["lnk", "shortcut", "timeline", "filetime", "plaso", "windows"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: { hostname: { type: "string", title: "Host identifier (optional)", maxLength: 256, default: "" } },
      required: ["hostname"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_LNK_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const lnk = await inspectLnk(bytesInput(inputs), ctx.signal);
      if (!lnk.targetPath) throw new Error("Shortcut target path is unresolved from available LinkInfo/StringData");
      const records = [
        [lnk.created, "LNK target file creation time"],
        [lnk.accessed, "LNK target file access time"],
        [lnk.modified, "LNK target file modification time"],
      ].filter((entry): entry is [NonNullable<typeof lnk.created>, string] => entry[0] !== null)
        .map(([time, message]) => JSON.stringify({ timestamp: time.utc, parser: "lnk", hostname: params.hostname, filename: lnk.targetPath, message }));
      if (records.length === 0) throw new Error("Shortcut has no target-file timestamps to export");
      ctx.diagnostic(`Exported ${records.length} target-file timestamp(s) for Plaso-style timeline import.`);
      return { text: textValue(records.join("\n")) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});