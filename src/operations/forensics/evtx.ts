import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue, textValue } from "../../core/value";
import { extractEvtxBinXml, inspectEvtx, MAX_EVTX_BYTES } from "../../formats/evtx";
import { bytesInput } from "../util";

export const evtxInspect = defineOperation<{ maxChunks: number; maxRecords: number }>({
  spec: {
    id: "forensics.windows.evtx.inspect", version: "1.0.0", title: "Inspect EVTX headers", category: "Forensics",
    description: "Inspect bounded native EVTX file/chunk headers and record IDs/timestamps using range reads. BinXML event payloads are not decoded.",
    keywords: ["evtx", "windows", "event log", "chunk", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      maxChunks: { type: "integer", title: "Maximum chunks to inspect", minimum: 1, maximum: 256, default: 32 },
      maxRecords: { type: "integer", title: "Maximum record headers to inspect", minimum: 1, maximum: 4096, default: 256 },
    }, required: ["maxChunks", "maxRecords"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: MAX_EVTX_BYTES },
  },
  async run(ctx, inputs, params) {
    try { return { report: structuredValue(await inspectEvtx(bytesInput(inputs), params.maxChunks, ctx.signal, params.maxRecords)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const evtxTimelineExport = defineOperation<{ maxChunks: number; maxRecords: number; hostname: string }>({
  spec: {
    id: "forensics.windows.evtx.timeline-export", version: "1.0.0", title: "Export EVTX record timeline", category: "Forensics",
    description: "Export bounded native EVTX record IDs and FILETIME timestamps as Plaso-style JSONL. BinXML payloads, event IDs and channels are not decoded; the host label is user-supplied.",
    keywords: ["evtx", "windows", "event log", "timeline", "plaso"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "text", type: "text" }],
    parametersSchema: { type: "object", properties: {
      maxChunks: { type: "integer", title: "Maximum chunks to inspect", minimum: 1, maximum: 256, default: 32 },
      maxRecords: { type: "integer", title: "Maximum record headers to export", minimum: 1, maximum: 4096, default: 256 },
      hostname: { type: "string", title: "Host identifier (optional)", maxLength: 256, default: "" },
    }, required: ["maxChunks", "maxRecords", "hostname"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: MAX_EVTX_BYTES },
  },
  async run(ctx, inputs, params) {
    try {
      const report = await inspectEvtx(bytesInput(inputs), params.maxChunks, ctx.signal, params.maxRecords);
      const lines = report.chunks.flatMap((chunk) => chunk.records.map((record) => JSON.stringify({
        timestamp: record.utc, parser: "evtx_record_header", hostname: params.hostname,
        filename: "", message: `EVTX record ${record.id} at file offset ${record.offset} (payload not decoded)`,
      })));
      if (!lines.length) throw new Error("No EVTX record headers found within the selected chunk budget");
      ctx.diagnostic(`Exported ${lines.length} EVTX record header timestamp(s); payloads were not decoded.`);
      return { text: textValue(lines.join("\n")) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const evtxBinXmlExtract = defineOperation<{ chunkIndex: number; recordIndex: number }>({
  spec: {
    id: "forensics.windows.evtx.binxml-extract", version: "1.0.0", title: "Extract EVTX BinXML bytes", category: "Forensics",
    description: "Export one selected EVTX record's original BinXML bytes after checking file and chunk bounds, record trailer and chunk checksums. Event fields are not decoded.",
    keywords: ["evtx", "windows", "binxml", "record", "extract"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {
      chunkIndex: { type: "integer", title: "Chunk index (zero-based)", minimum: 0, maximum: 255, default: 0 },
      recordIndex: { type: "integer", title: "Record index within chunk (zero-based)", minimum: 0, maximum: 4095, default: 0 },
    }, required: ["chunkIndex", "recordIndex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium", limits: { maxInputBytes: MAX_EVTX_BYTES },
  },
  async run(ctx, inputs, params) {
    try { return { data: bytesValue(await extractEvtxBinXml(bytesInput(inputs), params.chunkIndex, params.recordIndex, ctx.signal)) }; }
    catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
