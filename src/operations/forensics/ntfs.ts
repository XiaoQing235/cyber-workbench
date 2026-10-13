import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue, textValue } from "../../core/value";
import { extractNtfsStream, inspectNtfsRecord, recoverDeletedNtfsNonResident, recoverDeletedNtfsResident } from "../../formats/ntfs";
import { bytesInput } from "../util";

const PARAMETERS = {
  type: "object" as const,
  properties: {
    recordNumber: { type: "integer" as const, title: "MFT record number", minimum: 0, maximum: 100_000, default: 64 },
    partitionOffset: { type: "integer" as const, title: "Filesystem byte offset", minimum: 0, default: 0 },
  },
  required: ["recordNumber", "partitionOffset"], additionalProperties: false as const,
};

export const ntfsRecordInspect = defineOperation<{ recordNumber: number; partitionOffset: number }>({
  spec: {
    id: "forensics.disk.ntfs.record", version: "1.0.0", title: "Inspect NTFS MFT record", category: "Forensics",
    description: "Read a single NTFS MFT record using its run map and sector fixups. Shows UTC MACB times from standard/filename attributes and ADS names/sizes. External attribute lists are not supported.",
    keywords: ["disk", "ntfs", "mft", "macb", "filetime", "ads", "stream", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: PARAMETERS,
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs, params) {
    try {
      const report = await inspectNtfsRecord(bytesInput(inputs), params.recordNumber, params.partitionOffset, ctx.signal);
      ctx.diagnostic(`NTFS MFT record ${report.recordNumber}: ${report.names.length} filename(s), ${report.streams.filter((stream) => stream.name !== null).length} named stream(s); $STANDARD_INFORMATION and $FILE_NAME times are kept separate.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const ntfsMacbTimelineExport = defineOperation<{ recordNumber: number; partitionOffset: number; hostname: string }>({
  spec: {
    id: "forensics.disk.ntfs.timeline-export", version: "1.0.0", title: "Export NTFS MACB timeline", category: "Forensics",
    description: "Export exact UTC MFT creation, modification, change and access times as Plaso-style JSONL. Standard-information and filename timestamps remain separate; host identity is supplied explicitly.",
    keywords: ["ntfs", "mft", "macb", "timeline", "plaso", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      ...PARAMETERS,
      properties: { ...PARAMETERS.properties, hostname: { type: "string", title: "Host identifier (optional)", maxLength: 256, default: "" } },
      required: [...PARAMETERS.required, "hostname"],
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs, params) {
    try {
      const report = await inspectNtfsRecord(bytesInput(inputs), params.recordNumber, params.partitionOffset, ctx.signal);
      const records: string[] = [];
      const append = (source: string, filename: string, values: NonNullable<typeof report.standardTimes>) => {
        for (const [kind, time] of Object.entries(values)) {
          if (!time) continue;
          records.push(JSON.stringify({ timestamp: time.utc, parser: "ntfs_mft", hostname: params.hostname,
            filename, message: `MFT ${report.recordNumber} ${source} ${kind}${report.inUse ? "" : " (deleted record)"}` }));
        }
      };
      if (report.standardTimes) append("$STANDARD_INFORMATION", report.names[0]?.name ?? "", report.standardTimes);
      for (const name of report.names) append(`$FILE_NAME (${name.namespace})`, name.name, name.times);
      if (records.length === 0) throw new Error("NTFS MFT record has no timestamps to export");
      ctx.diagnostic(`Exported ${records.length} UTC NTFS MACB event(s) from MFT record ${report.recordNumber}.`);
      return { text: textValue(records.join("\n")) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const ntfsStreamExtract = defineOperation<{ recordNumber: number; partitionOffset: number; streamName: string }>({
  spec: {
    id: "forensics.disk.ntfs.stream-extract", version: "1.0.0", title: "Extract NTFS data stream", category: "Forensics",
    description: "Extract an unnamed or named NTFS data stream from a live MFT record. Uncompressed non-resident runs are read lazily; compressed, encrypted, sparse and deleted records are rejected.",
    keywords: ["ntfs", "mft", "ads", "alternate", "data", "extract", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      ...PARAMETERS,
      properties: { ...PARAMETERS.properties, streamName: { type: "string", title: "Stream name (blank for default)", maxLength: 255, default: "" } },
      required: [...PARAMETERS.required, "streamName"],
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
  },
  async run(ctx, inputs, params) {
    try {
      const data = await extractNtfsStream(bytesInput(inputs), params.recordNumber, params.streamName, params.partitionOffset, ctx.signal);
      ctx.diagnostic(`Extracted ${data.size} byte(s) from MFT ${params.recordNumber} ${params.streamName ? `:$DATA:${params.streamName}` : "default $DATA"}.`);
      return { data: bytesValue(data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const ntfsDeletedResidentCandidate = defineOperation<{ recordNumber: number; partitionOffset: number; streamName: string }>({
  spec: {
    id: "forensics.disk.ntfs.deleted-resident", version: "1.0.0", title: "Recover deleted NTFS resident candidate", category: "Forensics",
    description: "Extract one resident $DATA stream still present inside a deleted NTFS MFT record. The result is a candidate, not a verified file; non-resident clusters and overwritten records are not recovered.",
    keywords: ["ntfs", "deleted", "resident", "mft", "recover", "candidate", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { ...PARAMETERS, properties: { ...PARAMETERS.properties,
      streamName: { type: "string", title: "Stream name (blank for default)", maxLength: 255, default: "" },
    }, required: [...PARAMETERS.required, "streamName"] },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
  },
  async run(ctx, inputs, params) {
    try {
      const result = await recoverDeletedNtfsResident(bytesInput(inputs), params.recordNumber, params.streamName, params.partitionOffset, ctx.signal);
      ctx.diagnostic(`Recovered ${result.report.bytes} resident byte(s) from deleted MFT ${result.report.recordNumber}; file integrity is not verified.`);
      return { data: bytesValue(result.data), report: structuredValue(result.report) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});

export const ntfsDeletedNonResidentCandidate = defineOperation<{ recordNumber: number; partitionOffset: number; streamName: string }>({
  spec: {
    id: "forensics.disk.ntfs.deleted-nonresident", version: "1.1.0", title: "Recover deleted NTFS cluster candidate", category: "Forensics",
    description: "Read a deleted non-resident MFT record's selected uncompressed $DATA runlist and export a bounded byte candidate. If a supported $Bitmap exists, report present-day free/allocated cluster counts; historical reuse and file integrity remain unverified.",
    keywords: ["ntfs", "deleted", "non-resident", "mft", "runlist", "cluster", "recover", "candidate"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { ...PARAMETERS, properties: { ...PARAMETERS.properties,
      streamName: { type: "string", title: "Stream name (blank for default)", maxLength: 255, default: "" },
    }, required: [...PARAMETERS.required, "streamName"] },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "medium",
  },
  async run(ctx, inputs, params) {
    try {
      const result = await recoverDeletedNtfsNonResident(bytesInput(inputs), params.recordNumber, params.streamName, params.partitionOffset, ctx.signal);
      ctx.diagnostic(`Read ${result.report.bytes} byte(s) from ${result.report.runs} mapped run(s) for deleted MFT ${params.recordNumber}; current bitmap status: ${result.report.currentClusterAllocation.status}; historical reuse and file integrity are unverified.`);
      return { data: bytesValue(result.data), report: structuredValue(result.report) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
