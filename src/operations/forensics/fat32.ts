import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { extractDeletedFat32Candidate, extractFat32File, inspectFat32 } from "../../formats/fat32";
import { bytesInput } from "../util";

const OFFSET = { type: "integer" as const, title: "Filesystem byte offset", minimum: 0, default: 0 };

export const fat32Inspect = defineOperation<{ partitionOffset: number }>({
  spec: {
    id: "forensics.disk.fat32.inspect", version: "1.0.0", title: "Inspect FAT32 root directory", category: "Forensics",
    description: "Inspect a FAT32 volume at a byte offset. Lists live and deleted root short-name records with local FAT timestamps; time zone, long names, subdirectories, and deleted data are not inferred.",
    keywords: ["disk", "fat32", "root", "directory", "deleted", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: { partitionOffset: OFFSET }, required: ["partitionOffset"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs, params) {
    try {
      const report = await inspectFat32(bytesInput(inputs), params.partitionOffset, ctx.signal);
      ctx.diagnostic(`Found ${report.entries.length} FAT32 root record(s), including ${report.entries.filter((entry) => entry.deleted).length} deleted; timestamps have no known time zone.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const fat32Extract = defineOperation<{ partitionOffset: number; entryIndex: number }>({
  spec: {
    id: "forensics.disk.fat32.extract", version: "1.0.0", title: "Extract FAT32 live file", category: "Forensics",
    description: "Extract a live FAT32 root file by zero-based entry index through a verified cluster chain. Deleted records are metadata-only; the image is read in bounded ranges.",
    keywords: ["disk", "fat32", "file", "extract", "cluster", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object", properties: {
        partitionOffset: OFFSET,
        entryIndex: { type: "integer", title: "Root record index (zero-based)", minimum: 0, maximum: 262_143, default: 0 },
      },
      required: ["partitionOffset", "entryIndex"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
  },
  async run(ctx, inputs, params) {
    try {
      const file = await extractFat32File(bytesInput(inputs), params.entryIndex, params.partitionOffset, ctx.signal);
      ctx.diagnostic(`Extracted ${file.name} (${file.data.size} bytes) from its FAT32 cluster chain.`);
      return { data: bytesValue(file.data) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const fat32DeletedCandidate = defineOperation<{ partitionOffset: number; entryIndex: number }>({
  spec: {
    id: "forensics.disk.fat32.deleted-candidate", version: "1.0.0", title: "Extract deleted FAT32 candidate", category: "Forensics",
    description: "Opt-in contiguous-data guess for a deleted FAT32 root file. Requires every assumed cluster to be unallocated; recovered bytes are unverified and may be stale or overwritten.",
    keywords: ["disk", "fat32", "deleted", "candidate", "recover", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: {
        partitionOffset: OFFSET,
        entryIndex: { type: "integer", title: "Deleted root record index (zero-based)", minimum: 0, maximum: 262_143, default: 0 },
      },
      required: ["partitionOffset", "entryIndex"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
  },
  async run(ctx, inputs, params) {
    try {
      const candidate = await extractDeletedFat32Candidate(bytesInput(inputs), params.entryIndex, params.partitionOffset, ctx.signal);
      ctx.diagnostic(`Candidate ${candidate.report.name}: ${candidate.report.assumedClusters} free contiguous cluster(s). Data and missing first filename character are unverified.`);
      return { data: bytesValue(candidate.data), report: structuredValue(candidate.report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});