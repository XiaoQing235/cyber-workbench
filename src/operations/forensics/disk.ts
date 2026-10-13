import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { inspectDiskPartitions } from "../../formats/diskPartitions";
import { bytesInput } from "../util";

export const diskPartitionsInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "forensics.disk.partitions", version: "1.0.0", title: "Inspect disk partitions", category: "Forensics",
    description: "Inspect an MBR or 512-byte-sector primary GPT from bounded disk-image reads. GPT header and entry CRCs are checked; backup GPT and filesystems are not inspected.",
    keywords: ["disk", "image", "partition", "mbr", "gpt", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs) {
    try {
      const report = await inspectDiskPartitions(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Found ${report.partitions.length} ${report.scheme} partition(s).${report.scheme === "GPT" ? " Only the primary GPT was validated; backup GPT was not read." : ""}`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});