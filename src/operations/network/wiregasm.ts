import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { isCapture } from "../../formats/pcap/capture";
import { importPack } from "../../runtimes/files";
import { bytesInput, MiB } from "../util";

export const pcapDeepInspect = defineOperation<{ filter: string; maxFrames: number }>({
  spec: {
    id: "pcap.deep-inspect", version: "1.0.0", title: "Dissect capture with Wiregasm", category: "Network",
    description: "Run Wireshark's WASM dissectors on a bounded pcap/pcapng capture and show filtered packets with depth-limited protocol trees. Loads the optional Wiregasm pack only on demand.",
    keywords: ["wiregasm", "wireshark", "pcap", "pcapng", "dissect", "filter", "protocol"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object", properties: {
        filter: { type: "string", title: "Wireshark display filter", maxLength: 128, default: "" },
        maxFrames: { type: "integer", title: "Maximum displayed packets", minimum: 1, maximum: 16, default: 5 },
      }, required: ["filter", "maxFrames"], additionalProperties: false,
    },
    runtime: "wasm", deterministic: true, streaming: false, sideEffects: "none", cost: "high",
    limits: { maxInputBytes: 8 * MiB },
  },
  async run(ctx, inputs, params) {
    const input = await readAll(bytesInput(inputs), 8 * MiB);
    if (!isCapture(input)) throw new OperationError("INVALID_INPUT", "Expected a pcap or pcapng capture");
    ctx.throwIfAborted();
    const { runDeepPcap } = await importPack("Wiregasm", () => import("../../runtimes/wiregasm"));
    const report = await runDeepPcap(input, params.filter, params.maxFrames, ctx.signal);
    ctx.diagnostic(`Wiregasm matched ${report.matched} of ${report.summary.packet_count} packet(s); showing ${report.frames.length} protocol tree(s).`);
    return { report: structuredValue(report) };
  },
});