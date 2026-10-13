import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { sigrokSessionToVcd } from "../../formats/sigrokSession";
import { bytesInput, MiB } from "../util";

export const sigrokSessionImport = defineOperation<Record<string, never>>({
  spec: {
    id: "hardware.sigrok.session-import", version: "1.1.0", title: "Import sigrok session", category: "Hardware",
    description: "Convert one-device, 1-byte-per-sample native sigrok .sr digital sessions to VCD. Requires integral nanosecond sample period and stored or ZIP-deflated logic-1; analog, multi-device and other compression are unsupported.",
    keywords: ["sigrok", "pulseview", "session", "sr", "digital", "vcd"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 8 * MiB },
  },
  async run(ctx, inputs) {
    try {
      const { vcd, report } = await sigrokSessionToVcd(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Converted ${report.samples} sigrok logic sample(s) across ${report.probes} probe(s).`);
      return { data: bytesFrom(vcd), report: structuredValue(report) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
