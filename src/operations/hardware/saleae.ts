import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { saleaeDigitalCsvToVcd, sigrokDigitalCsvToVcd } from "../../formats/saleaeCsv";
import { bytesInput, MiB } from "../util";

export const saleaeDigitalImport = defineOperation<Record<string, never>>({
  spec: {
    id: "hardware.saleae.digital-import", version: "1.0.0", title: "Import Saleae digital CSV", category: "Hardware",
    description: "Convert bounded Saleae Logic 2 digital transition CSV to VCD at 1 ns resolution. Explicit X gaps remain unknown; analog and analyzer exports are not accepted.",
    keywords: ["saleae", "logic", "csv", "digital", "vcd", "waveform"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 2 * MiB },
  },
  async run(ctx, inputs) {
    try {
      const result = await saleaeDigitalCsvToVcd(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Converted ${result.report.rows} Saleae row(s) across ${result.report.channels.length} digital channel(s), retaining unknown intervals.`);
      return { data: bytesFrom(result.vcd), report: structuredValue(result.report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const sigrokDigitalImport = defineOperation<Record<string, never>>({
  spec: {
    id: "hardware.sigrok.digital-import", version: "1.0.0", title: "Import sigrok digital CSV", category: "Hardware",
    description: "Convert a bounded sigrok-cli digital CSV with a seconds time column and 1–16 digital probes into 1 ns VCD. Unknown X states remain unknown; native .sr files and analog exports are unsupported.",
    keywords: ["sigrok", "pulseview", "logic", "csv", "digital", "vcd", "waveform"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 2 * MiB },
  },
  async run(ctx, inputs) {
    try {
      const result = await sigrokDigitalCsvToVcd(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Converted ${result.report.rows} sigrok digital row(s) to VCD without interpreting analog data.`);
      return { data: bytesFrom(result.vcd), report: structuredValue(result.report) };
    } catch (error) { ctx.throwIfAborted(); throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error)); }
  },
});
