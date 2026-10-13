import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { decodePng2 } from "../../formats/png2";
import { bytesInput, MiB } from "../util";

export const png2Decode = defineOperation<Record<string, never>>({
  spec: {
    id: "reverse.png2.decode", version: "1.0.0", title: "Decode PNG2 image", category: "Reverse",
    description: "Reverse Google CTF's custom 8-bit RGB PNG2 row filters and Hilbert pixel order into a CRC-checked PNG. Requires the PNG2-specific IHDR markers; normal PNG decoding is unchanged.",
    keywords: ["png2", "reverse", "hilbert", "custom filter", "image"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "high",
    limits: { maxInputBytes: 8 * MiB },
  },
  async run(ctx, inputs) {
    try {
      const { png, report } = await decodePng2(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Decoded ${report.width}x${report.height} PNG2 pixels after CRC, row-filter and Hilbert reconstruction.`);
      return { data: bytesFrom(png), report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});