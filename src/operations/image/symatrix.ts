import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { decodeSymatrix } from "../../formats/symatrix";
import { bytesInput, MiB } from "../util";

export const symatrixDecode = defineOperation<Record<string, never>>({
  spec: {
    id: "image.symatrix.decode", version: "1.0.0", title: "Decode mirrored Symatrix pixels", category: "Image",
    description: "Read the Google CTF Symatrix mirrored-pixel blue-channel bitstream from a CRC-checked PNG. The decoded text is a candidate; matching a flag requires independent verification.",
    keywords: ["symatrix", "steganography", "mirror", "pixels", "blue", "png"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 4 * MiB },
  },
  async run(ctx, inputs) {
    try {
      const report = await decodeSymatrix(bytesInput(inputs), ctx.signal);
      ctx.diagnostic(`Decoded ${report.bits} mirrored-pixel bit(s); compare the candidate to an independent challenge reference.`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});
