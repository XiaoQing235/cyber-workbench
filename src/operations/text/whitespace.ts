import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, structuredValue } from "../../core/value";
import { extractWhitespaceBits, type WhitespaceBitsReport } from "../../formats/whitespaceBits";
import { textInput } from "../util";

export const whitespaceExtract = defineOperation<{ mode: WhitespaceBitsReport["mode"]; bitOrder: WhitespaceBitsReport["bitOrder"]; maxBytes: number }>({
  spec: {
    id: "text.whitespace.extract", version: "1.0.0", title: "Extract whitespace bits", category: "Text",
    description: "Extract candidate bits from line-end spaces/tabs or zero-width spaces/non-joiners. Choose byte packing order; incomplete final bytes are reported, not padded.",
    keywords: ["whitespace", "stego", "snow", "trailing space", "zero width", "bits", "hidden text"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        mode: { type: "string", title: "Whitespace source", enum: ["line-end", "zero-width"], default: "line-end" },
        bitOrder: { type: "string", title: "Pack bits", enum: ["msb-first", "lsb-first"], default: "msb-first" },
        maxBytes: { type: "integer", title: "Maximum output bytes", minimum: 1, maximum: 125_000, default: 64_000 },
      },
      required: ["mode", "bitOrder", "maxBytes"], additionalProperties: false,
    },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
    limits: { maxInputBytes: 4_000_000 },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const text = textInput(inputs);
    if (text.length > 1_000_000 || new TextEncoder().encode(text).length > 4_000_000) throw new OperationError("INPUT_TOO_LARGE", "Whitespace source is limited to 1 million characters and 4 MB of UTF-8");
    try {
      const result = extractWhitespaceBits(text, params.mode, params.bitOrder, params.maxBytes, ctx.signal);
      ctx.diagnostic(`Extracted ${result.report.bits} bit(s) into ${result.report.bytes} full byte(s).${result.report.leftoverBits ? ` ${result.report.leftoverBits} leftover bit(s) were not padded.` : ""}${result.report.truncated ? " Output limit reached." : ""}`);
      return { data: bytesFrom(result.bytes), report: structuredValue(result.report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});