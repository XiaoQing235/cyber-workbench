import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom } from "../../core/value";
import { decodeImage } from "../../formats/decode";
import { ImageDecodeError } from "../../formats/image";
import { LsbError, extractBits, type LsbOptions } from "../../formats/lsb";
import { bytesInput, MiB } from "../util";

type Params = Omit<LsbOptions, "signal">;

export const imageLsb = defineOperation<Params>({
  spec: {
    id: "image.lsb",
    version: "1.0.0",
    title: "Extract LSB / bit plane",
    category: "Image",
    description:
      "Read one bit from the chosen channels of every pixel, in scan order, and pack the bits into bytes (zsteg-style). Works on raw PNG/BMP samples, not Canvas output.",
    keywords: ["lsb", "steganography", "stego", "bit plane", "zsteg", "stegsolve", "png", "bmp"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        channels: { type: "string", title: "Channels, in order (e.g. RGB, BGR, A)", pattern: "^[RGBAYI]{1,6}$", default: "RGB" },
        bit: { type: "integer", title: "Bit (0 = least significant)", minimum: 0, maximum: 15, default: 0 },
        bitOrder: { type: "string", title: "Pack bits", enum: ["msb-first", "lsb-first"], default: "msb-first" },
        scan: { type: "string", title: "Scan", enum: ["rows", "columns"], default: "rows" },
        startFrom: { type: "string", title: "Start from", enum: ["top", "bottom"], default: "top" },
      },
      required: ["channels", "bit", "bitOrder", "scan", "startFrom"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "medium",
    limits: { maxInputBytes: 256 * MiB },
  },
  async run(ctx, inputs, params) {
    try {
      const { image, warnings } = await decodeImage(bytesInput(inputs), { signal: ctx.signal });
      warnings.forEach((warning) => ctx.diagnostic(warning));
      const result = extractBits(image, { ...params, signal: ctx.signal });
      if (result.leftoverBits > 0) ctx.diagnostic(`${result.leftoverBits} trailing bit(s) did not fill a byte and were dropped.`);
      return { data: bytesFrom(result.bytes) };
    } catch (error) {
      if (error instanceof ImageDecodeError || error instanceof LsbError) throw new OperationError("INVALID_INPUT", error.message);
      throw error;
    }
  },
});
