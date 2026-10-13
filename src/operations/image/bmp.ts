import { ConcatSource, MemorySource, SliceSource } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesValue, structuredValue } from "../../core/value";
import { parseBmp } from "../../formats/bmp/bmp";
import { bytesInput } from "../util";

export const bmpInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "bmp.inspect",
    version: "1.0.0",
    title: "Inspect BMP",
    category: "Image",
    description: "Read the BMP headers and compare the pixel data with the declared dimensions (a reduced height shows up here).",
    keywords: ["bmp", "bitmap", "height", "header", "structure"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "low",
  },
  async run(_ctx, inputs) {
    const structure = await parseBmp(bytesInput(inputs));
    return { report: structuredValue({ header: structure.header, rowStride: structure.rowStride, findings: structure.findings }) };
  },
});

export const bmpSetDimensions = defineOperation<{ width: number; height: number }>({
  spec: {
    id: "bmp.set-dimensions",
    version: "1.0.0",
    title: "Set BMP dimensions",
    category: "Image",
    description: "Write a new width and/or height into the BMP header, keeping the row order. The original file is not changed.",
    keywords: ["bmp", "height", "width", "repair", "fix"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: {
        width: { type: "integer", title: "Width (-1 = keep)", minimum: -1, maximum: 0x7fffffff, default: -1 },
        height: { type: "integer", title: "Height (-1 = keep)", minimum: -1, maximum: 0x7fffffff, default: -1 },
      },
      required: ["width", "height"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "low",
  },
  async run(_ctx, inputs, params) {
    if (params.width === 0 || params.height === 0) throw new OperationError("INVALID_PARAMS", "Dimensions must be at least 1");
    const source = bytesInput(inputs);
    const { header } = await parseBmp(source);
    if (!header) throw new OperationError("INVALID_INPUT", "Not a supported BMP file");
    const size = header.dimensionFieldSize;
    const limit = size === 2 ? 0xffff : 0x7fffffff;
    if (params.width > limit || params.height > limit) {
      throw new OperationError("INVALID_PARAMS", `This BMP header stores dimensions in ${size * 8} bits`);
    }
    const fields = await source.read(header.widthFieldOffset, size * 2);
    const view = new DataView(fields.buffer);
    const write = (at: number, value: number) => (size === 2 ? view.setUint16(at, value, true) : view.setInt32(at, value, true));
    if (params.width !== -1) write(0, params.width);
    if (params.height !== -1) write(size, header.topDown ? -params.height : params.height);
    const end = header.widthFieldOffset + fields.length;
    return {
      data: bytesValue(
        new ConcatSource([
          new SliceSource(source, 0, header.widthFieldOffset),
          new MemorySource(fields),
          new SliceSource(source, end, source.size - end),
        ]),
      ),
    };
  },
});
