import { Reader } from "protobufjs";
import type { ByteSource } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";
import { SliceSource } from "../core/bytes/sources";

const MAX_ONNX_BYTES = 16 * 1024 * 1024;
const MAX_FIELDS = 100_000;
const MAX_NODES = 1_024;
const MAX_TENSORS = 1_024;
const MAX_IO = 256;
const MAX_TEXT = 512;

interface Budget { fields: number; signal?: AbortSignal }
interface TypeInfo { dataType: number | null; shape: string[] | null }
interface ValueInfo extends TypeInfo { name: string }

export interface OnnxReport {
  irVersion: string;
  producer: string;
  opsets: { domain: string; version: string }[];
  graph: {
    name: string;
    nodes: { name: string; opType: string; domain: string; inputs: string[]; outputs: string[] }[];
    inputs: ValueInfo[];
    outputs: ValueInfo[];
    initializers: { name: string; dataType: number | null; dimensions: string[]; elements: string; rawDataBytes: number; rawDataOffset: number | null; externalData: boolean }[];
  };
  externalTensorDataRead: false;
  modelExecuted: false;
  modelValidated: false;
}

function walk(bytes: Uint8Array, budget: Budget, depth: number, visit: (field: number, wire: number, reader: Reader) => void): void {
  if (depth > 8) throw new Error("ONNX metadata nesting exceeds eight levels");
  const reader = Reader.create(bytes);
  while (reader.pos < reader.len) {
    if ((++budget.fields & 0x3fff) === 0 && budget.signal?.aborted) throw budget.signal.reason;
    if (budget.fields > MAX_FIELDS) throw new Error("ONNX metadata exceeds its protobuf field budget");
    const tag = reader.uint32();
    const field = tag >>> 3;
    const wire = tag & 7;
    if (field === 0 || wire === 3 || wire === 4 || wire > 5) throw new Error("ONNX has an invalid protobuf field or group wire type");
    const start = reader.pos;
    visit(field, wire, reader);
    if (reader.pos === start) reader.skipType(wire);
    if (reader.pos > reader.len) throw new Error("ONNX protobuf field exceeds its declared message extent");
  }
}

function text(reader: Reader): string {
  const bytes = reader.bytes();
  if (bytes.length > MAX_TEXT) throw new Error("ONNX metadata name exceeds 512 bytes");
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

function dimensions(bytes: Uint8Array, budget: Budget, depth: number): string[] {
  const shape: string[] = [];
  walk(bytes, budget, depth, (field, wire, reader) => {
    if (field !== 1 || wire !== 2) return;
    if (shape.length >= 32) throw new Error("ONNX shape exceeds 32 dimensions");
    let value = "?";
    walk(reader.bytes(), budget, depth + 1, (dimensionField, dimensionWire, nested) => {
      if (dimensionField === 1 && dimensionWire === 0) value = nested.int64().toString();
      if (dimensionField === 2 && dimensionWire === 2) value = text(nested);
    });
    shape.push(value);
  });
  return shape;
}

function valueInfo(bytes: Uint8Array, budget: Budget, depth: number): ValueInfo {
  const result: ValueInfo = { name: "", dataType: null, shape: null };
  walk(bytes, budget, depth, (field, wire, reader) => {
    if (field === 1 && wire === 2) result.name = text(reader);
    if (field === 2 && wire === 2) walk(reader.bytes(), budget, depth + 1, (typeField, typeWire, typeReader) => {
      if (typeField === 1 && typeWire === 2) walk(typeReader.bytes(), budget, depth + 2, (tensorField, tensorWire, tensorReader) => {
        if (tensorField === 1 && tensorWire === 0) result.dataType = tensorReader.uint32();
        if (tensorField === 2 && tensorWire === 2) result.shape = dimensions(tensorReader.bytes(), budget, depth + 3);
      });
    });
  });
  if (!result.name) throw new Error("ONNX graph input or output has no name");
  return result;
}

function initializer(bytes: Uint8Array, budget: Budget, depth: number, fileOffset: number): OnnxReport["graph"]["initializers"][number] {
  const result = { name: "", dataType: null as number | null, dimensions: [] as string[], elements: "1", rawDataBytes: 0, rawDataOffset: null as number | null, externalData: false };
  walk(bytes, budget, depth, (field, wire, reader) => {
    if (field === 1 && wire === 0) result.dimensions.push(reader.int64().toString());
    if (field === 1 && wire === 2) {
      const packed = Reader.create(reader.bytes());
      while (packed.pos < packed.len) result.dimensions.push(packed.int64().toString());
    }
    if (result.dimensions.length > 32) throw new Error("ONNX initializer exceeds 32 dimensions");
    if (field === 2 && wire === 0) result.dataType = reader.uint32();
    if (field === 8 && wire === 2) result.name = text(reader);
    if (field === 9 && wire === 2) {
      const raw = reader.bytes();
      result.rawDataBytes = raw.length;
      result.rawDataOffset = raw.byteOffset - bytes.byteOffset + fileOffset;
    }
    if (field === 13 && wire === 2) { result.externalData = true; reader.bytes(); }
  });
  if (!result.name) throw new Error("ONNX initializer has no name");
  const sizes = result.dimensions.map((dimension) => BigInt(dimension));
  if (sizes.some((dimension) => dimension < 0n)) throw new Error("ONNX initializer has a negative dimension");
  result.elements = sizes.reduce((total, dimension) => total * dimension, 1n).toString();
  return result;
}

function graph(bytes: Uint8Array, budget: Budget, depth: number, fileOffset: number): OnnxReport["graph"] {
  const result: OnnxReport["graph"] = { name: "", nodes: [], inputs: [], outputs: [], initializers: [] };
  walk(bytes, budget, depth, (field, wire, reader) => {
    if (field === 2 && wire === 2) result.name = text(reader);
    if (field === 1 && wire === 2) {
      if (result.nodes.length >= MAX_NODES) throw new Error("ONNX graph exceeds its node budget");
      const node = { name: "", opType: "", domain: "", inputs: [] as string[], outputs: [] as string[] };
      walk(reader.bytes(), budget, depth + 1, (nodeField, nodeWire, nested) => {
        if (nodeField === 1 && nodeWire === 2) node.inputs.push(text(nested));
        if (nodeField === 2 && nodeWire === 2) node.outputs.push(text(nested));
        if (nodeField === 3 && nodeWire === 2) node.name = text(nested);
        if (nodeField === 4 && nodeWire === 2) node.opType = text(nested);
        if (nodeField === 7 && nodeWire === 2) node.domain = text(nested);
      });
      if (!node.opType || node.inputs.length > MAX_IO || node.outputs.length > MAX_IO) throw new Error("ONNX node operation or port budget is invalid");
      result.nodes.push(node);
    }
    if (field === 5 && wire === 2) {
      if (result.initializers.length >= MAX_TENSORS) throw new Error("ONNX graph exceeds its initializer budget");
      const packed = reader.bytes();
      result.initializers.push(initializer(packed, budget, depth + 1, fileOffset + packed.byteOffset - bytes.byteOffset));
    }
    if (field === 11 && wire === 2) {
      if (result.inputs.length >= MAX_IO) throw new Error("ONNX graph exceeds its input budget");
      result.inputs.push(valueInfo(reader.bytes(), budget, depth + 1));
    }
    if (field === 12 && wire === 2) {
      if (result.outputs.length >= MAX_IO) throw new Error("ONNX graph exceeds its output budget");
      result.outputs.push(valueInfo(reader.bytes(), budget, depth + 1));
    }
  });
  return result;
}

export async function inspectOnnx(source: ByteSource, signal?: AbortSignal): Promise<OnnxReport> {
  if (!Number.isSafeInteger(source.size) || source.size < 4 || source.size > MAX_ONNX_BYTES) throw new Error("ONNX input is truncated or exceeds the 16 MiB metadata budget");
  if (signal?.aborted) throw signal.reason;
  const bytes = await readAll(source, MAX_ONNX_BYTES);
  const budget: Budget = { fields: 0, signal };
  const result: OnnxReport = { irVersion: "", producer: "", opsets: [], graph: { name: "", nodes: [], inputs: [], outputs: [], initializers: [] },
    externalTensorDataRead: false, modelExecuted: false, modelValidated: false };
  let hasGraph = false;
  walk(bytes, budget, 0, (field, wire, reader) => {
    if (field === 1 && wire === 0) result.irVersion = reader.int64().toString();
    if (field === 2 && wire === 2) result.producer = text(reader);
    if (field === 7 && wire === 2) {
      if (hasGraph) throw new Error("ONNX model graph is duplicated");
      const packed = reader.bytes();
      result.graph = graph(packed, budget, 1, packed.byteOffset - bytes.byteOffset);
      hasGraph = true;
    }
    if (field === 8 && wire === 2) {
      if (result.opsets.length >= 32) throw new Error("ONNX model exceeds its opset budget");
      const opset = { domain: "", version: "" };
      walk(reader.bytes(), budget, 1, (opField, opWire, nested) => {
        if (opField === 1 && opWire === 2) opset.domain = text(nested);
        if (opField === 2 && opWire === 0) opset.version = nested.int64().toString();
      });
      result.opsets.push(opset);
    }
  });
  if (!result.irVersion || !hasGraph) throw new Error("ONNX model is missing its IR version or graph");
  return result;
}

export async function extractOnnxTensor(source: ByteSource, name: string, signal?: AbortSignal): Promise<ByteSource> {
  const report = await inspectOnnx(source, signal);
  const tensor = report.graph.initializers.find((entry) => entry.name === name);
  if (!tensor) throw new Error("ONNX initializer name is not present");
  if (tensor.externalData || tensor.rawDataOffset === null || tensor.rawDataBytes === 0) throw new Error("ONNX initializer has no embedded raw_data; external data is not fetched");
  if (tensor.rawDataBytes > 8 * 1024 * 1024 || tensor.rawDataOffset + tensor.rawDataBytes > source.size) throw new Error("ONNX initializer exceeds the extraction budget or file extent");
  return new SliceSource(source, tensor.rawDataOffset, tensor.rawDataBytes);
}

/** Pack one selected bit from each embedded, fixed-width ONNX tensor element into an output artifact. */
export async function extractOnnxTensorBits(source: ByteSource, name: string, bit: number, maxBytes: number,
  signal?: AbortSignal): Promise<{ data: Uint8Array<ArrayBuffer>; samples: number; dataType: number }> {
  if (!Number.isSafeInteger(bit) || bit < 0 || bit > 63 || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 1024 * 1024) {
    throw new Error("ONNX tensor bit index or output budget is invalid");
  }
  const report = await inspectOnnx(source, signal);
  const tensor = report.graph.initializers.find((entry) => entry.name === name);
  if (!tensor || tensor.externalData || tensor.rawDataOffset === null) throw new Error("ONNX tensor needs embedded raw_data");
  const width = ({ 1: 4, 2: 1, 3: 1, 4: 2, 5: 2, 6: 4, 7: 8, 9: 1, 10: 2, 11: 8, 12: 4, 13: 8, 16: 2 } as Record<number, number>)[tensor.dataType ?? -1];
  if (!width || bit >= width * 8) throw new Error("ONNX tensor dtype or bit index is unsupported");
  const samples = Number(tensor.elements);
  if (!Number.isSafeInteger(samples) || samples > 8 * 1024 * 1024 || samples * width !== tensor.rawDataBytes ||
    Math.ceil(samples / 8) > maxBytes) throw new Error("ONNX tensor shape or output bytes exceed the budget");
  const data = new Uint8Array(Math.ceil(samples / 8));
  const lane = Math.floor(bit / 8);
  for (let start = 0; start < samples; start += Math.max(1, Math.floor(65536 / width))) {
    if (signal?.aborted) throw signal.reason;
    const count = Math.min(Math.floor(65536 / width), samples - start);
    const raw = await source.read(tensor.rawDataOffset + start * width, count * width);
    if (raw.length !== count * width) throw new Error("ONNX tensor raw_data is truncated");
    for (let i = 0; i < count; i++) data[(start + i) >> 3] |= ((raw[i * width + lane] >> (bit % 8)) & 1) << (7 - ((start + i) & 7));
  }
  return { data, samples, dataType: tensor.dataType! };
}
