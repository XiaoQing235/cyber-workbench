import type { ByteSource } from "../core/bytes/ByteSource";
import { SliceSource } from "../core/bytes/sources";

const MAX_HEADER_BYTES = 8 * 1024 * 1024;
const MAX_TENSORS = 10_000;
const MAX_EXTRACT_BYTES = 64 * 1024 * 1024;
const WIDTH: Readonly<Record<string, number>> = {
  BOOL: 1, U8: 1, I8: 1, U16: 2, I16: 2, F16: 2, BF16: 2,
  U32: 4, I32: 4, F32: 4, U64: 8, I64: 8, F64: 8,
  F8_E4M3FN: 1, F8_E5M2: 1,
};

export interface SafeTensorInfo {
  name: string;
  dtype: string;
  shape: number[];
  elements: string;
  bytes: number;
  offset: number;
}

export interface SafeTensorsReport {
  format: "safetensors";
  headerBytes: number;
  dataOffset: number;
  tensorCount: number;
  metadataKeys: string[];
  metadataValuesReturned: false;
  tensors: SafeTensorInfo[];
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`SafeTensors ${label} must be an object`);
  return value as Record<string, unknown>;
}

export async function inspectSafeTensors(source: ByteSource, signal?: AbortSignal): Promise<SafeTensorsReport> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < 10) throw new Error("SafeTensors header is truncated");
  const length = await source.read(0, 8);
  if (length.length !== 8) throw new Error("SafeTensors length field is truncated");
  const headerLength = new DataView(length.buffer, length.byteOffset, length.byteLength).getBigUint64(0, true);
  if (headerLength < 2n || headerLength > BigInt(MAX_HEADER_BYTES) || headerLength > BigInt(source.size - 8)) throw new Error("SafeTensors header exceeds the bounded input extent");
  const headerBytes = Number(headerLength);
  const dataOffset = headerBytes + 8;
  const raw = await source.read(8, headerBytes);
  if (raw.length !== headerBytes) throw new Error("SafeTensors JSON header is truncated");
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw)); }
  catch { throw new Error("SafeTensors JSON header is malformed"); }
  const header = object(parsed, "header");
  const names = Object.keys(header).filter((name) => name !== "__metadata__");
  if (names.length > MAX_TENSORS) throw new Error("SafeTensors exceeds the 10,000-tensor budget");
  const metadata = header.__metadata__ === undefined ? {} : object(header.__metadata__, "metadata");
  if (Object.keys(metadata).length > 1_000 || Object.values(metadata).some((value) => typeof value !== "string")) throw new Error("SafeTensors metadata exceeds the text-only budget");
  const tensors: SafeTensorInfo[] = [];
  const ranges: { start: number; end: number }[] = [];
  for (const name of names) {
    if (signal?.aborted) throw signal.reason;
    if (name.length < 1 || name.length > 512 || /[\0-\x1f\x7f]/.test(name)) throw new Error("SafeTensors tensor name is invalid");
    const tensor = object(header[name], `tensor ${name}`);
    if (typeof tensor.dtype !== "string" || !(tensor.dtype in WIDTH)) throw new Error(`SafeTensors tensor ${name} uses unsupported dtype`);
    if (!Array.isArray(tensor.shape) || tensor.shape.length > 32 || tensor.shape.some((size) => !Number.isSafeInteger(size) || size < 0)) throw new Error(`SafeTensors tensor ${name} has invalid shape`);
    if (!Array.isArray(tensor.data_offsets) || tensor.data_offsets.length !== 2 || tensor.data_offsets.some((offset) => !Number.isSafeInteger(offset) || offset < 0)) throw new Error(`SafeTensors tensor ${name} has invalid offsets`);
    const [start, end] = tensor.data_offsets as number[];
    if (start > end || end > source.size - dataOffset) throw new Error(`SafeTensors tensor ${name} exceeds the file data`);
    const elements = (tensor.shape as number[]).reduce((total: bigint, dimension) => total * BigInt(dimension), 1n);
    if (elements * BigInt(WIDTH[tensor.dtype]) !== BigInt(end - start)) throw new Error(`SafeTensors tensor ${name} byte length disagrees with shape and dtype`);
    tensors.push({ name, dtype: tensor.dtype, shape: [...tensor.shape], elements: elements.toString(), bytes: end - start, offset: start });
    ranges.push({ start, end });
  }
  ranges.sort((first, second) => first.start - second.start);
  let covered = 0;
  for (const range of ranges) {
    if (range.start !== covered) throw new Error("SafeTensors tensor data overlaps or has an unclaimed gap");
    covered = range.end;
  }
  if (covered !== source.size - dataOffset) throw new Error("SafeTensors tensor data has trailing unclaimed bytes");
  return { format: "safetensors", headerBytes, dataOffset, tensorCount: tensors.length,
    metadataKeys: Object.keys(metadata).sort(), metadataValuesReturned: false, tensors };
}

export async function extractSafeTensor(source: ByteSource, name: string, signal?: AbortSignal): Promise<ByteSource> {
  const report = await inspectSafeTensors(source, signal);
  const tensor = report.tensors.find((item) => item.name === name);
  if (!tensor) throw new Error("SafeTensors tensor name is not present");
  if (tensor.bytes > MAX_EXTRACT_BYTES) throw new Error("SafeTensors tensor exceeds the 64 MiB extraction budget");
  return new SliceSource(source, report.dataOffset + tensor.offset, tensor.bytes);
}