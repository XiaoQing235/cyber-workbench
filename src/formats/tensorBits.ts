import type { ByteSource } from "../core/bytes/ByteSource";
import { extractSafeTensor, inspectSafeTensors } from "./safeTensors";

export const MAX_TENSOR_SAMPLES = 8 * 1024 * 1024;
export const MAX_TENSOR_OUTPUT_BYTES = 1024 * 1024;

/** Extract one bit per stored element (including float representation bits); bitOrder controls output packing. */
export async function extractTensorBits(source: ByteSource, name: string, bit: number,
  bitOrder: "msb" | "lsb", maxBytes: number, signal?: AbortSignal): Promise<{ data: Uint8Array; samples: number }> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_TENSOR_OUTPUT_BYTES ||
    !Number.isSafeInteger(bit) || bit < 0 || bit > 63 || !["msb", "lsb"].includes(bitOrder)) {
    throw new Error("Tensor bit index, ordering or output budget is invalid");
  }
  const report = await inspectSafeTensors(source, signal);
  const tensor = report.tensors.find((item) => item.name === name);
  if (!tensor) throw new Error("SafeTensors tensor is not present");
  const width = ({ BOOL: 1, U8: 1, I8: 1, U16: 2, I16: 2, F16: 2, BF16: 2, U32: 4, I32: 4, F32: 4, U64: 8, I64: 8, F64: 8,
    F8_E4M3FN: 1, F8_E5M2: 1 } as Record<string, number>)[tensor.dtype];
  if (!width) throw new Error("Tensor dtype has no supported storage width");
  if (bit >= width * 8 || (tensor.dtype === "BOOL" && bit !== 0)) throw new Error("Tensor bit index exceeds the dtype width");
  const count = Number(tensor.elements);
  if (!Number.isSafeInteger(count) || count > MAX_TENSOR_SAMPLES || Math.ceil(count / 8) > maxBytes) {
    throw new Error("Tensor samples or extracted bytes exceed the configured budget");
  }
  const data = new Uint8Array(Math.ceil(count / 8));
  const selected = await extractSafeTensor(source, name, signal);
  const chunkElements = Math.max(1, Math.floor(65_536 / width));
  for (let start = 0; start < count; start += chunkElements) {
    if (signal?.aborted) throw signal.reason;
    const length = Math.min(chunkElements, count - start);
    const bytes = await selected.read(start * width, length * width);
    if (bytes.length !== length * width) throw new Error("Tensor sample data is truncated");
    for (let index = 0; index < length; index++) {
      const sample = start + index;
      const value = (bytes[index * width + Math.floor(bit / 8)] >> (bit % 8)) & 1;
      data[sample >> 3] |= value << (bitOrder === "msb" ? 7 - (sample & 7) : sample & 7);
    }
  }
  return { data, samples: count };
}
