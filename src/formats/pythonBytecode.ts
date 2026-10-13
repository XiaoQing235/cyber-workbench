import type { ByteSource } from "../core/bytes/ByteSource";
import { SliceSource } from "../core/bytes/sources";

const KNOWN_MAGIC = new Map([
  ["a70d0d0a", "3.11"],
  ["cb0d0d0a", "3.12"],
  ["f30d0d0a", "3.13"],
]);

export function magicForPythonVersion(version: string): Uint8Array<ArrayBuffer> {
  const known = [...KNOWN_MAGIC].find(([, candidate]) => candidate === version)?.[0];
  if (!known) throw new Error(`No supported .pyc magic for Python ${version}`);
  return Uint8Array.from({ length: 4 }, (_, index) => Number.parseInt(known.slice(index * 2, index * 2 + 2), 16));
}

export interface PythonBytecodeReport {
  pythonVersion: string;
  magic: string;
  invalidation: "timestamp" | "checked-hash" | "unchecked-hash";
  sourceSize: number | null;
  modifiedUtc: string | null;
  sourceHash: string | null;
  marshalOffset: 16;
  marshalBytes: number;
  executed: false;
}

export async function inspectPythonBytecode(source: ByteSource, signal?: AbortSignal): Promise<PythonBytecodeReport> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < 17) throw new Error("Python bytecode header or marshal payload is truncated");
  const header = await source.read(0, 16);
  if (header.length !== 16 || header[2] !== 0x0d || header[3] !== 0x0a) throw new Error("Python bytecode magic is malformed");
  const magic = Array.from(header.subarray(0, 4), (byte) => byte.toString(16).padStart(2, "0")).join("");
  const pythonVersion = KNOWN_MAGIC.get(magic);
  if (!pythonVersion) throw new Error(`Unsupported Python bytecode magic ${magic}`);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  const flags = view.getUint32(4, true);
  if (flags !== 0 && flags !== 1 && flags !== 3) throw new Error("Python bytecode invalidation flags are unsupported");
  const hashBased = (flags & 1) !== 0;
  const timestamp = view.getUint32(8, true);
  return {
    pythonVersion, magic, invalidation: hashBased ? flags === 3 ? "checked-hash" : "unchecked-hash" : "timestamp",
    sourceSize: hashBased ? null : view.getUint32(12, true),
    modifiedUtc: hashBased ? null : new Date(timestamp * 1_000).toISOString(),
    sourceHash: hashBased ? Array.from(header.subarray(8, 16), (byte) => byte.toString(16).padStart(2, "0")).join("") : null,
    marshalOffset: 16, marshalBytes: source.size - 16, executed: false,
  };
}

export async function extractPythonMarshal(source: ByteSource, signal?: AbortSignal): Promise<ByteSource> {
  await inspectPythonBytecode(source, signal);
  return new SliceSource(source, 16, source.size - 16);
}