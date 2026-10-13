import { BlobSource, toBlob } from "../core/bytes/sources";
import type { Value } from "../core/value";

/** Structured-clone-safe form of a Value. Bytes travel as Blobs, which stay lazy for files. */
export type WireValue =
  | { type: "bytes"; blob: Blob }
  | { type: "text"; text: string }
  | { type: "number"; value: number | bigint }
  | { type: "structured"; data: unknown };

export async function toWire(value: Value): Promise<WireValue> {
  switch (value.type) {
    case "bytes":
      return { type: "bytes", blob: await toBlob(value.source) };
    case "text":
      return { type: "text", text: value.text };
    case "number":
      return { type: "number", value: value.value };
    case "structured":
      return { type: "structured", data: value.data };
  }
}

export function fromWire(wire: WireValue): Value {
  switch (wire.type) {
    case "bytes":
      return { type: "bytes", source: new BlobSource(wire.blob) };
    case "text":
      return { type: "text", text: wire.text };
    case "number":
      return { type: "number", value: wire.value };
    case "structured":
      return { type: "structured", data: wire.data };
  }
}

export async function toWireRecord(values: Readonly<Record<string, Value>>): Promise<Record<string, WireValue>> {
  const entries = await Promise.all(
    Object.entries(values).map(async ([name, value]) => [name, await toWire(value)] as const),
  );
  return Object.fromEntries(entries);
}

export function fromWireRecord(wires: Readonly<Record<string, WireValue>>): Record<string, Value> {
  return Object.fromEntries(Object.entries(wires).map(([name, wire]) => [name, fromWire(wire)]));
}
