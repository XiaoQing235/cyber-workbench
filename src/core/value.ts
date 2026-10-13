import type { ByteSource, Bytes } from "./bytes/ByteSource";
import { MemorySource } from "./bytes/sources";

export type ValueType = "bytes" | "text" | "number" | "structured";

export interface BytesValue {
  readonly type: "bytes";
  readonly source: ByteSource;
}

/** JavaScript string. Any byte↔text conversion is an explicit operation with a named charset. */
export interface TextValue {
  readonly type: "text";
  readonly text: string;
}

export interface NumberValue {
  readonly type: "number";
  readonly value: number | bigint;
}

export interface StructuredValue {
  readonly type: "structured";
  readonly data: unknown;
}

export type Value = BytesValue | TextValue | NumberValue | StructuredValue;

export const bytesValue = (source: ByteSource): BytesValue => ({ type: "bytes", source });
export const bytesFrom = (bytes: Bytes): BytesValue => bytesValue(new MemorySource(bytes));
export const textValue = (text: string): TextValue => ({ type: "text", text });
export const numberValue = (value: number | bigint): NumberValue => ({ type: "number", value });
export const structuredValue = (data: unknown): StructuredValue => ({ type: "structured", data });

export function describeValue(value: Value): string {
  switch (value.type) {
    case "bytes":
      return `bytes · ${formatSize(value.source.size)}`;
    case "text":
      return `text · ${value.text.length.toLocaleString()} chars`;
    case "number":
      return `number · ${value.value.toString()}`;
    case "structured":
      return "structured";
  }
}

export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GiB`;
}
