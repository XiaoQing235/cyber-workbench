import type { Finding } from "../../core/analysis/finding";
import type { SourceSpan } from "../../core/bytes/span";

/** How a field's bytes can be rewritten in place. */
export type FieldEncoding =
  | { kind: "int"; width: 1 | 2 | 4 | 8; signed: boolean; le: boolean }
  | { kind: "float"; width: 4 | 8; le: boolean }
  | { kind: "bytes" }
  | { kind: "str"; encoding: string; pad: number | null; terminated: boolean };

export interface FieldNode {
  name: string;
  /** e.g. u4be, str, bytes, chunk, chunk[] */
  type: string;
  /** Absolute offset in the parsed artifact; null inside processed (decompressed, XORed) data or for computed values. */
  offset: number | null;
  length: number;
  /** JSON-safe value of primitives (large integers as decimal strings, bytes as hex). */
  value?: string | number | boolean | null;
  display?: string;
  /** Enum label, when the value has one. */
  label?: string;
  children?: FieldNode[];
  /** Arrays: number of elements (children may be capped). */
  count?: number;
  instance?: boolean;
  doc?: string;
  error?: string;
  encoding?: FieldEncoding;
  checksum?: { algorithm: string; computed: number; ok: boolean; range: SourceSpan | null };
}

export interface StructReport {
  kind: "struct";
  title: string;
  /** Parameters that reproduce this parse (for edits and re-parses). */
  params: { format: string; ksy: string };
  /** The schema text, for export. */
  schema: string;
  root: FieldNode;
  parsedBytes: number;
  totalBytes: number;
  error?: { message: string; offset: number | null; path: string };
  truncated: boolean;
  findings: Finding[];
}

export const joinPath = (parent: string, name: string): string =>
  name.startsWith("[") ? `${parent}${name}` : parent ? `${parent}.${name}` : name;

export function isStructReport(data: unknown): data is StructReport {
  return typeof data === "object" && data !== null && (data as { kind?: unknown }).kind === "struct" && "root" in data;
}

/** Path of the deepest field whose bytes contain `offset`. */
export function deepestAt(root: FieldNode, offset: number): string | null {
  let best: string | null = null;
  const visit = (node: FieldNode, path: string) => {
    for (const child of node.children ?? []) {
      const childPath = joinPath(path, child.name);
      if (child.offset !== null && offset >= child.offset && offset < child.offset + Math.max(child.length, 1)) {
        best = childPath;
        visit(child, childPath);
        return;
      }
      if (child.offset === null && child.children) visit(child, childPath);
    }
  };
  visit(root, "");
  return best;
}
