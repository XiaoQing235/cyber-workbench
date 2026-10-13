import type { Artifact } from "../artifact/store";
import type { ByteSource } from "../bytes/ByteSource";
import type { OperationRun } from "../operation/run";
import type { Pipeline } from "../pipeline/pipeline";
import type { Recipe } from "../recipe/recipe";
import { bytesValue, numberValue, structuredValue, textValue, type Value } from "../value";

export type StoredValue =
  | { type: "bytes"; hash: string; size: number }
  | { type: "text"; text: string }
  | { type: "number"; value: number | bigint }
  | { type: "structured"; data: unknown };

export interface ArtifactRecord {
  id: string;
  name: string;
  createdAt: string;
  producedBy?: string;
  parents: string[];
  value: StoredValue;
  /** Insertion order: parents always sort before their children. */
  seq: number;
}

export interface WorkspaceSnapshot {
  artifacts: ArtifactRecord[];
  runs: OperationRun[];
  recipes: Recipe[];
  pipelines: Pipeline[];
}

/** Workspace metadata (IndexedDB in the browser). */
export interface MetaStore {
  load(): Promise<WorkspaceSnapshot>;
  putArtifact(record: ArtifactRecord): Promise<void>;
  putRun(run: OperationRun): Promise<void>;
  putRecipe(recipe: Recipe): Promise<void>;
  putPipeline(pipeline: Pipeline): Promise<void>;
  deleteArtifact(id: string): Promise<void>;
  deleteRecipe(id: string): Promise<void>;
  deletePipeline(id: string): Promise<void>;
  clear(): Promise<void>;
}

/** Content-addressed file storage keyed by SHA-256 (OPFS in the browser). */
export interface BlobStore {
  has(hash: string): Promise<boolean>;
  put(hash: string, data: Blob): Promise<void>;
  get(hash: string): Promise<Blob | undefined>;
  delete(hash: string): Promise<void>;
  list(): Promise<string[]>;
}

export const SHA256_HEX = /^[0-9a-f]{64}$/;

export async function storeValue(value: Value, hashOf: (source: ByteSource) => Promise<string>): Promise<StoredValue> {
  switch (value.type) {
    case "bytes":
      return { type: "bytes", hash: await hashOf(value.source), size: value.source.size };
    case "text":
      return { type: "text", text: value.text };
    case "number":
      return { type: "number", value: value.value };
    case "structured":
      return { type: "structured", data: value.data };
  }
}

export function loadValue(stored: StoredValue, sourceFor: (hash: string, size: number) => ByteSource): Value {
  switch (stored.type) {
    case "bytes":
      return bytesValue(sourceFor(stored.hash, stored.size));
    case "text":
      return textValue(stored.text);
    case "number":
      return numberValue(stored.value);
    case "structured":
      return structuredValue(stored.data);
  }
}

export function toRecord(artifact: Artifact, value: StoredValue, seq: number): ArtifactRecord {
  return {
    id: artifact.id,
    name: artifact.name,
    createdAt: artifact.createdAt,
    parents: [...artifact.parents],
    value,
    seq,
    ...(artifact.producedBy !== undefined ? { producedBy: artifact.producedBy } : {}),
  };
}

export function fromRecord(record: ArtifactRecord, value: Value): Artifact {
  return {
    id: record.id,
    name: record.name,
    createdAt: record.createdAt,
    parents: [...record.parents],
    value,
    ...(record.producedBy !== undefined ? { producedBy: record.producedBy } : {}),
  };
}

/**
 * Records whose parents and producing run are all known, in insertion order, so they can be
 * inserted one by one. Anything else is reported instead of failing the whole load.
 */
export function insertable(
  records: readonly ArtifactRecord[],
  knownArtifacts: (id: string) => boolean,
  knownRuns: (id: string) => boolean,
): { ready: ArtifactRecord[]; orphans: ArtifactRecord[] } {
  const ready: ArtifactRecord[] = [];
  const orphans: ArtifactRecord[] = [];
  const accepted = new Set<string>();
  for (const record of [...records].sort((a, b) => a.seq - b.seq)) {
    const parentsKnown = record.parents.every((parent) => accepted.has(parent) || knownArtifacts(parent));
    const runKnown = record.producedBy === undefined || knownRuns(record.producedBy);
    if (parentsKnown && runKnown) {
      ready.push(record);
      accepted.add(record.id);
    } else {
      orphans.push(record);
    }
  }
  return { ready, orphans };
}

const TAG = "$ctf";

/** JSON that keeps BigInt and Uint8Array values, which plain JSON cannot represent. */
export function encodeJson(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) => {
    if (typeof item === "bigint") return { [TAG]: "bigint", value: item.toString() };
    if (item instanceof Uint8Array) return { [TAG]: "bytes", hex: Array.from(item, (b) => b.toString(16).padStart(2, "0")).join("") };
    return item;
  });
}

export function decodeJson(text: string): unknown {
  return JSON.parse(text, (_key, item: unknown) => {
    if (typeof item !== "object" || item === null || !(TAG in item)) return item;
    const tagged = item as { [TAG]: unknown; value?: unknown; hex?: unknown };
    if (tagged[TAG] === "bigint" && typeof tagged.value === "string") return BigInt(tagged.value);
    if (tagged[TAG] === "bytes" && typeof tagged.hex === "string") {
      return Uint8Array.from(tagged.hex.match(/../g) ?? [], (pair) => parseInt(pair, 16));
    }
    return item;
  });
}
