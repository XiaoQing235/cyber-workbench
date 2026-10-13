import type { ArtifactStore } from "../artifact/store";
import { readZip, writeZip, zipEntryData } from "../archive/zip";
import { BlobSource, MissingSource, toBlob } from "../bytes/sources";
import { rememberSha256, sha256Source } from "../hash/sha256";
import type { OperationRun } from "../operation/run";
import type { Pipeline } from "../pipeline/pipeline";
import type { Recipe } from "../recipe/recipe";
import {
  decodeJson,
  encodeJson,
  fromRecord,
  insertable,
  loadValue,
  SHA256_HEX,
  storeValue,
  toRecord,
  type ArtifactRecord,
} from "./records";

export const CTFWORK_VERSION = 2;
const MAX_MANIFEST_BYTES = 256 * 1024 * 1024;
const MAX_FILE_BYTES = 1024 * 1024 * 1024;

export interface CtfworkManifest {
  format: "ctfwork";
  formatVersion: number;
  exportedAt: string;
  app: string;
  includesFiles: boolean;
  artifacts: ArtifactRecord[];
  runs: OperationRun[];
  recipes: Recipe[];
  pipelines: Pipeline[];
}

export interface ImportSummary {
  artifacts: number;
  /** Already present (same id), so left unchanged. */
  skipped: number;
  recipes: number;
  pipelines: number;
  missingFiles: number;
  /** Records dropped because a parent or producing run was missing from the file. */
  orphans: number;
}

export class CtfworkError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CtfworkError";
  }
}

/** Manifest upgrades by index: entry `n` turns format version `n + 1` into `n + 2`. */
const MANIFEST_MIGRATIONS: readonly ((manifest: Record<string, unknown>) => Record<string, unknown>)[] = [
  (manifest) => ({ ...manifest, formatVersion: 2, pipelines: [] }),
];

/** A ZIP holding manifest.json and, optionally, every distinct file under files/<sha256>. */
export async function exportCtfwork(store: ArtifactStore, options: { includeFiles: boolean; app: string }): Promise<Blob> {
  const files = new Map<string, Blob>();
  const artifacts: ArtifactRecord[] = [];
  for (const artifact of store.list()) {
    const value = await storeValue(artifact.value, async (source) => {
      const hash = await sha256Source(source);
      if (options.includeFiles && !(source instanceof MissingSource) && !files.has(hash)) {
        files.set(hash, await toBlob(source));
      }
      return hash;
    });
    artifacts.push(toRecord(artifact, value, artifacts.length));
  }
  const manifest: CtfworkManifest = {
    format: "ctfwork",
    formatVersion: CTFWORK_VERSION,
    exportedAt: new Date().toISOString(),
    app: options.app,
    includesFiles: options.includeFiles,
    artifacts,
    runs: store.listRuns(),
    recipes: store.listRecipes(),
    pipelines: store.listPipelines(),
  };
  return writeZip([
    { name: "manifest.json", data: new Blob([encodeJson(manifest)], { type: "application/json" }) },
    ...[...files].map(([hash, data]) => ({ name: `files/${hash}`, data })),
  ]);
}

/** Adds the archive's contents to the store. Artifacts, runs and recipes whose ids already exist are kept as they are. */
export async function importCtfwork(store: ArtifactStore, archive: Blob): Promise<ImportSummary> {
  const entries = new Map((await readZip(archive)).map((entry) => [entry.name, entry]));
  const manifestEntry = entries.get("manifest.json");
  if (!manifestEntry) throw new CtfworkError("Not a .ctfwork file: manifest.json is missing");
  const manifest = parseManifest(await (await zipEntryData(manifestEntry, MAX_MANIFEST_BYTES)).text());

  const files = new Map<string, Blob>();
  for (const record of manifest.artifacts) {
    if (record.value.type !== "bytes" || files.has(record.value.hash)) continue;
    const entry = entries.get(`files/${record.value.hash}`);
    if (!entry) continue;
    const data = await zipEntryData(entry, MAX_FILE_BYTES);
    const source = new BlobSource(data);
    if (data.size !== record.value.size || (await sha256Source(source)) !== record.value.hash) {
      throw new CtfworkError(`files/${record.value.hash} does not match its recorded size and hash`);
    }
    files.set(record.value.hash, data);
  }

  const runIds = new Set(manifest.runs.map((run) => run.id));
  const { ready, orphans } = insertable(
    manifest.artifacts,
    (id) => store.get(id) !== undefined,
    (id) => runIds.has(id) || store.hasRun(id),
  );
  const summary: ImportSummary = { artifacts: 0, skipped: 0, recipes: 0, pipelines: 0, missingFiles: 0, orphans: orphans.length };
  store.batch(() => {
    for (const run of manifest.runs) if (!store.hasRun(run.id)) store.recordRun(run);
    for (const recipe of manifest.recipes) {
      if (store.getRecipe(recipe.id)) continue;
      store.saveRecipe(recipe);
      summary.recipes++;
    }
    for (const pipeline of manifest.pipelines) {
      if (store.getPipeline(pipeline.id)) continue;
      store.savePipeline(pipeline);
      summary.pipelines++;
    }
    for (const record of ready) {
      if (store.get(record.id)) {
        summary.skipped++;
        continue;
      }
      const value = loadValue(record.value, (hash, size) => {
        const file = files.get(hash);
        if (!file) summary.missingFiles++;
        const source = file ? new BlobSource(file) : new MissingSource(size);
        rememberSha256(source, hash);
        return source;
      });
      store.insert(fromRecord(record, value));
      summary.artifacts++;
    }
  });
  return summary;
}

function fail(path: string, expected: string): never {
  throw new CtfworkError(`Invalid manifest: ${path} must be ${expected}`);
}

const isObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);
const isString = (value: unknown): value is string => typeof value === "string";
const isStringArray = (value: unknown): value is string[] => Array.isArray(value) && value.every(isString);

function field<T>(object: Record<string, unknown>, key: string, path: string, check: (value: unknown) => value is T, expected: string): T {
  const value = object[key];
  if (!check(value)) fail(`${path}.${key}`, expected);
  return value;
}

function list(value: unknown, path: string): Record<string, unknown>[] {
  if (!Array.isArray(value) || !value.every(isObject)) fail(path, "a list of objects");
  return value;
}

function checkValue(value: unknown, path: string): void {
  if (!isObject(value)) fail(path, "an object");
  switch (value.type) {
    case "bytes":
      if (!isString(value.hash) || !SHA256_HEX.test(value.hash)) fail(`${path}.hash`, "a SHA-256 hex string");
      if (!Number.isSafeInteger(value.size) || (value.size as number) < 0) fail(`${path}.size`, "a non-negative integer");
      return;
    case "text":
      field(value, "text", path, isString, "a string");
      return;
    case "number":
      if (typeof value.value !== "number" && typeof value.value !== "bigint") fail(`${path}.value`, "a number");
      return;
    case "structured":
      if (!("data" in value)) fail(`${path}.data`, "present");
      return;
    default:
      fail(`${path}.type`, "bytes, text, number or structured");
  }
}

export function parseManifest(text: string): CtfworkManifest {
  let raw: unknown;
  try {
    raw = decodeJson(text);
  } catch {
    throw new CtfworkError("manifest.json is not valid JSON");
  }
  if (!isObject(raw) || raw.format !== "ctfwork") throw new CtfworkError("Not a .ctfwork manifest");
  const version = raw.formatVersion;
  if (!Number.isSafeInteger(version) || (version as number) < 1) fail("formatVersion", "a positive integer");
  if ((version as number) > CTFWORK_VERSION) {
    throw new CtfworkError(`This file was made by a newer version (format ${version}); this app reads up to ${CTFWORK_VERSION}`);
  }
  let manifest = raw;
  for (let v = version as number; v < CTFWORK_VERSION; v++) manifest = MANIFEST_MIGRATIONS[v - 1](manifest);

  list(manifest.artifacts, "artifacts").forEach((record, index) => {
    const path = `artifacts[${index}]`;
    field(record, "id", path, isString, "a string");
    field(record, "name", path, isString, "a string");
    field(record, "createdAt", path, isString, "a string");
    field(record, "parents", path, isStringArray, "a list of strings");
    if (record.producedBy !== undefined) field(record, "producedBy", path, isString, "a string");
    if (!Number.isSafeInteger(record.seq)) fail(`${path}.seq`, "an integer");
    checkValue(record.value, `${path}.value`);
  });
  list(manifest.runs, "runs").forEach((run, index) => {
    const path = `runs[${index}]`;
    for (const key of ["id", "operationId", "status", "startedAt", "finishedAt"]) field(run, key, path, isString, "a string");
    if (run.operationVersion !== null) field(run, "operationVersion", path, isString, "a string or null");
    field(run, "parameters", path, isObject, "an object");
    field(run, "diagnostics", path, isStringArray, "a list of strings");
    if (typeof run.durationMs !== "number") fail(`${path}.durationMs`, "a number");
  });
  list(manifest.recipes, "recipes").forEach((recipe, index) => {
    const path = `recipes[${index}]`;
    for (const key of ["id", "name", "createdAt"]) field(recipe, key, path, isString, "a string");
    list(recipe.steps, `${path}.steps`).forEach((step, stepIndex) => {
      const stepPath = `${path}.steps[${stepIndex}]`;
      field(step, "operationId", stepPath, isString, "a string");
      if (step.operationVersion !== null) field(step, "operationVersion", stepPath, isString, "a string or null");
      field(step, "params", stepPath, isObject, "an object");
    });
  });
  list(manifest.pipelines, "pipelines").forEach((pipeline, index) => {
    const path = `pipelines[${index}]`;
    for (const key of ["id", "name"]) field(pipeline, key, path, isString, "a string");
    if (!Number.isSafeInteger(pipeline.schemaVersion)) fail(`${path}.schemaVersion`, "an integer");
    list(pipeline.nodes, `${path}.nodes`).forEach((node, nodeIndex) => {
      const nodePath = `${path}.nodes[${nodeIndex}]`;
      field(node, "id", nodePath, isString, "a string");
      if (node.kind === "input") {
        field(node, "label", nodePath, isString, "a string");
      } else if (node.kind === "operation") {
        for (const key of ["operationId", "operationVersion"]) field(node, key, nodePath, isString, "a string");
        field(node, "params", nodePath, isObject, "an object");
      } else {
        fail(`${nodePath}.kind`, "input or operation");
      }
    });
    list(pipeline.edges, `${path}.edges`).forEach((edge, edgeIndex) => {
      for (const key of ["id", "from", "fromPort", "to", "toPort"]) field(edge, key, `${path}.edges[${edgeIndex}]`, isString, "a string");
    });
  });
  return manifest as unknown as CtfworkManifest;
}
