import { IDBFactory } from "fake-indexeddb";
import { describe, expect, it } from "vitest";
import { createDefaultRegistry } from "../../operations";
import { writeZip } from "../archive/zip";
import { ArtifactStore, type Artifact } from "../artifact/store";
import { MemorySource, MissingSource, readAll } from "../bytes/sources";
import { sha256Source } from "../hash/sha256";
import { executeOperation } from "../operation/execute";
import type { Params } from "../operation/types";
import { lineage, recipeFromLineage } from "../recipe/recipe";
import { linearPipeline, newPipeline } from "../pipeline/pipeline";
import { bytesValue, textValue, type Value } from "../value";
import { CtfworkError, exportCtfwork, importCtfwork } from "./ctfwork";
import { IdbMetaStore } from "./idb";
import { WorkspacePersistence } from "./persistence";
import { encodeJson, type BlobStore } from "./records";

const registry = createDefaultRegistry();
const ascii = (text: string) => new TextEncoder().encode(text);

class MemoryBlobStore implements BlobStore {
  readonly files = new Map<string, Blob>();
  async has(hash: string) {
    return this.files.has(hash);
  }
  async put(hash: string, data: Blob) {
    this.files.set(hash, new Blob([await data.arrayBuffer()]));
  }
  async get(hash: string) {
    return this.files.get(hash);
  }
  async delete(hash: string) {
    this.files.delete(hash);
  }
  async list() {
    return [...this.files.keys()];
  }
}

/** Runs an operation and records it the way the UI does. */
async function derive(store: ArtifactStore, input: Artifact, operationId: string, params: Params = {}): Promise<Artifact> {
  const spec = registry.get(operationId).spec;
  const result = await executeOperation(registry, { operationId, inputs: { [spec.inputs[0].name]: input.value }, params });
  expect(result.run.error).toBeUndefined();
  store.recordRun(result.run);
  const [name, value] = Object.entries(result.outputs)[0];
  return store.add({ name: `${spec.title} → ${name}`, value, producedBy: result.run.id, parents: [input.id] });
}

/** challenge.bin → To Base64 → From Base64 → XOR, plus a recipe from that chain. */
async function sampleWorkspace(store: ArtifactStore) {
  const root = store.add({ name: "challenge.bin", value: bytesValue(new MemorySource(ascii("secret payload"))) });
  const encoded = await derive(store, root, "base64.encode");
  const decoded = await derive(store, encoded, "base64.decode");
  const xored = await derive(store, decoded, "bytes.xor", { key: "2a" });
  const chain = lineage(store, xored.id);
  store.saveRecipe(recipeFromLineage("Round trip and XOR", chain!.steps));
  store.savePipeline(linearPipeline("XOR pipeline", [{ operationId: "bytes.xor", params: { key: "2a" } }], registry, root.id));
  return { root, encoded, decoded, xored };
}

async function fingerprint(value: Value): Promise<string> {
  switch (value.type) {
    case "bytes":
      return `bytes:${await sha256Source(value.source)}`;
    case "text":
      return `text:${value.text}`;
    default:
      return `${value.type}:${encodeJson(value)}`;
  }
}

async function describeStore(store: ArtifactStore) {
  return Promise.all(
    store.list().map(async (artifact) => ({
      id: artifact.id,
      name: artifact.name,
      parents: artifact.parents,
      producedBy: artifact.producedBy,
      content: await fingerprint(artifact.value),
    })),
  );
}

describe("IndexedDB metadata store", () => {
  it("creates the schema once and keeps data across reopening", async () => {
    const factory = new IDBFactory();
    const first = await IdbMetaStore.open(factory, "test");
    await first.putRecipe({ id: "r1", name: "Recipe", createdAt: "now", steps: [] });
    first.close();
    const second = await IdbMetaStore.open(factory, "test");
    expect((await second.load()).recipes.map((recipe) => recipe.id)).toEqual(["r1"]);
    await second.clear();
    expect(await second.load()).toEqual({ artifacts: [], runs: [], recipes: [], pipelines: [] });
  });

  it("upgrades a version 1 database in place, keeping its data", async () => {
    const factory = new IDBFactory();
    await new Promise<void>((resolve, reject) => {
      const request = factory.open("legacy", 1);
      request.onupgradeneeded = () => {
        for (const name of ["artifacts", "runs", "recipes"]) request.result.createObjectStore(name, { keyPath: "id" });
      };
      request.onsuccess = () => {
        const db = request.result;
        const transaction = db.transaction("recipes", "readwrite");
        transaction.objectStore("recipes").put({ id: "old", name: "Old recipe", createdAt: "then", steps: [] });
        transaction.oncomplete = () => (db.close(), resolve());
      };
      request.onerror = () => reject(request.error);
    });
    const upgraded = await IdbMetaStore.open(factory, "legacy");
    await upgraded.putPipeline(newPipeline("After the upgrade"));
    const snapshot = await upgraded.load();
    expect(snapshot.recipes.map((recipe) => recipe.id)).toEqual(["old"]);
    expect(snapshot.pipelines.map((pipeline) => pipeline.name)).toEqual(["After the upgrade"]);
  });
});

describe("workspace persistence", () => {
  it("restores artifacts, runs and recipes byte-identically after a reload", async () => {
    const meta = await IdbMetaStore.open(new IDBFactory());
    const blobs = new MemoryBlobStore();
    const before = new ArtifactStore();
    const saving = new WorkspacePersistence(before, meta, blobs);
    await saving.enable();
    await sampleWorkspace(before);
    await saving.flush();
    expect(saving.getStatus()).toEqual({ pending: 0, error: null });

    const after = new ArtifactStore();
    let notifications = 0;
    after.subscribe(() => notifications++);
    const summary = await new WorkspacePersistence(after, meta, blobs).restore();
    expect(summary).toEqual({ artifacts: 4, orphans: 0, missingFiles: 0 });
    expect(notifications).toBe(1);
    expect(await describeStore(after)).toEqual(await describeStore(before));
    expect(after.listRuns().map((run) => run.id).sort()).toEqual(before.listRuns().map((run) => run.id).sort());
    expect(after.listRecipes()).toEqual(before.listRecipes());
    expect(after.listPipelines()).toEqual(before.listPipelines());
  });

  it("saves what existed before it was enabled, collects unused files and wipes on disable", async () => {
    const meta = await IdbMetaStore.open(new IDBFactory());
    const blobs = new MemoryBlobStore();
    const store = new ArtifactStore();
    const { xored } = await sampleWorkspace(store);
    const persistence = new WorkspacePersistence(store, meta, blobs);
    await persistence.enable();
    expect((await meta.load()).artifacts).toHaveLength(4);
    // The Base64 round trip reproduces the original bytes, so content addressing stores them once.
    expect(blobs.files.size).toBe(2);

    store.remove(xored.id);
    await persistence.flush();
    expect(await persistence.collectGarbage()).toEqual({ files: 1, bytes: 14 });
    expect(() => store.remove(store.list()[0].id)).toThrow(/derived/);

    await persistence.disable();
    expect(await meta.load()).toEqual({ artifacts: [], runs: [], recipes: [], pipelines: [] });
    expect(blobs.files.size).toBe(0);
  });
});

describe(".ctfwork export and import", () => {
  it("reproduces every artifact byte-identically in a fresh workspace", async () => {
    const original = new ArtifactStore();
    await sampleWorkspace(original);
    const archive = await exportCtfwork(original, { includeFiles: true, app: "test" });

    const fresh = new ArtifactStore();
    expect(await importCtfwork(fresh, archive)).toEqual({ artifacts: 4, skipped: 0, recipes: 1, pipelines: 1, missingFiles: 0, orphans: 0 });
    expect(await describeStore(fresh)).toEqual(await describeStore(original));
    expect(fresh.listPipelines()).toEqual(original.listPipelines());
    expect(await importCtfwork(fresh, archive)).toMatchObject({ artifacts: 0, skipped: 4, recipes: 0, pipelines: 0 });
  });

  it("upgrades a format 1 file, which had no pipelines", async () => {
    const original = new ArtifactStore();
    await sampleWorkspace(original);
    const manifest = parseManifestOf(await readManifest(await exportCtfwork(original, { includeFiles: false, app: "test" })));
    const { pipelines: _dropped, ...v1 } = { ...(await manifest), formatVersion: 1 };
    const archive = await writeZip([{ name: "manifest.json", data: new Blob([encodeJson(v1)]) }]);
    const fresh = new ArtifactStore();
    expect(await importCtfwork(fresh, archive)).toMatchObject({ artifacts: 4, recipes: 1, pipelines: 0 });
  });

  it("exports history and recipes without files on request", async () => {
    const original = new ArtifactStore();
    const { encoded } = await sampleWorkspace(original);
    const fresh = new ArtifactStore();
    const summary = await importCtfwork(fresh, await exportCtfwork(original, { includeFiles: false, app: "test" }));
    expect(summary).toMatchObject({ artifacts: 4, missingFiles: 3 });
    const root = fresh.list()[0];
    expect(root.value.type === "bytes" && root.value.source instanceof MissingSource).toBe(true);
    if (root.value.type === "bytes") await expect(readAll(root.value.source)).rejects.toThrow(/without files/);
    expect(fresh.get(encoded.id)?.value).toEqual(textValue("c2VjcmV0IHBheWxvYWQ="));
  });

  it("rejects tampered files, newer formats and malformed manifests", async () => {
    const original = new ArtifactStore();
    await sampleWorkspace(original);
    const manifest = await (await import("./ctfwork")).parseManifest(
      await (await readManifest(await exportCtfwork(original, { includeFiles: false, app: "test" }))).text(),
    );
    const bytesRecord = manifest.artifacts[0];
    if (bytesRecord.value.type !== "bytes") throw new Error("expected bytes");
    const tampered = await writeZip([
      { name: "manifest.json", data: new Blob([encodeJson(manifest)]) },
      { name: `files/${bytesRecord.value.hash}`, data: new Blob([ascii("SECRET payload")]) },
    ]);
    await expect(importCtfwork(new ArtifactStore(), tampered)).rejects.toThrow(/does not match/);

    const newer = await writeZip([{ name: "manifest.json", data: new Blob([encodeJson({ ...manifest, formatVersion: 99 })]) }]);
    await expect(importCtfwork(new ArtifactStore(), newer)).rejects.toThrow(/newer version/);

    const broken = { ...manifest, artifacts: [{ ...manifest.artifacts[0], parents: "nope" }] };
    const malformed = await writeZip([{ name: "manifest.json", data: new Blob([encodeJson(broken)]) }]);
    await expect(importCtfwork(new ArtifactStore(), malformed)).rejects.toThrow(CtfworkError);
    await expect(importCtfwork(new ArtifactStore(), malformed)).rejects.toThrow(/artifacts\[0\]\.parents/);
  });
});

async function readManifest(archive: Blob): Promise<Blob> {
  const { readZip, zipEntryData } = await import("../archive/zip");
  const entry = (await readZip(archive)).find((candidate) => candidate.name === "manifest.json");
  return zipEntryData(entry!, 1 << 20);
}

async function parseManifestOf(manifest: Blob) {
  return (await import("./ctfwork")).parseManifest(await manifest.text());
}

describe("recipes", () => {
  it("records the lineage of an artifact and replays it to identical output", async () => {
    const store = new ArtifactStore();
    const { root, xored } = await sampleWorkspace(store);
    const chain = lineage(store, xored.id)!;
    expect(chain.root.id).toBe(root.id);
    expect(chain.steps.map((step) => step.run.operationId)).toEqual(["base64.encode", "base64.decode", "bytes.xor"]);

    const recipe = store.listRecipes()[0];
    expect(recipe.steps.map((step) => step.operationVersion)).toEqual(["1.0.0", "1.0.0", "1.0.0"]);
    let current = root;
    for (const step of recipe.steps) {
      current = await derive(store, current, step.operationId, step.params);
    }
    expect(await fingerprint(current.value)).toBe(await fingerprint(xored.value));
  });
});
