import type { Artifact, ArtifactStore, StoreChange } from "../artifact/store";
import { BlobSource, MissingSource, toBlob } from "../bytes/sources";
import { rememberSha256, sha256Source } from "../hash/sha256";
import { fromRecord, insertable, loadValue, storeValue, toRecord, type BlobStore, type MetaStore } from "./records";

export interface PersistenceStatus {
  /** Writes queued or in progress. */
  pending: number;
  error: string | null;
}

export interface RestoreSummary {
  artifacts: number;
  /** Records skipped because a parent or producing run was missing. */
  orphans: number;
  missingFiles: number;
}

/** Mirrors an ArtifactStore into persistent storage and restores it on start-up. */
export class WorkspacePersistence {
  private readonly store: ArtifactStore;
  private readonly meta: MetaStore;
  private readonly blobs: BlobStore;
  private queue: Promise<unknown> = Promise.resolve();
  private seq = 0;
  private unsubscribe: (() => void) | null = null;
  private suspended = false;
  private status: PersistenceStatus = { pending: 0, error: null };
  private readonly listeners = new Set<() => void>();

  constructor(store: ArtifactStore, meta: MetaStore, blobs: BlobStore) {
    this.store = store;
    this.meta = meta;
    this.blobs = blobs;
  }

  get active(): boolean {
    return this.unsubscribe !== null;
  }

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  readonly getStatus = (): PersistenceStatus => this.status;

  /** Loads the saved workspace into the store and keeps saving from then on. */
  async restore(): Promise<RestoreSummary> {
    this.listen();
    const snapshot = await this.meta.load();
    const files = new Map<string, Blob>();
    for (const record of snapshot.artifacts) {
      if (record.value.type !== "bytes" || files.has(record.value.hash)) continue;
      const file = await this.blobs.get(record.value.hash);
      if (file) files.set(record.value.hash, file);
    }
    const runIds = new Set(snapshot.runs.map((run) => run.id));
    const { ready, orphans } = insertable(
      snapshot.artifacts,
      (id) => this.store.get(id) !== undefined,
      (id) => runIds.has(id) || this.store.hasRun(id),
    );
    let missingFiles = 0;
    this.seq = snapshot.artifacts.reduce((max, record) => Math.max(max, record.seq + 1), this.seq);
    // Restored data is already saved; only changes made after this point are written.
    this.suspended = true;
    try {
      this.store.batch(() => {
        for (const run of snapshot.runs) if (!this.store.hasRun(run.id)) this.store.recordRun(run);
        for (const recipe of snapshot.recipes) if (!this.store.getRecipe(recipe.id)) this.store.saveRecipe(recipe);
        for (const pipeline of snapshot.pipelines) if (!this.store.getPipeline(pipeline.id)) this.store.savePipeline(pipeline);
        for (const record of ready) {
          if (this.store.get(record.id)) continue;
          const value = loadValue(record.value, (hash, size) => {
            const file = files.get(hash);
            if (!file) missingFiles++;
            const source = file ? new BlobSource(file) : new MissingSource(size);
            rememberSha256(source, hash);
            return source;
          });
          this.store.insert(fromRecord(record, value));
        }
      });
    } finally {
      this.suspended = false;
    }
    return { artifacts: ready.length, orphans: orphans.length, missingFiles };
  }

  /** Starts saving: writes everything already in the store, then every change. */
  async enable(): Promise<void> {
    if (this.unsubscribe) return;
    this.listen();
    for (const run of this.store.listRuns()) this.enqueue(() => this.meta.putRun(run));
    for (const recipe of this.store.listRecipes()) this.enqueue(() => this.meta.putRecipe(recipe));
    for (const pipeline of this.store.listPipelines()) this.enqueue(() => this.meta.putPipeline(pipeline));
    for (const artifact of this.store.list()) this.enqueue(() => this.saveArtifact(artifact));
    await this.flush();
  }

  /** Stops saving and deletes the saved copy. The open session is kept in memory. */
  async disable(): Promise<void> {
    this.unsubscribe?.();
    this.unsubscribe = null;
    await this.enqueue(() => this.wipe());
  }

  /** Deletes stored files that no saved artifact refers to. */
  collectGarbage(): Promise<{ files: number; bytes: number }> {
    return this.enqueue(async () => {
      const { artifacts } = await this.meta.load();
      const referenced = new Set(artifacts.flatMap((record) => (record.value.type === "bytes" ? [record.value.hash] : [])));
      let files = 0;
      let bytes = 0;
      for (const hash of await this.blobs.list()) {
        if (referenced.has(hash)) continue;
        bytes += (await this.blobs.get(hash))?.size ?? 0;
        await this.blobs.delete(hash);
        files++;
      }
      return { files, bytes };
    });
  }

  /** Resolves once every queued write has finished. */
  async flush(): Promise<void> {
    await this.queue.catch(() => undefined);
  }

  private listen(): void {
    this.unsubscribe ??= this.store.onChange((change) => {
      if (!this.suspended) void this.enqueue(() => this.apply(change)).catch(() => undefined);
    });
  }

  private enqueue<T>(task: () => Promise<T>): Promise<T> {
    this.setStatus({ pending: this.status.pending + 1 });
    const result = this.queue.catch(() => undefined).then(task);
    this.queue = result;
    result.then(
      () => this.setStatus({ pending: this.status.pending - 1 }),
      (error: unknown) =>
        this.setStatus({
          pending: this.status.pending - 1,
          error: `Saving failed: ${error instanceof Error ? error.message : String(error)}`,
        }),
    );
    return result;
  }

  private setStatus(update: Partial<PersistenceStatus>): void {
    this.status = { ...this.status, ...update };
    for (const listener of this.listeners) listener();
  }

  private async apply(change: StoreChange): Promise<void> {
    switch (change.kind) {
      case "artifact":
        return this.saveArtifact(change.artifact);
      case "run":
        return this.meta.putRun(change.run);
      case "recipe":
        return this.meta.putRecipe(change.recipe);
      case "pipeline":
        return this.meta.putPipeline(change.pipeline);
      case "artifact-removed":
        return this.meta.deleteArtifact(change.id);
      case "recipe-removed":
        return this.meta.deleteRecipe(change.id);
      case "pipeline-removed":
        return this.meta.deletePipeline(change.id);
      case "cleared":
        return this.wipe();
    }
  }

  private async saveArtifact(artifact: Artifact): Promise<void> {
    const value = await storeValue(artifact.value, async (source) => {
      const hash = await sha256Source(source);
      if (!(source instanceof MissingSource) && !(await this.blobs.has(hash))) {
        await this.blobs.put(hash, await toBlob(source));
      }
      return hash;
    });
    await this.meta.putArtifact(toRecord(artifact, value, this.seq++));
  }

  private async wipe(): Promise<void> {
    await this.meta.clear();
    for (const hash of await this.blobs.list()) await this.blobs.delete(hash);
  }
}
