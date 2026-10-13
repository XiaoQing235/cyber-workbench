import type { OperationRun } from "../operation/run";
import type { Pipeline } from "../pipeline/pipeline";
import type { Recipe } from "../recipe/recipe";
import type { ArtifactRecord, MetaStore, WorkspaceSnapshot } from "./records";

const DB_NAME = "ctf-workbench";
const STORES = ["artifacts", "runs", "recipes", "pipelines"] as const;
type StoreName = (typeof STORES)[number];

/** Schema migrations by index: entry `n` upgrades version `n` to `n + 1`. Never edit a shipped entry. */
const MIGRATIONS: readonly ((db: IDBDatabase, transaction: IDBTransaction) => void)[] = [
  (db) => {
    for (const name of ["artifacts", "runs", "recipes"]) db.createObjectStore(name, { keyPath: "id" });
  },
  (db) => {
    db.createObjectStore("pipelines", { keyPath: "id" });
  },
];

export const SCHEMA_VERSION = MIGRATIONS.length;

function settle<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

function completion(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB transaction failed"));
    transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
  });
}

export class IdbMetaStore implements MetaStore {
  private readonly db: IDBDatabase;

  private constructor(db: IDBDatabase) {
    this.db = db;
    // Let a newer version of the app in another tab upgrade the schema.
    db.onversionchange = () => db.close();
  }

  static open(factory: IDBFactory = indexedDB, name = DB_NAME): Promise<IdbMetaStore> {
    return new Promise((resolve, reject) => {
      const request = factory.open(name, SCHEMA_VERSION);
      request.onupgradeneeded = (event) => {
        const transaction = request.transaction;
        if (!transaction) return;
        for (let version = event.oldVersion; version < SCHEMA_VERSION; version++) {
          MIGRATIONS[version](request.result, transaction);
        }
      };
      request.onsuccess = () => resolve(new IdbMetaStore(request.result));
      request.onerror = () => reject(request.error ?? new Error("Could not open the workspace database"));
      request.onblocked = () => reject(new Error("The workspace database is held open by another tab; close it and retry"));
    });
  }

  async load(): Promise<WorkspaceSnapshot> {
    const transaction = this.db.transaction([...STORES], "readonly");
    const [artifacts, runs, recipes, pipelines] = await Promise.all([
      settle(transaction.objectStore("artifacts").getAll() as IDBRequest<ArtifactRecord[]>),
      settle(transaction.objectStore("runs").getAll() as IDBRequest<OperationRun[]>),
      settle(transaction.objectStore("recipes").getAll() as IDBRequest<Recipe[]>),
      settle(transaction.objectStore("pipelines").getAll() as IDBRequest<Pipeline[]>),
    ]);
    return { artifacts: artifacts.sort((a, b) => a.seq - b.seq), runs, recipes, pipelines };
  }

  putArtifact(record: ArtifactRecord): Promise<void> {
    return this.write("artifacts", (store) => store.put(record));
  }

  putRun(run: OperationRun): Promise<void> {
    return this.write("runs", (store) => store.put(run));
  }

  putRecipe(recipe: Recipe): Promise<void> {
    return this.write("recipes", (store) => store.put(recipe));
  }

  putPipeline(pipeline: Pipeline): Promise<void> {
    return this.write("pipelines", (store) => store.put(pipeline));
  }

  deletePipeline(id: string): Promise<void> {
    return this.write("pipelines", (store) => store.delete(id));
  }

  deleteArtifact(id: string): Promise<void> {
    return this.write("artifacts", (store) => store.delete(id));
  }

  deleteRecipe(id: string): Promise<void> {
    return this.write("recipes", (store) => store.delete(id));
  }

  async clear(): Promise<void> {
    const transaction = this.db.transaction([...STORES], "readwrite");
    for (const name of STORES) transaction.objectStore(name).clear();
    await completion(transaction);
  }

  close(): void {
    this.db.close();
  }

  private async write(name: StoreName, action: (store: IDBObjectStore) => void): Promise<void> {
    const transaction = this.db.transaction(name, "readwrite");
    action(transaction.objectStore(name));
    await completion(transaction);
  }
}
