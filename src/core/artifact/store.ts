import type { OperationRun } from "../operation/run";
import type { Pipeline } from "../pipeline/pipeline";
import type { Recipe } from "../recipe/recipe";
import type { Value } from "../value";

export interface Artifact {
  readonly id: string;
  readonly name: string;
  readonly value: Value;
  readonly createdAt: string;
  /** Id of the OperationRun that produced this artifact; absent for user imports. */
  readonly producedBy?: string;
  readonly parents: readonly string[];
}

export interface NewArtifact {
  name: string;
  value: Value;
  producedBy?: string;
  parents?: readonly string[];
}

export type StoreChange =
  | { kind: "artifact"; artifact: Artifact }
  | { kind: "run"; run: OperationRun }
  | { kind: "recipe"; recipe: Recipe }
  | { kind: "pipeline"; pipeline: Pipeline }
  | { kind: "artifact-removed"; id: string }
  | { kind: "recipe-removed"; id: string }
  | { kind: "pipeline-removed"; id: string }
  | { kind: "cleared" };

/**
 * In-memory workspace store. Artifacts are immutable: deriving data always adds a new
 * artifact linked to its parents and to the run that produced it.
 */
export class ArtifactStore {
  private readonly artifacts = new Map<string, Artifact>();
  private readonly runs = new Map<string, OperationRun>();
  private readonly recipes = new Map<string, Recipe>();
  private readonly pipelines = new Map<string, Pipeline>();
  private readonly listeners = new Set<() => void>();
  private readonly changeListeners = new Set<(change: StoreChange) => void>();
  private version = 0;
  private batchDepth = 0;
  private batchChanged = false;

  add(init: NewArtifact): Artifact {
    const artifact: Artifact = {
      id: crypto.randomUUID(),
      name: init.name,
      value: init.value,
      createdAt: new Date().toISOString(),
      parents: [...(init.parents ?? [])],
      ...(init.producedBy !== undefined ? { producedBy: init.producedBy } : {}),
    };
    this.insert(artifact);
    return artifact;
  }

  /** Adds an artifact that already has an id, e.g. when restoring or importing a workspace. */
  insert(artifact: Artifact): void {
    if (this.artifacts.has(artifact.id)) throw new Error(`Artifact ${artifact.id} already exists`);
    for (const parent of artifact.parents) {
      if (!this.artifacts.has(parent)) throw new Error(`Unknown parent artifact ${parent}`);
    }
    if (artifact.producedBy !== undefined && !this.runs.has(artifact.producedBy)) {
      throw new Error(`Unknown operation run ${artifact.producedBy}`);
    }
    this.artifacts.set(artifact.id, artifact);
    this.changed({ kind: "artifact", artifact });
  }

  recordRun(run: OperationRun): void {
    this.runs.set(run.id, run);
    this.changed({ kind: "run", run });
  }

  /** Removes an artifact nothing else was derived from. */
  remove(id: string): void {
    if (!this.artifacts.has(id)) return;
    if (this.childrenOf(id).length > 0) throw new Error("Other artifacts were derived from this one");
    this.artifacts.delete(id);
    this.changed({ kind: "artifact-removed", id });
  }

  saveRecipe(recipe: Recipe): void {
    this.recipes.set(recipe.id, recipe);
    this.changed({ kind: "recipe", recipe });
  }

  removeRecipe(id: string): void {
    if (this.recipes.delete(id)) this.changed({ kind: "recipe-removed", id });
  }

  savePipeline(pipeline: Pipeline): void {
    this.pipelines.set(pipeline.id, pipeline);
    this.changed({ kind: "pipeline", pipeline });
  }

  removePipeline(id: string): void {
    if (this.pipelines.delete(id)) this.changed({ kind: "pipeline-removed", id });
  }

  getPipeline(id: string): Pipeline | undefined {
    return this.pipelines.get(id);
  }

  listPipelines(): Pipeline[] {
    return [...this.pipelines.values()];
  }

  clear(): void {
    this.artifacts.clear();
    this.runs.clear();
    this.recipes.clear();
    this.pipelines.clear();
    this.changed({ kind: "cleared" });
  }

  get(id: string): Artifact | undefined {
    return this.artifacts.get(id);
  }

  getRun(id: string): OperationRun | undefined {
    return this.runs.get(id);
  }

  hasRun(id: string): boolean {
    return this.runs.has(id);
  }

  /** Artifacts in creation order. */
  list(): Artifact[] {
    return [...this.artifacts.values()];
  }

  listRuns(): OperationRun[] {
    return [...this.runs.values()];
  }

  listRecipes(): Recipe[] {
    return [...this.recipes.values()];
  }

  getRecipe(id: string): Recipe | undefined {
    return this.recipes.get(id);
  }

  childrenOf(id: string): Artifact[] {
    return this.list().filter((artifact) => artifact.parents.includes(id));
  }

  /** Groups changes so subscribers re-render once, e.g. when restoring a whole workspace. */
  batch<T>(work: () => T): T {
    this.batchDepth++;
    try {
      return work();
    } finally {
      this.batchDepth--;
      if (this.batchDepth === 0 && this.batchChanged) {
        this.batchChanged = false;
        this.notify();
      }
    }
  }

  /** Arrow properties so they can be passed directly to React's useSyncExternalStore. */
  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  readonly getVersion = (): number => this.version;

  /** Detailed change feed, e.g. for persistence. */
  onChange(listener: (change: StoreChange) => void): () => void {
    this.changeListeners.add(listener);
    return () => this.changeListeners.delete(listener);
  }

  private changed(change: StoreChange): void {
    for (const listener of this.changeListeners) listener(change);
    if (this.batchDepth > 0) {
      this.batchChanged = true;
      return;
    }
    this.notify();
  }

  private notify(): void {
    this.version++;
    for (const listener of this.listeners) listener();
  }
}
