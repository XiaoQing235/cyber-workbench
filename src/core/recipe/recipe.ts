import type { Artifact, ArtifactStore } from "../artifact/store";
import type { OperationRun } from "../operation/run";
import type { Params } from "../operation/types";

export interface RecipeStep {
  operationId: string;
  /** Pinned so a replay runs the same code; null only for runs whose operation was unknown. */
  operationVersion: string | null;
  params: Params;
}

/** A linear pipeline whose input is bound when it is replayed. */
export interface Recipe {
  id: string;
  name: string;
  createdAt: string;
  steps: RecipeStep[];
}

export interface LineageStep {
  run: OperationRun;
  artifact: Artifact;
}

/** The runs that produced an artifact, oldest first, back to the input it was derived from. */
export function lineage(store: ArtifactStore, artifactId: string): { root: Artifact; steps: LineageStep[] } | null {
  let current = store.get(artifactId);
  if (!current) return null;
  const steps: LineageStep[] = [];
  const visited = new Set<string>();
  while (current.producedBy !== undefined && current.parents.length > 0 && !visited.has(current.id)) {
    visited.add(current.id);
    const run = store.getRun(current.producedBy);
    const parent = store.get(current.parents[0]);
    if (!run || !parent) break;
    steps.unshift({ run, artifact: current });
    current = parent;
  }
  return { root: current, steps };
}

export function recipeFromLineage(name: string, steps: readonly LineageStep[]): Recipe {
  return {
    id: crypto.randomUUID(),
    name,
    createdAt: new Date().toISOString(),
    steps: steps.map(({ run }) => ({
      operationId: run.operationId,
      operationVersion: run.operationVersion,
      params: structuredClone(run.parameters),
    })),
  };
}
