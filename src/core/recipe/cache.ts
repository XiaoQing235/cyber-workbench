import type { Artifact, ArtifactStore } from "../artifact/store";
import type { OperationRun } from "../operation/run";
import type { OperationSpec, Params } from "../operation/types";

/** JSON with object keys sorted, so equal parameters always serialise identically. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, item: unknown) =>
    item && typeof item === "object" && !Array.isArray(item)
      ? Object.fromEntries(Object.entries(item as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : typeof item === "bigint"
        ? `${item}n`
        : item,
  );
}

/**
 * An earlier successful run of the same deterministic operation, version and parameters on the
 * same input. Artifacts are immutable, so its outputs are exactly what a new run would produce.
 */
export function findReusableRun(
  store: ArtifactStore,
  input: Artifact,
  spec: OperationSpec,
  params: Params,
): { run: OperationRun; outputs: Artifact[] } | null {
  if (!spec.deterministic || spec.sideEffects !== "none") return null;
  const key = canonicalJson(params);
  const children = store.childrenOf(input.id);
  for (const child of children) {
    const run = child.producedBy === undefined ? undefined : store.getRun(child.producedBy);
    if (
      run?.status === "success" &&
      run.operationId === spec.id &&
      run.operationVersion === spec.version &&
      canonicalJson(run.parameters) === key
    ) {
      return { run, outputs: children.filter((artifact) => artifact.producedBy === run.id) };
    }
  }
  return null;
}
