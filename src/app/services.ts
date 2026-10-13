import { ArtifactStore } from "../core/artifact/store";
import { PipelineExecutor } from "../core/pipeline/executor";
import { createDefaultRegistry } from "../operations";
import { WorkerPool } from "../runtime/workerPool";

// App-wide singletons, created outside React so StrictMode remounts don't recreate them.
export const registry = createDefaultRegistry();
export const store = new ArtifactStore();

let pool: WorkerPool | undefined;

export function getPool(): WorkerPool {
  pool ??= new WorkerPool(
    () => new Worker(new URL("../workers/general.worker.ts", import.meta.url), { type: "module", name: "general" }),
  );
  return pool;
}

/** Shared so its content-keyed cache survives across pipeline runs and editor remounts. */
export const pipelineExecutor = new PipelineExecutor(registry, (request, signal) =>
  getPool().run(request.operationId, request.inputs, request.params, { operationVersion: request.operationVersion, signal }),
);
