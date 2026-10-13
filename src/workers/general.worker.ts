import { createDefaultRegistry } from "../operations";
import { handleRunRequest } from "../runtime/jobHandler";
import type { WorkerRequest, WorkerResponse } from "../runtime/protocol";

// Typed locally: the project compiles against the DOM lib, which lacks the WebWorker globals.
interface WorkerScope {
  onmessage: ((event: MessageEvent<WorkerRequest>) => void) | null;
  postMessage(message: WorkerResponse): void;
}

const scope = self as unknown as WorkerScope;
const registry = createDefaultRegistry();
const controllers = new Map<string, AbortController>();

scope.onmessage = (event) => {
  const message = event.data;
  if (message.kind === "cancel") {
    controllers.get(message.jobId)?.abort();
    return;
  }
  const controller = new AbortController();
  controllers.set(message.jobId, controller);
  handleRunRequest(registry, message, controller.signal)
    .then((response) => scope.postMessage(response))
    .catch((error: unknown) => scope.postMessage({ kind: "crash", jobId: message.jobId, message: String(error) }))
    .finally(() => controllers.delete(message.jobId));
};
