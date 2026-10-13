import { executeOperation } from "../core/operation/execute";
import type { OperationRegistry } from "../core/operation/registry";
import type { RunRequest, RunResponse } from "./protocol";
import { fromWireRecord, toWireRecord } from "./wire";

/** Worker-side handling of one run request. Kept free of Worker globals so it can be unit tested. */
export async function handleRunRequest(
  registry: OperationRegistry,
  request: RunRequest,
  signal: AbortSignal,
): Promise<RunResponse> {
  const result = await executeOperation(
    registry,
    {
      operationId: request.operationId,
      operationVersion: request.operationVersion,
      inputs: fromWireRecord(request.inputs),
      params: request.params,
    },
    { signal, runId: request.jobId },
  );
  return {
    kind: "result",
    jobId: request.jobId,
    run: result.run,
    outputs: await toWireRecord(result.outputs),
  };
}
