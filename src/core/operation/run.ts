import type { Value } from "../value";
import type { OperationErrorCode } from "./errors";
import type { Params } from "./types";

export type RunStatus = "success" | "failed" | "cancelled";

/** Provenance record for one execution. Failure is its own status, never an empty success. */
export interface OperationRun {
  id: string;
  operationId: string;
  operationVersion: string | null;
  parameters: Params;
  status: RunStatus;
  startedAt: string;
  finishedAt: string;
  durationMs: number;
  diagnostics: string[];
  error?: { code: OperationErrorCode; message: string };
}

export interface OperationResult {
  run: OperationRun;
  outputs: Record<string, Value>;
}
