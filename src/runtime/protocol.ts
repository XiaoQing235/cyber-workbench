import type { OperationRun } from "../core/operation/run";
import type { Params } from "../core/operation/types";
import type { WireValue } from "./wire";

export interface RunRequest {
  kind: "run";
  jobId: string;
  operationId: string;
  operationVersion?: string;
  inputs: Record<string, WireValue>;
  params: Params;
}

export interface CancelRequest {
  kind: "cancel";
  jobId: string;
}

export type WorkerRequest = RunRequest | CancelRequest;

export interface RunResponse {
  kind: "result";
  jobId: string;
  run: OperationRun;
  outputs: Record<string, WireValue>;
}

/** The worker failed outside the operation contract (e.g. could not serialise outputs). */
export interface CrashResponse {
  kind: "crash";
  jobId: string;
  message: string;
}

export type WorkerResponse = RunResponse | CrashResponse;
