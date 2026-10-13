import type { OperationResult, RunStatus } from "../core/operation/run";
import type { Params } from "../core/operation/types";
import type { Value } from "../core/value";
import type { WorkerRequest, WorkerResponse } from "./protocol";
import { fromWireRecord, toWireRecord, type WireValue } from "./wire";

/** The subset of the Worker API the pool uses, so tests can supply a fake. */
export interface WorkerLike {
  onmessage: ((event: MessageEvent<WorkerResponse>) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  postMessage(message: WorkerRequest): void;
  terminate(): void;
}

export interface RunOptions {
  operationVersion?: string;
  signal?: AbortSignal;
}

interface Job {
  id: string;
  operationId: string;
  operationVersion?: string;
  params: Params;
  inputs: Readonly<Record<string, Value>>;
  resolve: (result: OperationResult) => void;
  signal?: AbortSignal;
  onAbort?: () => void;
  worker?: WorkerLike;
  posted: boolean;
  cancelRequested: boolean;
  cancelTimer?: ReturnType<typeof setTimeout>;
}

function defaultPoolSize(): number {
  const cores = typeof navigator === "undefined" ? 2 : (navigator.hardwareConcurrency ?? 2);
  return Math.max(1, Math.min(4, cores - 1));
}

function syntheticResult(job: Job, status: Exclude<RunStatus, "success">, message: string): OperationResult {
  const now = new Date().toISOString();
  return {
    run: {
      id: job.id,
      operationId: job.operationId,
      operationVersion: job.operationVersion ?? null,
      parameters: job.params,
      status,
      startedAt: now,
      finishedAt: now,
      durationMs: 0,
      diagnostics: [],
      error: { code: status === "cancelled" ? "CANCELLED" : "INTERNAL", message },
    },
    outputs: {},
  };
}

/**
 * Runs operations on a small pool of workers, one job per worker at a time. Cancellation is
 * cooperative first; a worker that ignores it for `cancelGraceMs` is terminated and replaced.
 * `run()` always resolves with a run record and never rejects.
 */
export class WorkerPool {
  private readonly workers = new Set<WorkerLike>();
  private readonly idle: WorkerLike[] = [];
  private readonly queue: Job[] = [];
  private readonly running = new Map<string, Job>();
  private disposed = false;

  constructor(
    private readonly createWorker: () => WorkerLike,
    private readonly maxWorkers = defaultPoolSize(),
    private readonly cancelGraceMs = 1000,
  ) {}

  run(
    operationId: string,
    inputs: Readonly<Record<string, Value>>,
    params: Params,
    options: RunOptions = {},
  ): Promise<OperationResult> {
    return new Promise((resolve) => {
      const job: Job = {
        id: crypto.randomUUID(),
        operationId,
        operationVersion: options.operationVersion,
        params,
        inputs,
        resolve,
        signal: options.signal,
        posted: false,
        cancelRequested: false,
      };
      if (this.disposed) {
        resolve(syntheticResult(job, "cancelled", "The worker pool has been shut down"));
        return;
      }
      if (options.signal?.aborted) {
        resolve(syntheticResult(job, "cancelled", "Cancelled before it started"));
        return;
      }
      if (options.signal) {
        job.onAbort = () => this.cancel(job);
        options.signal.addEventListener("abort", job.onAbort, { once: true });
      }
      this.queue.push(job);
      this.pump();
    });
  }

  dispose(): void {
    this.disposed = true;
    for (const job of this.queue.splice(0)) this.finish(job, syntheticResult(job, "cancelled", "Shut down"));
    for (const job of [...this.running.values()]) this.finish(job, syntheticResult(job, "cancelled", "Shut down"));
    for (const worker of [...this.workers]) this.terminate(worker);
  }

  private pump(): void {
    while (this.queue.length > 0) {
      const worker = this.idle.pop() ?? this.spawn();
      if (!worker) return;
      void this.start(worker, this.queue.shift()!);
    }
  }

  private spawn(): WorkerLike | undefined {
    if (this.disposed || this.workers.size >= this.maxWorkers) return undefined;
    const worker = this.createWorker();
    worker.onmessage = (event) => this.onMessage(worker, event.data);
    worker.onerror = (event) => {
      event.preventDefault?.();
      this.onCrash(worker, event.message || "Worker error");
    };
    this.workers.add(worker);
    return worker;
  }

  private async start(worker: WorkerLike, job: Job): Promise<void> {
    job.worker = worker;
    this.running.set(job.id, job);
    let inputs: Record<string, WireValue>;
    try {
      inputs = await toWireRecord(job.inputs);
    } catch (error) {
      this.finish(job, syntheticResult(job, "failed", `Could not send inputs: ${String(error)}`));
      this.release(worker);
      return;
    }
    if (!this.running.has(job.id)) return;
    if (job.cancelRequested) {
      this.finish(job, syntheticResult(job, "cancelled", "Cancelled before it started"));
      this.release(worker);
      return;
    }
    job.posted = true;
    worker.postMessage({
      kind: "run",
      jobId: job.id,
      operationId: job.operationId,
      operationVersion: job.operationVersion,
      inputs,
      params: job.params,
    });
  }

  private cancel(job: Job): void {
    const queued = this.queue.indexOf(job);
    if (queued >= 0) {
      this.queue.splice(queued, 1);
      this.finish(job, syntheticResult(job, "cancelled", "Cancelled before it started"));
      return;
    }
    const worker = job.worker;
    if (!worker || !this.running.has(job.id)) return;
    if (!job.posted) {
      job.cancelRequested = true;
      return;
    }
    worker.postMessage({ kind: "cancel", jobId: job.id });
    job.cancelTimer = setTimeout(() => {
      if (!this.running.has(job.id)) return;
      this.terminate(worker);
      this.finish(job, syntheticResult(job, "cancelled", "Cancelled; the worker did not stop in time and was restarted"));
      this.pump();
    }, this.cancelGraceMs);
  }

  private onMessage(worker: WorkerLike, message: WorkerResponse): void {
    const job = this.running.get(message.jobId);
    if (!job) return;
    if (message.kind === "result") {
      this.finish(job, { run: message.run, outputs: fromWireRecord(message.outputs) });
    } else {
      this.finish(job, syntheticResult(job, "failed", message.message));
    }
    this.release(worker);
  }

  private onCrash(worker: WorkerLike, message: string): void {
    for (const job of [...this.running.values()]) {
      if (job.worker === worker) this.finish(job, syntheticResult(job, "failed", `Worker crashed: ${message}`));
    }
    this.terminate(worker);
    this.pump();
  }

  private finish(job: Job, result: OperationResult): void {
    this.running.delete(job.id);
    if (job.cancelTimer !== undefined) clearTimeout(job.cancelTimer);
    if (job.signal && job.onAbort) job.signal.removeEventListener("abort", job.onAbort);
    job.resolve(result);
  }

  private release(worker: WorkerLike): void {
    if (!this.workers.has(worker)) return;
    this.idle.push(worker);
    this.pump();
  }

  private terminate(worker: WorkerLike): void {
    worker.terminate();
    this.workers.delete(worker);
    const index = this.idle.indexOf(worker);
    if (index >= 0) this.idle.splice(index, 1);
  }
}
