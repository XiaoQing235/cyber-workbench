import { OperationError } from "../../core/operation/errors";
import type { PythonOutcome } from "./engine";
import type { PythonRequest, PythonResponse } from "./python.worker";

/** Pyodide's files are served under a versioned folder next to this chunk (see vite.config.ts). */
const indexUrl = () => {
  // A variable base keeps Vite from treating this as an asset URL to resolve at build time.
  const base = import.meta.url;
  return import.meta.env.DEV ? new URL("/node_modules/pyodide/", location.href).href : new URL(`./pack-python-${__PYODIDE_VERSION__}/`, base).href;
};

type Runner = (script: string, input: Uint8Array, timeLimitMs: number, signal: AbortSignal) => Promise<PythonOutcome & { note?: string }>;

let worker: Worker | null = null;
let ready: Promise<{ version: string; loadMs: number }> | null = null;

function stop(): void {
  worker?.terminate();
  worker = null;
  ready = null;
}

function start(): Promise<{ version: string; loadMs: number }> {
  if (ready) return ready;
  const created = new Worker(new URL("./python.worker.ts", import.meta.url), { type: "module", name: "python" });
  worker = created;
  ready = new Promise((resolve, reject) => {
    created.onmessage = (event: MessageEvent<PythonResponse>) => {
      if (event.data.kind === "ready") resolve(event.data);
      else reject(new OperationError("UNAVAILABLE", `Python could not start: ${event.data.kind === "failed" ? event.data.message : "unexpected reply"}`));
    };
    created.onerror = (event) => {
      event.preventDefault();
      reject(new OperationError("UNAVAILABLE", `The Python pack could not be loaded (${event.message || "worker error"}). If you are offline, download it under Runtime packs next time you are online.`));
    };
    created.postMessage({ kind: "init", indexURL: indexUrl() } satisfies PythonRequest);
  });
  ready.catch(stop);
  return ready;
}

/** Runs a script in the isolated Python worker. A time limit or cancellation terminates the worker. */
let runner: Runner = async (script, input, timeLimitMs, signal) => {
  const startedLoad = ready === null;
  const info = await start();
  const current = worker!;
  return new Promise((resolve, reject) => {
    const finish = (settle: () => void) => {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      settle();
    };
    const timer = setTimeout(() => {
      stop();
      finish(() => reject(new OperationError("INVALID_PARAMS", `Stopped after ${timeLimitMs / 1000} s (time limit); the Python worker was restarted`)));
    }, timeLimitMs);
    const onAbort = () => {
      stop();
      finish(() => reject(new OperationError("CANCELLED", "Cancelled; the Python worker was restarted")));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    current.onmessage = (event: MessageEvent<PythonResponse>) => {
      const reply = event.data;
      if (reply.kind === "result") finish(() => resolve({ ...reply, ...(startedLoad ? { note: `Python ${info.version} started in ${info.loadMs} ms.` } : {}) }));
      else finish(() => reject(new OperationError("INTERNAL", reply.kind === "failed" ? reply.message : "Unexpected reply from the Python worker")));
    };
    current.onerror = (event) => {
      event.preventDefault();
      stop();
      finish(() => reject(new OperationError("INTERNAL", `The Python worker crashed: ${event.message || "unknown error"}`)));
    };
    const copy = new Uint8Array(input);
    current.postMessage({ kind: "run", script, input: copy } satisfies PythonRequest, [copy.buffer]);
  });
};

/** Tests run the engine in-process instead of in a worker. */
export function setPythonRunner(next: Runner): void {
  runner = next;
}

export const runPython: Runner = (...args) => runner(...args);
