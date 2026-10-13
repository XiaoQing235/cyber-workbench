import { loadPyodide } from "pyodide";
import { createEngine, type PythonEngine } from "./engine";

/**
 * The Python pack's own worker. It is the only script allowed eval (Pyodide needs it to start), so
 * once Pyodide has loaded it removes network, storage, worker and eval access from itself.
 */

export type PythonRequest = { kind: "init"; indexURL: string } | { kind: "run"; script: string; input: Uint8Array };

export type PythonResponse =
  | { kind: "ready"; version: string; loadMs: number }
  | { kind: "result"; stdout: string[]; result: Uint8Array | null; error?: string }
  | { kind: "failed"; message: string };

interface WorkerScope {
  onmessage: ((event: MessageEvent<PythonRequest>) => void) | null;
  postMessage(message: PythonResponse, transfer?: Transferable[]): void;
}

const scope = self as unknown as WorkerScope;
let engine: PythonEngine | undefined;

const BLOCKED = [
  "fetch", "XMLHttpRequest", "WebSocket", "WebTransport", "EventSource", "RTCPeerConnection",
  "indexedDB", "caches", "Worker", "SharedWorker", "BroadcastChannel", "importScripts", "eval",
];

function lockDown(): void {
  // Defined on prototypes (WorkerGlobalScope, WindowOrWorkerGlobalScope…) too, so shadowing only the global is not enough.
  for (const name of BLOCKED) {
    for (let target: object | null = globalThis; target; target = Object.getPrototypeOf(target) as object | null) {
      if (Object.hasOwn(target, name)) Object.defineProperty(target, name, { value: undefined, configurable: false, writable: false });
    }
    Object.defineProperty(globalThis, name, { value: undefined, configurable: false, writable: false });
  }
  for (let target: object | null = navigator; target; target = Object.getPrototypeOf(target) as object | null) {
    if (Object.hasOwn(target, "storage")) Object.defineProperty(target, "storage", { value: undefined, configurable: false });
  }
  // Every function's constructor chain leads to Function (or its async/generator kin), which would rebuild eval.
  const kinds = [function () {}, async function () {}, function* () {}, async function* () {}];
  for (const kind of kinds) Object.defineProperty(Object.getPrototypeOf(kind), "constructor", { value: undefined, configurable: false });
}

scope.onmessage = (event) => {
  const message = event.data;
  if (message.kind === "init") {
    const started = performance.now();
    createEngine(loadPyodide, message.indexURL).then(
      (created) => {
        engine = created;
        lockDown();
        scope.postMessage({ kind: "ready", version: created.version, loadMs: Math.round(performance.now() - started) });
      },
      (error: unknown) => scope.postMessage({ kind: "failed", message: error instanceof Error ? error.message : String(error) }),
    );
    return;
  }
  if (!engine) {
    scope.postMessage({ kind: "failed", message: "Python is not loaded" });
    return;
  }
  const outcome = engine.run(message.script, message.input);
  scope.postMessage({ kind: "result", ...outcome }, outcome.result ? [outcome.result.buffer as ArrayBuffer] : []);
};
