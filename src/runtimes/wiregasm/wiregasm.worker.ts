import { Wiregasm, vectorToArray, type LoadSummary } from "@goodtools/wiregasm";
import loadWiregasm from "@goodtools/wiregasm/dist/wiregasm.js";
import wasmURL from "@goodtools/wiregasm/dist/wiregasm.wasm?url";
import dataURL from "@goodtools/wiregasm/dist/wiregasm.data?url";
import { projectTree, type TreeNode } from "./tree";

export interface DeepPcapReport {
  filter: string;
  matched: number;
  truncated: boolean;
  summary: LoadSummary;
  frames: { number: number; columns: string[]; tree: TreeNode[] }[];
}

export type DeepPcapRequest = { input: Uint8Array; filter: string; maxFrames: number };
export type DeepPcapResponse = { report: DeepPcapReport } | { error: string; code: "INVALID_INPUT" | "INVALID_PARAMS" | "UNAVAILABLE" };

interface WorkerScope {
  onmessage: ((event: MessageEvent<DeepPcapRequest>) => void) | null;
  postMessage(message: DeepPcapResponse): void;
}

const scope = self as unknown as WorkerScope;

function restrictNetwork(): void {
  for (const name of ["fetch", "XMLHttpRequest", "WebSocket", "WebTransport", "EventSource", "RTCPeerConnection", "indexedDB", "caches", "Worker", "SharedWorker", "BroadcastChannel", "importScripts", "eval"]) {
    for (let target: object | null = globalThis; target; target = Object.getPrototypeOf(target) as object | null) {
      if (Object.hasOwn(target, name)) Object.defineProperty(target, name, { value: undefined, configurable: false, writable: false });
    }
    Object.defineProperty(globalThis, name, { value: undefined, configurable: false, writable: false });
  }
  for (let target: object | null = navigator; target; target = Object.getPrototypeOf(target) as object | null) {
    if (Object.hasOwn(target, "storage")) Object.defineProperty(target, "storage", { value: undefined, configurable: false });
  }
  const kinds = [function () {}, async function () {}, function* () {}, async function* () {}];
  for (const kind of kinds) Object.defineProperty(Object.getPrototypeOf(kind), "constructor", { value: undefined, configurable: false });
}

scope.onmessage = async (event) => {
  const { input, filter, maxFrames } = event.data;
  const wiregasm = new Wiregasm();
  let code: Extract<DeepPcapResponse, { error: string }>["code"] = "UNAVAILABLE";
  try {
    await wiregasm.init(loadWiregasm, { locateFile: (name) => new URL(name === "wiregasm.wasm" ? wasmURL : dataURL, import.meta.url).href });
    restrictNetwork();
    if (filter) {
      const checked = wiregasm.testFilter(filter);
      if (!checked.ok) { code = "INVALID_PARAMS"; throw new Error(checked.error); }
    }
    const loaded = wiregasm.load("capture.pcap", input);
    if (loaded.code !== 0) { code = "INVALID_INPUT"; throw new Error(loaded.error); }
    const listed = wiregasm.frames(filter, 0, maxFrames);
    const frames = vectorToArray(listed.frames).map((meta) => {
      const details = wiregasm.frame(meta.number);
      return { number: meta.number, columns: vectorToArray(meta.columns).map((column) => column.slice(0, 256)),
        tree: projectTree(details.tree, 0, { nodes: 128 }) };
    });
    scope.postMessage({ report: { filter, matched: listed.matched, truncated: listed.matched > frames.length, summary: loaded.summary, frames } });
  } catch (error) {
    scope.postMessage({ code, error: error instanceof Error ? error.message : String(error) });
  } finally {
    wiregasm.destroy();
  }
};
