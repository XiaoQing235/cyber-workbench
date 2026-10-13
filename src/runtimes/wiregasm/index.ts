import { OperationError } from "../../core/operation/errors";
import type { DeepPcapRequest, DeepPcapResponse, DeepPcapReport } from "./wiregasm.worker";

export function runDeepPcap(input: Uint8Array, filter: string, maxFrames: number, signal: AbortSignal): Promise<DeepPcapReport> {
  if (signal.aborted) return Promise.reject(new OperationError("CANCELLED", "Wiregasm was cancelled"));
  const worker = new Worker(new URL("./wiregasm.worker.ts", import.meta.url), { type: "module", name: "wiregasm" });
  return new Promise((resolve, reject) => {
    const finish = (settle: () => void) => {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      worker.terminate();
      settle();
    };
    const timer = setTimeout(() => finish(() => reject(new OperationError("UNAVAILABLE", "Wiregasm took over 120 seconds to start or dissect the capture"))), 120_000);
    const onAbort = () => finish(() => reject(new OperationError("CANCELLED", "Wiregasm was cancelled")));
    signal.addEventListener("abort", onAbort, { once: true });
    worker.onmessage = (event: MessageEvent<DeepPcapResponse>) => {
      const message = event.data;
      if ("report" in message) finish(() => resolve(message.report));
      else finish(() => reject(new OperationError(message.code, message.error)));
    };
    worker.onerror = (event) => {
      event.preventDefault();
      finish(() => reject(new OperationError("UNAVAILABLE", `Wiregasm worker failed (${event.message || "unknown error"})`)));
    };
    const copy = new Uint8Array(input);
    worker.postMessage({ input: copy, filter, maxFrames } satisfies DeepPcapRequest, [copy.buffer]);
  });
}
