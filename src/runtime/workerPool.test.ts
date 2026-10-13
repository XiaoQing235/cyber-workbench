import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { OperationRegistry } from "../core/operation/registry";
import { defineOperation } from "../core/operation/types";
import { bytesValue, textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { handleRunRequest } from "./jobHandler";
import type { WorkerRequest, WorkerResponse } from "./protocol";
import { WorkerPool, type WorkerLike } from "./workerPool";

/** Runs requests in-process, mimicking a dedicated worker. */
class FakeWorker implements WorkerLike {
  onmessage: ((event: MessageEvent<WorkerResponse>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  terminated = false;
  private readonly controllers = new Map<string, AbortController>();

  constructor(private readonly registry: OperationRegistry) {}

  postMessage(message: WorkerRequest): void {
    if (this.terminated) return;
    if (message.kind === "cancel") {
      this.controllers.get(message.jobId)?.abort();
      return;
    }
    const controller = new AbortController();
    this.controllers.set(message.jobId, controller);
    void handleRunRequest(this.registry, message, controller.signal).then((response) => {
      if (!this.terminated) this.onmessage?.({ data: response } as MessageEvent<WorkerResponse>);
    });
  }

  terminate(): void {
    this.terminated = true;
  }
}

const NO_PARAMS = { type: "object", properties: {}, additionalProperties: false } as const;

function testRegistry(): OperationRegistry {
  const registry = createDefaultRegistry();
  registry.register(
    defineOperation({
      spec: {
        id: "test.hang",
        version: "1.0.0",
        title: "Hang",
        category: "Test",
        description: "Never finishes and ignores cancellation",
        inputs: [{ name: "text", type: "text" }],
        outputs: [{ name: "text", type: "text" }],
        parametersSchema: NO_PARAMS,
        runtime: "ts",
        deterministic: true,
        streaming: false,
        sideEffects: "none",
        cost: "low",
      },
      run: () => new Promise(() => {}),
    }),
  );
  return registry;
}

function setup(maxWorkers = 1) {
  const registry = testRegistry();
  const workers: FakeWorker[] = [];
  const pool = new WorkerPool(
    () => {
      const worker = new FakeWorker(registry);
      workers.push(worker);
      return worker;
    },
    maxWorkers,
    20,
  );
  return { pool, workers };
}

describe("WorkerPool", () => {
  it("runs operations and returns outputs as lazy byte sources", async () => {
    const { pool } = setup();
    const result = await pool.run(
      "bytes.reverse",
      { data: bytesValue(new MemorySource(Uint8Array.from([1, 2, 3]))) },
      {},
    );
    expect(result.run.status).toBe("success");
    const output = result.outputs.data;
    if (output.type !== "bytes") throw new Error("expected bytes");
    expect([...(await readAll(output.source))]).toEqual([3, 2, 1]);
  });

  it("queues jobs beyond the pool size and reuses workers", async () => {
    const { pool, workers } = setup(1);
    const results = await Promise.all(
      ["a", "b", "c"].map((text) => pool.run("base64.encode", { data: bytesValue(new MemorySource(new TextEncoder().encode(text))) }, {})),
    );
    expect(results.map((r) => r.outputs.text)).toEqual([textValue("YQ=="), textValue("Yg=="), textValue("Yw==")]);
    expect(workers).toHaveLength(1);
  });

  it("terminates and replaces a worker that ignores cancellation", async () => {
    const { pool, workers } = setup(1);
    const controller = new AbortController();
    const pending = pool.run("test.hang", { text: textValue("") }, {}, { signal: controller.signal });
    await new Promise((resolve) => setTimeout(resolve, 5));
    controller.abort();
    const result = await pending;
    expect(result.run.status).toBe("cancelled");
    expect(workers[0].terminated).toBe(true);

    const next = await pool.run("hex.encode", { data: bytesValue(new MemorySource(Uint8Array.from([255]))) }, {});
    expect(next.outputs.text).toEqual(textValue("ff"));
    expect(workers).toHaveLength(2);
  });

  it("cancels queued jobs without starting them", async () => {
    const { pool } = setup(1);
    const blocker = new AbortController();
    const first = pool.run("test.hang", { text: textValue("") }, {}, { signal: blocker.signal });
    const queued = new AbortController();
    const second = pool.run("hex.encode", { data: bytesValue(new MemorySource(Uint8Array.from([1]))) }, {}, { signal: queued.signal });
    queued.abort();
    expect((await second).run.status).toBe("cancelled");
    blocker.abort();
    expect((await first).run.status).toBe("cancelled");
  });

  it("reports operation failures as failed runs, never as rejections", async () => {
    const { pool } = setup();
    const result = await pool.run("base64.decode", { text: textValue("!!!") }, {});
    expect(result.run.status).toBe("failed");
    expect(result.run.error?.code).toBe("INVALID_INPUT");
  });
});
