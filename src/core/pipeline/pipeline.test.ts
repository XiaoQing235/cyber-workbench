import { describe, expect, it } from "vitest";
import { createDefaultRegistry } from "../../operations";
import { MemorySource, readAll } from "../bytes/sources";
import { executeOperation } from "../operation/execute";
import { bytesValue, type Value } from "../value";
import { PipelineExecutor, type OperationRunner } from "./executor";
import { linearPipeline, newPipeline, validatePipeline, type OperationNode, type Pipeline, type PipelineNode } from "./pipeline";

const registry = createDefaultRegistry();
const ascii = (text: string) => new TextEncoder().encode(text);

function counting(delayMs = 0) {
  const calls: string[] = [];
  let active = 0;
  let maxActive = 0;
  const runner: OperationRunner = async (request, signal) => {
    calls.push(request.operationId);
    active++;
    maxActive = Math.max(maxActive, active);
    try {
      if (delayMs > 0) {
        await new Promise<void>((resolve) => {
          const timer = setTimeout(resolve, delayMs);
          signal.addEventListener("abort", () => (clearTimeout(timer), resolve()), { once: true });
        });
      }
      return await executeOperation(registry, request, { signal });
    } finally {
      active--;
    }
  };
  return { runner, calls, peak: () => maxActive };
}

function op(id: string, operationId: string, params = {}): OperationNode {
  return { id, kind: "operation", operationId, operationVersion: registry.get(operationId).spec.version, params };
}

/** in → xor(A) → base64(C);  in → reverse(B) */
function diamond(key = "01"): Pipeline {
  const pipeline = newPipeline("test");
  const nodes: PipelineNode[] = [
    { id: "in", kind: "input", label: "Input" },
    op("A", "bytes.xor", { key }),
    op("B", "bytes.reverse"),
    op("C", "base64.encode"),
  ];
  pipeline.nodes.push(...nodes);
  pipeline.edges.push(
    { id: "e1", from: "in", fromPort: "data", to: "A", toPort: "data" },
    { id: "e2", from: "in", fromPort: "data", to: "B", toPort: "data" },
    { id: "e3", from: "A", fromPort: "data", to: "C", toPort: "data" },
  );
  return pipeline;
}

const input: Value = bytesValue(new MemorySource(ascii("abc")));

describe("pipeline validation", () => {
  it("reports unknown operations, bad ports, type mismatches, double connections and cycles", () => {
    const pipeline = diamond();
    expect(validatePipeline(pipeline, registry)).toEqual([]);
    pipeline.nodes.push(op("D", "text.decode"), { id: "X", kind: "operation", operationId: "nope.op", operationVersion: "1.0.0", params: {} });
    pipeline.edges.push(
      { id: "e4", from: "C", fromPort: "text", to: "D", toPort: "data" },
      { id: "e5", from: "B", fromPort: "data", to: "A", toPort: "data" },
      { id: "e6", from: "C", fromPort: "missing", to: "B", toPort: "data" },
      { id: "e7", from: "D", fromPort: "text", to: "in", toPort: "data" },
    );
    const problems = validatePipeline(pipeline, registry).join("\n");
    expect(problems).toMatch(/Unknown operation nope\.op/);
    expect(problems).toMatch(/text output into a bytes input/);
    expect(problems).toMatch(/more than one connection/);
    expect(problems).toMatch(/no output port "missing"/);
    expect(problems).toMatch(/cycle/);
  });
});

describe("pipeline executor", () => {
  it("runs independent branches in parallel and only recomputes what an edit affects", async () => {
    const { runner, calls, peak } = counting(20);
    const executor = new PipelineExecutor(registry, runner);
    const first = await executor.run(diamond("01"), { in: input });
    expect([...first.values()].every((state) => state.status === "success")).toBe(true);
    expect(calls.sort()).toEqual(["base64.encode", "bytes.reverse", "bytes.xor"]);
    expect(peak()).toBeGreaterThanOrEqual(2);
    const c = first.get("C")!.outputs!.text;
    expect(c).toEqual({ type: "text", text: btoa(String.fromCharCode(..."abc".split("").map((ch) => ch.charCodeAt(0) ^ 1))) });

    calls.length = 0;
    const edited = await executor.run(diamond("02"), { in: input });
    expect(calls.sort()).toEqual(["base64.encode", "bytes.xor"]);
    expect(edited.get("B")!.cached).toBe(true);

    calls.length = 0;
    await executor.run(diamond("01"), { in: input });
    expect(calls).toEqual([]);

    await executor.run(diamond("01"), { in: input }, { force: ["B"] });
    expect(calls).toEqual(["bytes.reverse"]);
  });

  it("evaluates only what a target needs", async () => {
    const { runner, calls } = counting();
    const states = await new PipelineExecutor(registry, runner).run(diamond(), { in: input }, { targets: ["B"] });
    expect([...states.keys()].sort()).toEqual(["B", "in"]);
    expect(calls).toEqual(["bytes.reverse"]);
  });

  it("keeps independent results when a step fails and blocks only what depends on it", async () => {
    const { runner } = counting();
    const pipeline = diamond();
    pipeline.nodes.push(op("D", "base64.decode", { requirePadding: true }), op("E", "hash.digest"));
    pipeline.edges.push(
      { id: "e4", from: "C", fromPort: "text", to: "D", toPort: "text" },
      { id: "e5", from: "D", fromPort: "data", to: "E", toPort: "data" },
    );
    const states = await new PipelineExecutor(registry, runner).run(pipeline, { in: bytesValue(new MemorySource(ascii("ab"))) });
    expect(states.get("C")!.status).toBe("success");
    expect(states.get("B")!.status).toBe("success");
    expect(states.get("D")!.status).toBe("success");
    const broken = diamond();
    broken.nodes.push(op("D", "base64.decode"), op("E", "hash.digest"));
    broken.edges.push(
      { id: "e4", from: "C", fromPort: "text", to: "D", toPort: "text" },
      { id: "e5", from: "D", fromPort: "data", to: "E", toPort: "data" },
    );
    (broken.nodes.find((node) => node.id === "A") as OperationNode).params = { key: "" };
    const failed = await new PipelineExecutor(registry, runner).run(broken, { in: input });
    expect(failed.get("A")).toMatchObject({ status: "failed" });
    expect(failed.get("C")).toMatchObject({ status: "blocked" });
    expect(failed.get("E")).toMatchObject({ status: "blocked" });
    expect(failed.get("B")).toMatchObject({ status: "success" });
  });

  it("blocks without a bound input and cancels running and waiting steps", async () => {
    const { runner } = counting(5_000);
    const executor = new PipelineExecutor(registry, runner);
    expect((await executor.run(diamond(), {})).get("in")).toMatchObject({ status: "blocked", message: "No input chosen" });
    const controller = new AbortController();
    const running = executor.run(diamond(), { in: input }, { signal: controller.signal });
    setTimeout(() => controller.abort(), 20);
    const states = await running;
    expect(states.get("A")!.status).toBe("cancelled");
    expect(states.get("C")!.status).toBe("cancelled");
  });

  it("runs a linear pipeline built from recipe steps", async () => {
    const pipeline = linearPipeline("chain", [{ operationId: "base64.encode" }, { operationId: "base64.decode" }], registry);
    const states = await new PipelineExecutor(registry, counting().runner).run(pipeline, { [pipeline.nodes[0].id]: input });
    const last = states.get(pipeline.nodes[2].id)!.outputs!.data;
    expect(last.type === "bytes" && new TextDecoder().decode(await readAll(last.source))).toBe("abc");
  });
});

describe("semver-compatible resolution", () => {
  it("resolves a pinned version to the newest compatible one", () => {
    expect(registry.get("bytes.xor", "1.0.0").spec.version).toBe("1.0.0");
    expect(() => registry.get("bytes.xor", "2.0.0")).toThrow(/Unknown operation/);
    expect(() => registry.get("bytes.xor", "0.9.0")).toThrow(/Unknown operation/);
  });
});
