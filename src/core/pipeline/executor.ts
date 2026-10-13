import { Sha256, sha256Source, toHexString } from "../hash/sha256";
import { applyDefaults } from "../operation/execute";
import type { OperationRegistry } from "../operation/registry";
import type { OperationResult, OperationRun } from "../operation/run";
import type { Params } from "../operation/types";
import { canonicalJson } from "../recipe/cache";
import type { Value } from "../value";
import { ancestors, incoming, INPUT_PORT, validatePipeline, type Pipeline } from "./pipeline";

export type NodeStatus = "waiting" | "running" | "success" | "failed" | "cancelled" | "blocked";

export interface NodeState {
  status: NodeStatus;
  outputs?: Record<string, Value>;
  run?: OperationRun;
  /** Served from the cache: same operation version, parameters and input content as an earlier run. */
  cached?: boolean;
  message?: string;
}

export interface RunnerRequest {
  operationId: string;
  operationVersion: string;
  inputs: Record<string, Value>;
  params: Params;
}

export type OperationRunner = (request: RunnerRequest, signal: AbortSignal) => Promise<OperationResult>;

export interface PipelineRunOptions {
  signal?: AbortSignal;
  /** Evaluate only these nodes and what they depend on. */
  targets?: readonly string[];
  /** Recompute these nodes even when a cached result exists. */
  force?: readonly string[];
  onUpdate?: (nodeId: string, state: NodeState) => void;
}

const MAX_CACHE_ENTRIES = 500;

const digest = (text: string) => toHexString(new Sha256().update(new TextEncoder().encode(text)).digest());

async function contentKey(value: Value): Promise<string> {
  switch (value.type) {
    case "bytes":
      return `bytes:${await sha256Source(value.source)}`;
    case "text":
      return `text:${digest(value.text)}`;
    case "number":
      return `number:${typeof value.value === "bigint" ? `${value.value}n` : value.value}`;
    case "structured":
      return `structured:${digest(canonicalJson(value.data))}`;
  }
}

class Slots {
  private available: number;
  private readonly waiting: (() => void)[] = [];

  constructor(count: number) {
    this.available = count;
  }

  async acquire(): Promise<void> {
    if (this.available > 0) {
      this.available--;
      return;
    }
    await new Promise<void>((resolve) => this.waiting.push(resolve));
  }

  release(): void {
    const next = this.waiting.shift();
    if (next) next();
    else this.available++;
  }
}

/**
 * Runs a pipeline in dependency order with independent branches in parallel. Deterministic
 * results are cached by content, so after an edit only nodes whose inputs actually changed rerun.
 */
export class PipelineExecutor {
  private readonly cache = new Map<string, { outputs: Record<string, Value>; run: OperationRun }>();
  private readonly registry: OperationRegistry;
  private readonly runner: OperationRunner;
  private readonly maxParallel: number;

  constructor(registry: OperationRegistry, runner: OperationRunner, maxParallel = 4) {
    this.registry = registry;
    this.runner = runner;
    this.maxParallel = maxParallel;
  }

  clearCache(): void {
    this.cache.clear();
  }

  async run(pipeline: Pipeline, bindings: Readonly<Record<string, Value>>, options: PipelineRunOptions = {}): Promise<Map<string, NodeState>> {
    const problems = validatePipeline(pipeline, this.registry);
    if (problems.length > 0) throw new Error(problems.join("; "));
    const signal = options.signal ?? new AbortController().signal;
    const force = new Set(options.force ?? []);
    const wanted = options.targets ? ancestors(pipeline, options.targets) : new Set(pipeline.nodes.map((node) => node.id));
    const nodes = new Map(pipeline.nodes.map((node) => [node.id, node]));
    const states = new Map<string, NodeState>();
    const slots = new Slots(this.maxParallel);
    const pending = new Map<string, Promise<NodeState>>();

    const set = (id: string, state: NodeState): NodeState => {
      states.set(id, state);
      options.onUpdate?.(id, state);
      return state;
    };
    const fail = (id: string, message: string): NodeState => set(id, { status: "failed", message });
    const block = (id: string, message: string): NodeState => set(id, { status: "blocked", message });

    const evaluate = (id: string): Promise<NodeState> => {
      let promise = pending.get(id);
      if (!promise) {
        promise = evaluateNode(id);
        pending.set(id, promise);
      }
      return promise;
    };

    const evaluateNode = async (id: string): Promise<NodeState> => {
      const node = nodes.get(id)!;
      const edges = incoming(pipeline, id);
      const upstream = await Promise.all(edges.map((edge) => evaluate(edge.from)));
      if (signal.aborted) return set(id, { status: "cancelled" });
      if (upstream.some((state) => state.status !== "success")) return block(id, "An earlier step did not succeed");
      if (node.kind === "input") {
        const value = bindings[node.id];
        return value ? set(id, { status: "success", outputs: { [INPUT_PORT]: value } }) : block(id, "No input chosen");
      }

      const spec = this.registry.get(node.operationId, node.operationVersion).spec;
      const inputs: Record<string, Value> = {};
      for (const port of spec.inputs) {
        const index = edges.findIndex((edge) => edge.toPort === port.name);
        if (index < 0) return block(id, `Input "${port.name}" is not connected`);
        const value = upstream[index].outputs?.[edges[index].fromPort];
        if (!value) return block(id, `The previous step has no "${edges[index].fromPort}" output`);
        if (value.type !== port.type) return fail(id, `"${port.name}" needs ${port.type} but receives ${value.type}`);
        inputs[port.name] = value;
      }
      let params: Params;
      try {
        params = applyDefaults(spec, node.params);
        this.registry.validateParams(spec, params);
      } catch (error) {
        return fail(id, error instanceof Error ? error.message : String(error));
      }

      let key: string | null = null;
      if (spec.deterministic && spec.sideEffects === "none") {
        const inputKeys = await Promise.all(spec.inputs.map(async (port) => `${port.name}=${await contentKey(inputs[port.name])}`));
        key = `${spec.id}@${spec.version}|${canonicalJson(params)}|${inputKeys.join("|")}`;
        const hit = force.has(id) ? undefined : this.cache.get(key);
        if (hit) return set(id, { status: "success", outputs: hit.outputs, run: hit.run, cached: true });
      }

      await slots.acquire();
      try {
        if (signal.aborted) return set(id, { status: "cancelled" });
        set(id, { status: "running" });
        const result = await this.runner({ operationId: spec.id, operationVersion: spec.version, inputs, params }, signal);
        if (result.run.status !== "success") {
          return set(id, {
            status: result.run.status === "cancelled" ? "cancelled" : "failed",
            run: result.run,
            message: result.run.error?.message ?? result.run.status,
          });
        }
        if (key) this.remember(key, result.outputs, result.run);
        return set(id, { status: "success", outputs: result.outputs, run: result.run });
      } finally {
        slots.release();
      }
    };

    for (const node of pipeline.nodes) if (wanted.has(node.id)) set(node.id, { status: "waiting" });
    await Promise.all([...wanted].map(evaluate));
    return states;
  }

  private remember(key: string, outputs: Record<string, Value>, run: OperationRun): void {
    this.cache.delete(key);
    this.cache.set(key, { outputs, run });
    if (this.cache.size > MAX_CACHE_ENTRIES) this.cache.delete(this.cache.keys().next().value!);
  }
}
