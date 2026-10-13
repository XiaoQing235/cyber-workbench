import type { SuggestedStep } from "../analysis/finding";
import type { OperationRegistry } from "../operation/registry";
import type { Params } from "../operation/types";

export const PIPELINE_SCHEMA_VERSION = 1;

interface NodeBase {
  id: string;
  position?: { x: number; y: number };
}

/** A value supplied when the pipeline runs; files are never embedded in the pipeline itself. */
export interface InputNode extends NodeBase {
  kind: "input";
  label: string;
  /** Editor-session binding to an artifact; ignored when the pipeline is shared or replayed. */
  artifactId?: string;
}

export interface OperationNode extends NodeBase {
  kind: "operation";
  operationId: string;
  operationVersion: string;
  params: Params;
}

export type PipelineNode = InputNode | OperationNode;

export interface PipelineEdge {
  id: string;
  from: string;
  fromPort: string;
  to: string;
  toPort: string;
}

export interface Pipeline {
  schemaVersion: number;
  id: string;
  name: string;
  nodes: PipelineNode[];
  edges: PipelineEdge[];
}

export const INPUT_PORT = "data";

export function newPipeline(name: string): Pipeline {
  return { schemaVersion: PIPELINE_SCHEMA_VERSION, id: crypto.randomUUID(), name, nodes: [], edges: [] };
}

/** Input → step 1 → step 2 …, laid out left to right. */
export function linearPipeline(name: string, steps: readonly SuggestedStep[], registry: OperationRegistry, artifactId?: string): Pipeline {
  const pipeline = newPipeline(name);
  const input: InputNode = { id: crypto.randomUUID(), kind: "input", label: "Input", position: { x: 0, y: 0 }, ...(artifactId ? { artifactId } : {}) };
  pipeline.nodes.push(input);
  let previous: { id: string; port: string } = { id: input.id, port: INPUT_PORT };
  steps.forEach((step, index) => {
    const spec = registry.get(step.operationId, step.operationVersion).spec;
    const node: OperationNode = {
      id: crypto.randomUUID(),
      kind: "operation",
      operationId: spec.id,
      operationVersion: spec.version,
      params: { ...step.params },
      position: { x: (index + 1) * 260, y: 0 },
    };
    pipeline.nodes.push(node);
    pipeline.edges.push({ id: crypto.randomUUID(), from: previous.id, fromPort: previous.port, to: node.id, toPort: spec.inputs[0].name });
    previous = { id: node.id, port: spec.outputs[0].name };
  });
  return pipeline;
}

export function incoming(pipeline: Pipeline, nodeId: string): PipelineEdge[] {
  return pipeline.edges.filter((edge) => edge.to === nodeId);
}

/** Node ids in dependency order, or null if the edges form a cycle. */
export function topologicalOrder(pipeline: Pipeline): string[] | null {
  const remaining = new Map(pipeline.nodes.map((node) => [node.id, 0]));
  for (const edge of pipeline.edges) if (remaining.has(edge.to)) remaining.set(edge.to, (remaining.get(edge.to) ?? 0) + 1);
  const ready = [...remaining].filter(([, count]) => count === 0).map(([id]) => id);
  const order: string[] = [];
  while (ready.length > 0) {
    const id = ready.shift()!;
    order.push(id);
    for (const edge of pipeline.edges) {
      if (edge.from !== id || !remaining.has(edge.to)) continue;
      const count = remaining.get(edge.to)! - 1;
      remaining.set(edge.to, count);
      if (count === 0) ready.push(edge.to);
    }
  }
  return order.length === pipeline.nodes.length ? order : null;
}

/** Every node upstream of `ids`, plus the ids themselves. */
export function ancestors(pipeline: Pipeline, ids: readonly string[]): Set<string> {
  const result = new Set<string>();
  const stack = [...ids];
  while (stack.length > 0) {
    const id = stack.pop()!;
    if (result.has(id)) continue;
    result.add(id);
    for (const edge of incoming(pipeline, id)) stack.push(edge.from);
  }
  return result;
}

/** Every node downstream of `id`, plus `id` itself. */
export function descendants(pipeline: Pipeline, id: string): Set<string> {
  const result = new Set([id]);
  const stack = [id];
  while (stack.length > 0) {
    const current = stack.pop()!;
    for (const edge of pipeline.edges) {
      if (edge.from === current && !result.has(edge.to)) {
        result.add(edge.to);
        stack.push(edge.to);
      }
    }
  }
  return result;
}

/** Structural problems that make the pipeline unusable (unknown operations, bad ports, cycles). */
export function validatePipeline(pipeline: Pipeline, registry: OperationRegistry): string[] {
  const problems: string[] = [];
  const nodes = new Map<string, PipelineNode>();
  for (const node of pipeline.nodes) {
    if (nodes.has(node.id)) problems.push(`Duplicate node id ${node.id}`);
    nodes.set(node.id, node);
  }
  const portTypes = (node: PipelineNode, direction: "inputs" | "outputs") => {
    if (node.kind === "input") return direction === "outputs" ? new Map([[INPUT_PORT, null]]) : new Map<string, null>();
    try {
      const spec = registry.get(node.operationId, node.operationVersion).spec;
      return new Map(spec[direction].map((port) => [port.name, port.type]));
    } catch {
      return null;
    }
  };
  for (const node of pipeline.nodes) {
    if (node.kind === "operation" && portTypes(node, "inputs") === null) {
      problems.push(`Unknown operation ${node.operationId}@${node.operationVersion}`);
    }
  }
  const connected = new Set<string>();
  for (const edge of pipeline.edges) {
    const from = nodes.get(edge.from);
    const to = nodes.get(edge.to);
    if (!from || !to) {
      problems.push(`Edge ${edge.id} refers to a missing node`);
      continue;
    }
    const outputs = portTypes(from, "outputs");
    const inputs = portTypes(to, "inputs");
    if (!outputs || !inputs) continue;
    if (!outputs.has(edge.fromPort)) problems.push(`Edge ${edge.id}: no output port "${edge.fromPort}"`);
    if (!inputs.has(edge.toPort)) problems.push(`Edge ${edge.id}: no input port "${edge.toPort}"`);
    const fromType = outputs.get(edge.fromPort);
    const toType = inputs.get(edge.toPort);
    if (fromType && toType && fromType !== toType) problems.push(`Edge ${edge.id}: ${fromType} output into a ${toType} input`);
    const target = `${edge.to}:${edge.toPort}`;
    if (connected.has(target)) problems.push(`Input "${edge.toPort}" of a node has more than one connection`);
    connected.add(target);
  }
  if (topologicalOrder(pipeline) === null) problems.push("The pipeline contains a cycle");
  return problems;
}
