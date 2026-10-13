import {
  applyEdgeChanges,
  applyNodeChanges,
  Background,
  Controls,
  Handle,
  Position,
  ReactFlow,
  type Connection,
  type Edge,
  type EdgeChange,
  type Node,
  type NodeChange,
  type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useEffect, useState, useSyncExternalStore } from "react";
import type { NodeState, NodeStatus } from "../../core/pipeline/executor";
import {
  descendants,
  incoming,
  INPUT_PORT,
  newPipeline,
  topologicalOrder,
  validatePipeline,
  type OperationNode,
  type Pipeline,
  type PipelineNode,
} from "../../core/pipeline/pipeline";
import { describeValue, type Value } from "../../core/value";
import { pipelineExecutor, registry, store } from "../services";
import { ValueBody } from "./ArtifactView";
import { ParamsForm, defaultParams } from "./ParamsForm";

const BUTTON = "rounded border border-slate-300 bg-white px-2 py-1 text-xs hover:bg-slate-100 disabled:opacity-50";
type ShownStatus = NodeStatus | "idle" | "stale";

const STATUS_STYLE: Record<ShownStatus, string> = {
  idle: "border-slate-300",
  stale: "border-dashed border-slate-400",
  waiting: "border-dashed border-slate-400",
  running: "border-sky-500 ring-2 ring-sky-200",
  success: "border-emerald-500",
  failed: "border-red-500",
  cancelled: "border-amber-500",
  blocked: "border-dashed border-amber-400",
};

type FlowData = {
  title: string;
  detail: string;
  status: ShownStatus;
  cached: boolean;
  note: string;
  inputs: string[];
  outputs: string[];
};

const handleTop = (index: number, count: number) => ({ top: `${((index + 1) / (count + 1)) * 100}%` });

function NodeView({ data, selected }: NodeProps<Node<FlowData>>) {
  return (
    <div className={`w-52 rounded border-2 bg-white px-2 py-1 text-xs shadow-sm ${STATUS_STYLE[data.status]} ${selected ? "outline-2 outline-sky-400" : ""}`}>
      {data.inputs.map((port, index) => (
        <Handle key={port} type="target" position={Position.Left} id={port} style={handleTop(index, data.inputs.length)} title={port} />
      ))}
      <p className="truncate font-semibold">{data.title}</p>
      <p className="truncate font-mono text-[10px] text-slate-500">{data.detail}</p>
      <p className="truncate text-slate-600">
        {data.status}
        {data.cached && " · cached"}
        {data.note && ` · ${data.note}`}
      </p>
      {data.outputs.map((port, index) => (
        <Handle key={port} type="source" position={Position.Right} id={port} style={handleTop(index, data.outputs.length)} title={port} />
      ))}
    </div>
  );
}

const NODE_TYPES = { step: NodeView };

function portsOf(node: PipelineNode): { inputs: string[]; outputs: string[]; title: string; types: Map<string, string | null> } {
  if (node.kind === "input") return { inputs: [], outputs: [INPUT_PORT], title: node.label, types: new Map([[`out:${INPUT_PORT}`, null]]) };
  try {
    const spec = registry.get(node.operationId, node.operationVersion).spec;
    return {
      inputs: spec.inputs.map((port) => port.name),
      outputs: spec.outputs.map((port) => port.name),
      title: spec.title,
      types: new Map([
        ...spec.inputs.map((port) => [`in:${port.name}`, port.type] as const),
        ...spec.outputs.map((port) => [`out:${port.name}`, port.type] as const),
      ]),
    };
  } catch {
    return { inputs: [], outputs: [], title: `${node.operationId} (unknown)`, types: new Map() };
  }
}

/** Input → … → output with single connections only, i.e. something a linear recipe can express. */
function linearSteps(pipeline: Pipeline): OperationNode[] | null {
  const order = topologicalOrder(pipeline);
  const inputs = pipeline.nodes.filter((node) => node.kind === "input");
  if (!order || inputs.length !== 1) return null;
  const operations = order.map((id) => pipeline.nodes.find((node) => node.id === id)!).filter((node): node is OperationNode => node.kind === "operation");
  const chain = [inputs[0].id, ...operations.map((node) => node.id)];
  const linked = pipeline.edges.length === operations.length && pipeline.edges.every((edge) => chain.indexOf(edge.to) === chain.indexOf(edge.from) + 1);
  return linked && operations.length > 0 ? operations : null;
}

interface Props {
  pipelineId: string | null;
  onSelectPipeline: (id: string | null) => void;
}

export function PipelineEditor({ pipelineId, onSelectPipeline }: Props) {
  useSyncExternalStore(store.subscribe, store.getVersion);
  const pipelines = store.listPipelines();
  const pipeline = (pipelineId ? store.getPipeline(pipelineId) : undefined) ?? pipelines[0];
  const [selected, setSelected] = useState<string | null>(null);
  const [states, setStates] = useState<Record<string, NodeState>>({});
  const [stale, setStale] = useState<ReadonlySet<string>>(new Set());
  const [running, setRunning] = useState<AbortController | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [flowNodes, setFlowNodes] = useState<Node<FlowData>[]>([]);
  const [flowEdges, setFlowEdges] = useState<Edge[]>([]);

  useEffect(() => {
    if (!pipeline) return;
    setFlowNodes((previous) => {
      // Positions and selection belong to React Flow; carry them over instead of re-deriving them.
      const before = new Map(previous.map((node) => [node.id, node]));
      return pipeline.nodes.map((node, index) => {
        const { inputs, outputs, title } = portsOf(node);
        const state = states[node.id];
        const bound = node.kind === "input" && node.artifactId ? store.get(node.artifactId) : undefined;
        return {
          id: node.id,
          type: "step",
          position: before.get(node.id)?.position ?? node.position ?? { x: index * 260, y: 0 },
          selected: before.get(node.id)?.selected ?? false,
          data: {
            title,
            detail: node.kind === "input" ? (bound ? bound.name : "no artifact chosen") : `${node.operationId}@${node.operationVersion}`,
            status: stale.has(node.id) ? "stale" : (state?.status ?? "idle"),
            cached: !stale.has(node.id) && state?.cached === true,
            note: state?.run && !state.cached ? `${state.run.durationMs} ms` : "",
            inputs,
            outputs,
          },
        };
      });
    });
    setFlowEdges(
      pipeline.edges.map((edge) => ({
        id: edge.id,
        source: edge.from,
        sourceHandle: edge.fromPort,
        target: edge.to,
        targetHandle: edge.toPort,
        animated: states[edge.to]?.status === "running",
      })),
    );
  }, [pipeline, states, stale]);

  if (!pipeline) {
    return (
      <section className="flex flex-col items-start gap-2 rounded-lg border border-slate-200 bg-white p-4 text-sm">
        <p>No pipelines yet. Open one from a finding or recipe, or start an empty one.</p>
        <button className={BUTTON} onClick={() => create()}>
          New pipeline
        </button>
      </section>
    );
  }

  function create() {
    const next = newPipeline(`Pipeline ${store.listPipelines().length + 1}`);
    next.nodes.push({ id: crypto.randomUUID(), kind: "input", label: "Input", position: { x: 0, y: 0 } });
    store.savePipeline(next);
    onSelectPipeline(next.id);
  }

  const update = (change: (draft: Pipeline) => void, outdated: Iterable<string> = []) => {
    const draft = structuredClone(pipeline);
    change(draft);
    store.savePipeline(draft);
    const affected = new Set(stale);
    for (const id of outdated) for (const downstream of descendants(draft, id)) affected.add(downstream);
    setStale(affected);
  };

  const run = async (targets?: string[], force?: string[]) => {
    const bindings: Record<string, Value> = {};
    for (const node of pipeline.nodes) {
      const artifact = node.kind === "input" && node.artifactId ? store.get(node.artifactId) : undefined;
      if (artifact) bindings[node.id] = artifact.value;
    }
    const controller = new AbortController();
    setRunning(controller);
    setProblem(null);
    try {
      const result = await pipelineExecutor.run(pipeline, bindings, {
        signal: controller.signal,
        ...(targets ? { targets } : {}),
        ...(force ? { force } : {}),
        onUpdate: (id, state) => setStates((current) => ({ ...current, [id]: state })),
      });
      setStale((current) => new Set([...current].filter((id) => !result.has(id))));
    } catch (error) {
      setProblem(error instanceof Error ? error.message : String(error));
    } finally {
      setRunning(null);
    }
  };

  /** Adds the node's result, and every upstream result it needs, as artifacts with provenance. */
  const keep = (nodeId: string): string | undefined => {
    const node = pipeline.nodes.find((candidate) => candidate.id === nodeId);
    if (!node) return undefined;
    if (node.kind === "input") return node.artifactId;
    const state = states[nodeId];
    if (state?.status !== "success" || !state.run || !state.outputs || stale.has(nodeId)) return undefined;
    const run = state.run;
    const existing = store.list().find((artifact) => artifact.producedBy === run.id);
    if (existing) return existing.id;
    const parents = incoming(pipeline, nodeId).map((edge) => keep(edge.from));
    if (parents.some((parent) => parent === undefined)) return undefined;
    if (!store.hasRun(run.id)) store.recordRun(run);
    const title = registry.get(node.operationId, node.operationVersion).spec.title;
    let first: string | undefined;
    for (const [name, value] of Object.entries(state.outputs)) {
      first ??= store.add({ name: `${title} → ${name}`, value, producedBy: run.id, parents: parents as string[] }).id;
    }
    return first;
  };

  const addOperation = (operationId: string) => {
    const spec = registry.get(operationId).spec;
    const from = selected ? pipeline.nodes.find((node) => node.id === selected) : undefined;
    const fromPorts = from ? portsOf(from) : undefined;
    const fromPort = fromPorts?.outputs.find((port) => {
      const type = fromPorts.types.get(`out:${port}`);
      return type === null || type === spec.inputs[0].type;
    });
    const position = from?.position ? { x: from.position.x + 260, y: from.position.y } : { x: pipeline.nodes.length * 260, y: 120 };
    const node: OperationNode = { id: crypto.randomUUID(), kind: "operation", operationId, operationVersion: spec.version, params: defaultParams(spec), position };
    update((draft) => {
      draft.nodes.push(node);
      if (from && fromPort) draft.edges.push({ id: crypto.randomUUID(), from: from.id, fromPort, to: node.id, toPort: spec.inputs[0].name });
    }, [node.id]);
  };

  const connect = (connection: Connection) => {
    const source = pipeline.nodes.find((node) => node.id === connection.source);
    const target = pipeline.nodes.find((node) => node.id === connection.target);
    if (!source || !target || !connection.sourceHandle || !connection.targetHandle) return;
    const fromType = portsOf(source).types.get(`out:${connection.sourceHandle}`);
    const toType = portsOf(target).types.get(`in:${connection.targetHandle}`);
    if (fromType && toType && fromType !== toType) {
      setProblem(`Cannot connect a ${fromType} output to a ${toType} input.`);
      return;
    }
    update((draft) => {
      draft.edges = draft.edges.filter((edge) => !(edge.to === target.id && edge.toPort === connection.targetHandle));
      draft.edges.push({ id: crypto.randomUUID(), from: source.id, fromPort: connection.sourceHandle!, to: target.id, toPort: connection.targetHandle! });
      if (topologicalOrder(draft) === null) throw new Error("cycle");
    }, [target.id]);
  };

  const safeConnect = (connection: Connection) => {
    try {
      connect(connection);
    } catch {
      setProblem("That connection would create a cycle.");
    }
  };

  const problems = validatePipeline(pipeline, registry);
  const node = pipeline.nodes.find((candidate) => candidate.id === selected);
  const state = node ? states[node.id] : undefined;
  const steps = linearSteps(pipeline);
  const artifacts = store.list();

  return (
    <div className="flex min-h-0 flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <select className="rounded border border-slate-300 px-1 py-1" aria-label="Pipeline" value={pipeline.id} onChange={(event) => onSelectPipeline(event.target.value)}>
          {pipelines.map((item) => (
            <option key={item.id} value={item.id}>
              {item.name}
            </option>
          ))}
        </select>
        <input
          key={pipeline.id}
          className="rounded border border-slate-300 px-1 py-1"
          aria-label="Pipeline name"
          defaultValue={pipeline.name}
          onBlur={(event) => event.target.value.trim() && event.target.value !== pipeline.name && update((draft) => void (draft.name = event.target.value.trim()))}
        />
        <button className={BUTTON} onClick={create}>
          New
        </button>
        <button
          className={BUTTON}
          onClick={() =>
            update((draft) =>
              void draft.nodes.push({ id: crypto.randomUUID(), kind: "input", label: `Input ${draft.nodes.filter((n) => n.kind === "input").length + 1}`, position: { x: 0, y: 160 } }),
            )
          }
        >
          Add input
        </button>
        <select
          className="rounded border border-slate-300 px-1 py-1"
          aria-label="Add operation"
          value=""
          onChange={(event) => event.target.value && addOperation(event.target.value)}
        >
          <option value="">Add operation{selected ? " after the selected node" : ""}…</option>
          {registry.list().map((spec) => (
            <option key={spec.id} value={spec.id}>
              {spec.category}: {spec.title}
            </option>
          ))}
        </select>
        <button className={`${BUTTON} border-sky-600 bg-sky-600 text-white hover:bg-sky-700`} disabled={running !== null || problems.length > 0} onClick={() => void run()}>
          {running ? "Running…" : "Run all"}
        </button>
        {running && (
          <button className={BUTTON} onClick={() => running.abort()}>
            Cancel
          </button>
        )}
        <button
          className={BUTTON}
          disabled={!steps}
          title={steps ? "Save this chain as a linear recipe" : "Only a single chain from one input can be a recipe"}
          onClick={() =>
            steps &&
            store.saveRecipe({
              id: crypto.randomUUID(),
              name: pipeline.name,
              createdAt: new Date().toISOString(),
              steps: steps.map(({ operationId, operationVersion, params }) => ({ operationId, operationVersion, params: structuredClone(params) })),
            })
          }
        >
          Save as recipe
        </button>
        <button
          className={BUTTON}
          onClick={() => {
            if (!confirm(`Delete the pipeline "${pipeline.name}"?`)) return;
            store.removePipeline(pipeline.id);
            onSelectPipeline(null);
          }}
        >
          Delete pipeline
        </button>
      </div>
      {(problem || problems.length > 0) && <p className="text-xs text-red-700">{problem ?? problems.join("; ")}</p>}

      <div className="flex min-h-0 gap-3">
        <div className="h-[60vh] min-w-0 flex-1 rounded-lg border border-slate-200 bg-white">
          <ReactFlow
            nodes={flowNodes}
            edges={flowEdges}
            nodeTypes={NODE_TYPES}
            onNodesChange={(changes: NodeChange<Node<FlowData>>[]) => setFlowNodes((current) => applyNodeChanges(changes, current))}
            onEdgesChange={(changes: EdgeChange[]) => setFlowEdges((current) => applyEdgeChanges(changes, current))}
            onNodeDragStop={(_event, moved) =>
              update((draft) => {
                const target = draft.nodes.find((candidate) => candidate.id === moved.id);
                if (target) target.position = moved.position;
              })
            }
            onNodesDelete={(deleted) => {
              const ids = new Set(deleted.map((item) => item.id));
              update((draft) => {
                draft.nodes = draft.nodes.filter((candidate) => !ids.has(candidate.id));
                draft.edges = draft.edges.filter((edge) => !ids.has(edge.from) && !ids.has(edge.to));
              });
              setSelected(null);
            }}
            onEdgesDelete={(deleted) => {
              const ids = new Set(deleted.map((item) => item.id));
              const targets = pipeline.edges.filter((edge) => ids.has(edge.id)).map((edge) => edge.to);
              update((draft) => void (draft.edges = draft.edges.filter((edge) => !ids.has(edge.id))), targets);
            }}
            onConnect={safeConnect}
            onSelectionChange={({ nodes }) => setSelected(nodes[0]?.id ?? null)}
            fitView
            proOptions={{ hideAttribution: true }}
          >
            <Background />
            <Controls />
          </ReactFlow>
        </div>

        <aside className="flex w-96 shrink-0 flex-col gap-2 overflow-y-auto text-sm">
          {!node && <p className="text-xs text-slate-500">Select a node to edit it and see its result. Drag from a node's right edge to another node's left edge to connect them.</p>}
          {node?.kind === "input" && (
            <section className="flex flex-col gap-2 rounded-lg border border-slate-200 bg-white p-3">
              <h3 className="font-semibold">Input</h3>
              <label className="flex flex-col gap-1 text-xs">
                Artifact
                <select
                  className="rounded border border-slate-300 px-1 py-1"
                  value={node.artifactId ?? ""}
                  onChange={(event) =>
                    update((draft) => {
                      const target = draft.nodes.find((candidate) => candidate.id === node.id);
                      if (target?.kind === "input") target.artifactId = event.target.value || undefined;
                    }, [node.id])
                  }
                >
                  <option value="">Choose…</option>
                  {artifacts.map((artifact) => (
                    <option key={artifact.id} value={artifact.id}>
                      {artifact.name} ({describeValue(artifact.value)})
                    </option>
                  ))}
                </select>
              </label>
            </section>
          )}
          {node?.kind === "operation" && (
            <section className="flex flex-col gap-2 rounded-lg border border-slate-200 bg-white p-3">
              <h3 className="font-semibold">{portsOf(node).title}</h3>
              <p className="font-mono text-xs text-slate-500">
                {node.operationId}@{node.operationVersion}
              </p>
              {registry.has(node.operationId) && (
                <ParamsForm
                  spec={registry.get(node.operationId, node.operationVersion).spec}
                  value={node.params}
                  onChange={(params) =>
                    update((draft) => {
                      const target = draft.nodes.find((candidate) => candidate.id === node.id);
                      if (target?.kind === "operation") target.params = params;
                    }, [node.id])
                  }
                />
              )}
              <div className="flex flex-wrap gap-1">
                <button className={BUTTON} disabled={running !== null} onClick={() => void run([node.id])}>
                  Run to here
                </button>
                <button className={BUTTON} disabled={running !== null} title="Recompute even if a cached result exists" onClick={() => void run([node.id], [node.id])}>
                  Rerun
                </button>
                <button
                  className={BUTTON}
                  disabled={state?.status !== "success" || stale.has(node.id)}
                  onClick={() => setProblem(keep(node.id) ? null : "Run this node and the ones before it first, then keep it.")}
                >
                  Keep as artifact
                </button>
              </div>
              {state && (
                <p className={`text-xs ${state.status === "failed" ? "text-red-700" : "text-slate-600"}`}>
                  {stale.has(node.id) ? "Outdated: run again to update. " : ""}
                  {state.status}
                  {state.cached && " (cached: same operation version, parameters and input content as an earlier run)"}
                  {state.run && !state.cached && ` in ${state.run.durationMs} ms`}
                  {state.message && ` · ${state.message}`}
                </p>
              )}
              {state?.run?.diagnostics.map((message) => (
                <p key={message} className="text-xs text-amber-700">
                  {message}
                </p>
              ))}
              {state?.outputs &&
                Object.entries(state.outputs).map(([name, value]) => (
                  <div key={name} className="flex flex-col gap-1">
                    <p className="text-xs font-medium">
                      {name} · {describeValue(value)}
                    </p>
                    <ValueBody key={`${node.id}:${state.run?.id}`} value={value} />
                  </div>
                ))}
            </section>
          )}
        </aside>
      </div>
    </div>
  );
}
