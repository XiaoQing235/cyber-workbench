import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { findHamiltonianCandidate } from "../../formats/hamiltonian";
import { textInput } from "../util";

export const graphHamiltonianCandidate = defineOperation<{ startNode: number; maxStates: number }>({
  spec: {
    id: "crypto.graph.hamiltonian-candidate", version: "1.0.0", title: "Search Hamiltonian graph path", category: "Crypto",
    description: "Search a directed JSON adjacency graph for one Hamiltonian path within an explicit state budget. A matching graph path is only a candidate and cannot reveal a hidden oracle path or an LWE secret.",
    keywords: ["graph", "hamiltonian", "path", "constraint", "bounded", "maze"],
    inputs: [{ name: "graph", type: "text" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      startNode: { type: "integer", title: "Start node", minimum: 0, maximum: 31, default: 0 },
      maxStates: { type: "integer", title: "Maximum search states", minimum: 1, maximum: 500_000, default: 100_000 },
    }, required: ["startNode", "maxStates"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 32_000 },
  },
  async run(ctx, inputs, params) {
    try {
      const report = findHamiltonianCandidate(textInput(inputs, "graph"), params.startNode, params.maxStates, ctx.signal);
      ctx.diagnostic(report.verified
        ? `Verified a ${report.nodes}-node graph path in ${report.statesExplored} state(s); an oracle's hidden path may differ.`
        : `Explored ${report.statesExplored} state(s) without a path.${report.truncated ? " Search budget reached." : ""}`);
      return { report: structuredValue(report) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});