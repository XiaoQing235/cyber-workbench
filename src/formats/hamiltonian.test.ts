import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { findHamiltonianCandidate } from "./hamiltonian";
import originalGraph from "./testing/google-ctf-2025-filtermaze-graph.json?raw";

describe("bounded directed Hamiltonian graph search", () => {
  it("reproduces and verifies a candidate from the original Google CTF 2025 graph", async () => {
    const path = [0, 12, 13, 14, 22, 7, 8, 23, 29, 21, 6, 5, 4, 25, 17, 16, 24, 10, 9, 15, 1, 28, 20, 2, 3, 11, 26, 18, 19, 27];
    const report = findHamiltonianCandidate(originalGraph, 0, 100_000);
    expect(report).toEqual({ startNode: 0, nodes: 30, directedEdges: 122, statesExplored: 39_430,
      path, verified: true, candidateOnly: true, truncated: false });
    const graph = JSON.parse(originalGraph) as Record<string, number[]>;
    expect(new Set(path).size).toBe(30);
    expect(path.slice(1).every((node, index) => graph[path[index]].includes(node))).toBe(true);
    const result = await executeOperation(createDefaultRegistry(), { operationId: "crypto.graph.hamiltonian-candidate",
      inputs: { graph: textValue(originalGraph) }, params: { startNode: 0, maxStates: 100_000 } });
    expect(result.run.error).toBeUndefined();
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { path, statesExplored: 39_430, candidateOnly: true } });
    expect(result.run.diagnostics[0]).toMatch(/hidden path may differ/);
  });

  it("reports exhausted budgets and rejects malformed or repeated adjacency", () => {
    expect(findHamiltonianCandidate(originalGraph, 0, 1_000)).toMatchObject({ statesExplored: 1_000, path: null, verified: false, truncated: true });
    expect(findHamiltonianCandidate('{"0":[1],"1":[]}', 0, 100)).toMatchObject({ path: [0, 1], verified: true, truncated: false });
    expect(findHamiltonianCandidate('{"0":[],"1":[]}', 0, 100)).toMatchObject({ path: null, verified: false, truncated: false });
    expect(() => findHamiltonianCandidate('{"0":[1,1],"1":[]}', 0, 100)).toThrow(/repeated neighbors/);
    expect(() => findHamiltonianCandidate('{"0":[2],"1":[]}', 0, 100)).toThrow(/invalid or repeated/);
    expect(() => findHamiltonianCandidate(originalGraph, 30, 100)).toThrow(/consecutive node IDs/);
  });
});