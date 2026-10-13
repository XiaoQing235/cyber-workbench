export interface HamiltonianReport {
  startNode: number;
  nodes: number;
  directedEdges: number;
  statesExplored: number;
  path: number[] | null;
  verified: boolean;
  candidateOnly: true;
  truncated: boolean;
}

export function findHamiltonianCandidate(text: string, startNode: number, maxStates: number, signal?: AbortSignal): HamiltonianReport {
  if (text.length > 32_000 || !Number.isSafeInteger(startNode) || startNode < 0 || startNode > 31 ||
    !Number.isSafeInteger(maxStates) || maxStates < 1 || maxStates > 500_000) throw new Error("Graph input or search budget is invalid");
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { throw new Error("Graph is not valid JSON"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Graph must be a numbered adjacency object");
  const raw = parsed as Record<string, unknown>;
  const keys = Object.keys(raw);
  if (keys.length < 2 || keys.length > 32 || keys.some((key, index) => key !== String(index)) || startNode >= keys.length) {
    throw new Error("Graph must have 2 to 32 consecutive node IDs beginning at zero");
  }
  const graph = keys.map((key, node) => {
    const neighbors = raw[key];
    if (!Array.isArray(neighbors) || neighbors.length > 32 || neighbors.some((next) => !Number.isInteger(next) || next < 0 || next >= keys.length || next === node) ||
      new Set(neighbors).size !== neighbors.length) throw new Error(`Graph node ${node} has invalid or repeated neighbors`);
    return neighbors as number[];
  });
  const seen = new Uint8Array(keys.length);
  seen[startNode] = 1;
  const path = [startNode];
  let statesExplored = 0;
  let truncated = false;
  const search = (node: number): boolean => {
    if (signal?.aborted) throw signal.reason;
    if (statesExplored >= maxStates) { truncated = true; return false; }
    statesExplored++;
    if (path.length === keys.length) return true;
    for (const neighbor of graph[node]) {
      if (seen[neighbor]) continue;
      seen[neighbor] = 1;
      path.push(neighbor);
      if (search(neighbor)) return true;
      path.pop();
      seen[neighbor] = 0;
      if (truncated) return false;
    }
    return false;
  };
  const verified = search(startNode);
  return { startNode, nodes: graph.length, directedEdges: graph.reduce((sum, neighbors) => sum + neighbors.length, 0), statesExplored,
    path: verified ? path : null, verified, candidateOnly: true, truncated };
}