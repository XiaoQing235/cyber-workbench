/** Bounded validation of a candidate password against the original labeled, undirected DOT graph. */
export function verifyNpcHint(dot: string, candidate: string, maxStates: number, signal?: AbortSignal): {
  nodes: number; edges: number; statesExplored: number; path: number[] | null; candidate: string;
  graphValid: boolean; truncated: boolean; passwordVerified: false;
} {
  if (dot.length > 16_384 || !Number.isSafeInteger(maxStates) || maxStates < 1 || maxStates > 1_000_000 ||
    !/^[a-z]{2,64}$/.test(candidate)) throw new Error("NPC hint, candidate or search budget is invalid");
  const lines = dot.trim().split(/\r?\n/).map((line) => line.trim());
  if (lines[0] !== "graph {" || lines.at(-1) !== "}") throw new Error("NPC hint is not an undirected DOT graph");
  const labels = new Map<number, string>();
  const edges: [number, number][] = [];
  for (const line of lines.slice(1, -1)) {
    const node = /^(\d{1,10}) \[label=([a-z])\];$/.exec(line);
    const edge = /^(\d{1,10}) -- (\d{1,10});$/.exec(line);
    if (node) {
      const id = Number(node[1]);
      if (labels.has(id)) throw new Error("NPC hint contains a duplicate node");
      labels.set(id, node[2]);
    } else if (edge) edges.push([Number(edge[1]), Number(edge[2])]);
    else throw new Error("NPC hint contains an unsupported DOT declaration");
  }
  if (labels.size < 2 || labels.size > 64 || edges.length > 2_000 || candidate.length !== labels.size) {
    throw new Error("NPC graph or candidate length exceeds its bounds");
  }
  const nodes = [...labels.keys()];
  const positions = new Map(nodes.map((id, index) => [id, index]));
  const neighbors = nodes.map(() => new Set<number>());
  for (const [a, b] of edges) {
    const from = positions.get(a), to = positions.get(b);
    if (from === undefined || to === undefined || from === to) throw new Error("NPC hint has an invalid edge");
    neighbors[from].add(to); neighbors[to].add(from);
  }
  const count = (text: string) => [...text].sort().join("");
  if (count(candidate) !== count([...labels.values()].join(""))) return { nodes: labels.size, edges: edges.length,
    statesExplored: 0, path: null, candidate, graphValid: false, truncated: false, passwordVerified: false };
  const visited = new Uint8Array(nodes.length);
  const path: number[] = [];
  let statesExplored = 0;
  let truncated = false;
  const walk = (position: number, index: number): boolean => {
    if (signal?.aborted) throw signal.reason;
    if (statesExplored >= maxStates) { truncated = true; return false; }
    statesExplored++;
    visited[position] = 1;
    path.push(position);
    if (index === candidate.length - 1) return true;
    for (const next of neighbors[position]) {
      if (visited[next] || labels.get(nodes[next]) !== candidate[index + 1]) continue;
      if (walk(next, index + 1)) return true;
      if (truncated) break;
    }
    visited[position] = 0;
    path.pop();
    return false;
  };
  for (let start = 0; start < nodes.length && !truncated; start++) {
    if (labels.get(nodes[start]) !== candidate[0]) continue;
    if (walk(start, 0)) return { nodes: nodes.length, edges: edges.length, statesExplored, path: path.map((at) => nodes[at]),
      candidate, graphValid: true, truncated: false, passwordVerified: false };
  }
  return { nodes: nodes.length, edges: edges.length, statesExplored, path: null, candidate, graphValid: false,
    truncated, passwordVerified: false };
}
