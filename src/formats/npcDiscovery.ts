interface TrieNode {
  children: Map<string, TrieNode>;
  word: boolean;
}

interface Graph {
  labels: string[];
  neighbors: number[][];
}

export interface NpcDiscoveryReport {
  nodes: number;
  dictionaryWords: number;
  compatibleWords: number;
  statesExplored: number;
  candidates: string[];
  truncated: boolean;
}

function parseGraph(dot: string): Graph {
  if (dot.length > 16_384) throw new Error("NPC graph exceeds 16 KiB");
  const lines = dot.trim().split(/\r?\n/).map((line) => line.trim());
  if (lines[0] !== "graph {" || lines.at(-1) !== "}") throw new Error("NPC hint is not an undirected DOT graph");
  const labels = new Map<number, string>();
  const edges: [number, number][] = [];
  for (const line of lines.slice(1, -1)) {
    const node = /^(\d{1,10}) \[label=([a-z])\];$/.exec(line);
    const edge = /^(\d{1,10}) -- (\d{1,10});$/.exec(line);
    if (node) {
      const id = Number(node[1]);
      if (labels.has(id)) throw new Error("NPC hint has duplicate nodes");
      labels.set(id, node[2]);
    } else if (edge) edges.push([Number(edge[1]), Number(edge[2])]);
    else throw new Error("NPC hint contains an unsupported DOT declaration");
  }
  if (labels.size < 2 || labels.size > 64 || edges.length > 2_000) throw new Error("NPC graph exceeds its node or edge budget");
  const ids = [...labels.keys()];
  const positions = new Map(ids.map((id, index) => [id, index]));
  const neighbors = ids.map(() => new Set<number>());
  for (const [first, second] of edges) {
    const from = positions.get(first), to = positions.get(second);
    if (from === undefined || to === undefined || from === to) throw new Error("NPC hint has an invalid edge");
    neighbors[from].add(to);
    neighbors[to].add(from);
  }
  return { labels: [...labels.values()], neighbors: neighbors.map((set) => [...set]) };
}

export function discoverNpcPasswords(dot: string, dictionary: string, maxStates: number, maxCandidates: number, signal?: AbortSignal): NpcDiscoveryReport {
  if (dictionary.length > 64 * 1024 || !Number.isSafeInteger(maxStates) || maxStates < 1 || maxStates > 1_000_000 ||
    !Number.isSafeInteger(maxCandidates) || maxCandidates < 1 || maxCandidates > 64) throw new Error("NPC word list or search budget is invalid");
  const graph = parseGraph(dot);
  const words = [...new Set(dictionary.toLowerCase().replace(/[^a-z]/g, " ").split(/\s+/).filter(Boolean))].sort();
  if (words.length > 4_096) throw new Error("NPC dictionary exceeds 4,096 distinct words");
  const target = new Map<string, number>();
  for (const letter of graph.labels) target.set(letter, (target.get(letter) ?? 0) + 1);
  const eligible = words.filter((word) => {
    if (word.length > graph.labels.length) return false;
    const count = new Map<string, number>();
    for (const letter of word) count.set(letter, (count.get(letter) ?? 0) + 1);
    return [...count].every(([letter, amount]) => amount <= (target.get(letter) ?? 0));
  });
  const root: TrieNode = { children: new Map(), word: false };
  for (const word of eligible) {
    let node = root;
    for (const letter of word) {
      let next = node.children.get(letter);
      if (!next) { next = { children: new Map(), word: false }; node.children.set(letter, next); }
      node = next;
    }
    node.word = true;
  }
  const full = (1n << BigInt(graph.labels.length)) - 1n;
  const frontier: { last: number; used: bigint; phrase: string }[] = [{ last: -1, used: 0n, phrase: "" }];
  const candidates: string[] = [];
  const seen = new Set<string>();
  let statesExplored = 0;
  let processed = 0;
  let truncated = false;

  function walk(position: number, used: bigint, trie: TrieNode, prefix: string, phrase: string): void {
    if (statesExplored >= maxStates || frontier.length - processed > 150_000) { truncated = true; return; }
    if ((statesExplored & 0xff) === 0 && signal?.aborted) throw signal.reason;
    const next = trie.children.get(graph.labels[position]);
    if (!next) return;
    statesExplored++;
    const mask = used | (1n << BigInt(position));
    const spelling = prefix + graph.labels[position];
    const password = phrase + spelling;
    if (next.word) {
      if (mask === full) {
        if (!seen.has(password)) { seen.add(password); candidates.push(password); }
      } else frontier.push({ last: position, used: mask, phrase: password });
    }
    if (mask !== full && !truncated) {
      for (const neighbor of graph.neighbors[position]) {
        if ((mask & (1n << BigInt(neighbor))) === 0n) walk(neighbor, mask, next, spelling, phrase);
        if (truncated || candidates.length >= maxCandidates) return;
      }
    }
  }

  for (let index = 0; index < frontier.length && !truncated && candidates.length < maxCandidates; index++) {
    const state = frontier[index];
    processed = index + 1;
    const available = state.last < 0 ? graph.labels.map((_, position) => position) : graph.neighbors[state.last];
    for (const position of available) {
      if ((state.used & (1n << BigInt(position))) === 0n) walk(position, state.used, root, "", state.phrase);
      if (truncated || candidates.length >= maxCandidates) break;
    }
  }
  return { nodes: graph.labels.length, dictionaryWords: words.length, compatibleWords: eligible.length,
    statesExplored, candidates, truncated };
}