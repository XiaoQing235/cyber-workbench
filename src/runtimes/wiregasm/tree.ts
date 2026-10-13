import type { ProtoTree, Vector } from "@goodtools/wiregasm";

export interface TreeNode { label: string; filter: string; children: TreeNode[] }

export function projectTree(vector: Vector<ProtoTree>, depth: number, budget: { nodes: number }): TreeNode[] {
  const nodes: TreeNode[] = [];
  try {
    for (let index = 0; index < vector.size() && budget.nodes > 0; index++) {
      const node = vector.get(index);
      budget.nodes--;
      const descend = depth < 4 && budget.nodes > 0;
      const children = descend ? projectTree(node.tree, depth + 1, budget) : [];
      if (!descend) node.tree.delete();
      nodes.push({ label: node.label.slice(0, 512), filter: node.filter.slice(0, 256),
        children });
    }
  } finally {
    vector.delete();
  }
  return nodes;
}
