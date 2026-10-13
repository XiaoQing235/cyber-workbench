import { useEffect, useMemo, useRef, useState } from "react";
import type { Suggestion } from "../../core/analysis/finding";
import type { ByteSource } from "../../core/bytes/ByteSource";
import type { SourceSpan } from "../../core/bytes/span";
import { deepestAt, joinPath, type FieldNode, type StructReport } from "../../formats/ksy/tree";
import { downloadBlob } from "../download";
import { FindingsList } from "./FindingsList";
import { HexView } from "./HexView";

const MAX_ROWS = 5000;
const BUTTON = "rounded border border-slate-300 bg-white px-2 py-0.5 text-xs hover:bg-slate-100";
const hex = (value: number) => `0x${value.toString(16)}`;

interface Row {
  node: FieldNode;
  path: string;
  depth: number;
}

/** Paths of the nodes containing `path`, outermost first: a.b[2].c → a, a.b, a.b[2]. */
function ancestors(path: string): string[] {
  const out: string[] = [];
  for (let i = 1; i < path.length; i++) if (path[i] === "." || path[i] === "[") out.push(path.slice(0, i));
  return out;
}

function find(root: FieldNode, path: string): FieldNode | null {
  let found: FieldNode | null = null;
  const visit = (node: FieldNode, prefix: string) => {
    for (const child of node.children ?? []) {
      const childPath = joinPath(prefix, child.name);
      if (childPath === path) found = child;
      else if (path.startsWith(childPath)) visit(child, childPath);
      if (found) return;
    }
  };
  visit(root, "");
  return found;
}

function editableText(node: FieldNode): string | null {
  if (!node.encoding || node.offset === null) return null;
  if (node.encoding.kind === "int") return node.label ?? String(node.value ?? "");
  if (node.encoding.kind === "bytes" && node.length > 256) return null;
  return String(node.value ?? "");
}

interface Props {
  report: StructReport;
  /** The parsed bytes, for the linked hex view. */
  source?: ByteSource;
  /** Runs a suggestion on the parsed artifact. */
  onSuggest?: (suggestion: Suggestion) => void;
  onShowSpan?: (span: SourceSpan) => void;
  onOpenInPipeline?: (suggestion: Suggestion) => void;
}

/** Field tree linked both ways to a hex view, with in-place edits through struct.set-field. */
export function StructView({ report, source, onSuggest, onShowSpan, onOpenInPipeline }: Props) {
  const [expanded, setExpanded] = useState<Set<string>>(
    () => new Set((report.root.children ?? []).filter((child) => child.children?.length).map((child) => child.name)),
  );
  const [selected, setSelected] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const treeRef = useRef<HTMLDivElement>(null);
  const scrollTo = useRef<string | null>(null);

  const rows = useMemo(() => {
    const out: Row[] = [];
    const visit = (node: FieldNode, path: string, depth: number) => {
      for (const child of node.children ?? []) {
        if (out.length >= MAX_ROWS) return;
        const childPath = joinPath(path, child.name);
        out.push({ node: child, path: childPath, depth });
        if (child.children?.length && expanded.has(childPath)) visit(child, childPath, depth + 1);
      }
    };
    visit(report.root, "", 0);
    return out;
  }, [report, expanded]);

  const selectedNode = selected ? find(report.root, selected) : null;
  const highlight = useMemo<SourceSpan | undefined>(
    () => (selectedNode && selectedNode.offset !== null ? { offset: selectedNode.offset, length: Math.max(1, selectedNode.length) } : undefined),
    [selectedNode],
  );
  const editable = selectedNode && onSuggest ? editableText(selectedNode) : null;

  useEffect(() => {
    if (!scrollTo.current) return;
    treeRef.current?.querySelector(`[data-path="${CSS.escape(scrollTo.current)}"]`)?.scrollIntoView({ block: "nearest" });
    scrollTo.current = null;
  });

  const select = (path: string | null, reveal = false) => {
    setSelected(path);
    if (!path) return;
    const node = find(report.root, path);
    setDraft(node ? (editableText(node) ?? "") : "");
    if (reveal) {
      setExpanded((current) => new Set([...current, ...ancestors(path)]));
      scrollTo.current = path;
    }
  };

  const toggle = (path: string) =>
    setExpanded((current) => {
      const next = new Set(current);
      if (!next.delete(path)) next.add(path);
      return next;
    });

  const apply = () => {
    if (!selected || !onSuggest) return;
    onSuggest({
      operationId: "struct.set-field",
      params: { ...report.params, path: selected, value: draft, recompute: true },
      label: `Set ${selected}`,
      then: [{ operationId: "struct.parse", params: report.params }],
    });
  };

  const exportSchema = () => downloadBlob(new Blob([report.schema], { type: "text/yaml" }), `${report.root.name}.ksy`);

  const [exportProblem, setExportProblem] = useState<string | null>(null);
  const exportCode = async (language: "python" | "javascript") => {
    setExportProblem(null);
    try {
      // The generator and YAML parser are only downloaded when exporting.
      const { exportParser } = await import("../../formats/ksy/codegen");
      const { code, fileName } = exportParser(report.schema, language);
      downloadBlob(new Blob([code], { type: "text/plain" }), fileName);
    } catch (error) {
      setExportProblem(error instanceof Error ? error.message : String(error));
    }
  };

  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span className="font-medium">{report.title}</span>
        <span className="text-slate-500">
          {report.parsedBytes.toLocaleString()} of {report.totalBytes.toLocaleString()} bytes parsed
        </span>
        <span className="ml-auto flex gap-1">
          <button className={BUTTON} onClick={() => setExpanded(new Set(rows.filter((row) => row.node.children?.length).map((row) => row.path)))}>
            Expand shown
          </button>
          <button className={BUTTON} onClick={() => setExpanded(new Set())}>
            Collapse
          </button>
          <button className={BUTTON} onClick={() => void navigator.clipboard.writeText(report.schema)}>
            Copy .ksy
          </button>
          <button className={BUTTON} onClick={exportSchema}>
            Export .ksy
          </button>
          <button className={BUTTON} onClick={() => void exportCode("python")} title="Standalone Python 3 parser for this schema">
            Python
          </button>
          <button className={BUTTON} onClick={() => void exportCode("javascript")} title="Dependency-free ES module parser for this schema">
            JavaScript
          </button>
        </span>
      </div>
      {exportProblem && <p className="text-sm text-red-700">Export failed: {exportProblem}</p>}
      {report.error && (
        <p className="text-sm text-red-700">
          Stopped{report.error.offset !== null && ` at ${hex(report.error.offset)}`} in {report.error.path || report.root.name}: {report.error.message}{" "}
          {report.error.path && (
            <button className={BUTTON} onClick={() => select(report.error!.path, true)}>
              Show
            </button>
          )}
        </p>
      )}
      {report.findings.length > 0 && (
        <FindingsList findings={report.findings} onSuggest={onSuggest} onShowSpan={onShowSpan} onOpenInPipeline={onOpenInPipeline} />
      )}

      <div className="grid gap-2 xl:grid-cols-[minmax(0,1fr)_auto]">
        <div className="flex min-w-0 flex-col gap-1">
          {selectedNode && (
            <div className="flex flex-wrap items-center gap-2 rounded border border-slate-200 bg-white px-2 py-1 text-xs">
              <span className="font-mono">{selected}</span>
              <span className="text-slate-500">
                {selectedNode.type}
                {selectedNode.offset !== null && ` · ${hex(selectedNode.offset)}–${hex(selectedNode.offset + selectedNode.length)} (${selectedNode.length} bytes)`}
              </span>
              {selectedNode.doc && <span className="text-slate-500">· {selectedNode.doc}</span>}
              {editable !== null && (
                <form
                  className="ml-auto flex items-center gap-1"
                  onSubmit={(event) => {
                    event.preventDefault();
                    apply();
                  }}
                >
                  <input
                    aria-label="New value"
                    className="w-56 rounded border border-slate-300 px-1 py-0.5 font-mono"
                    value={draft}
                    onChange={(event) => setDraft(event.target.value)}
                  />
                  <button type="submit" className={BUTTON} disabled={draft === editable} title="Writes the value in place, recomputes declared checksums, and re-parses the result">
                    Set field
                  </button>
                </form>
              )}
            </div>
          )}
          <div ref={treeRef} className="max-h-[28rem] overflow-auto rounded border border-slate-200 bg-white py-1 font-mono text-xs" role="tree">
            {rows.map(({ node, path, depth }) => {
              const open = expanded.has(path);
              const parent = Boolean(node.children?.length);
              return (
                <div
                  key={path}
                  data-path={path}
                  role="treeitem"
                  aria-selected={selected === path}
                  aria-expanded={parent ? open : undefined}
                  title={node.doc}
                  className={`flex cursor-pointer items-baseline gap-2 px-2 leading-5 ${selected === path ? "bg-amber-100" : "hover:bg-slate-100"}`}
                  onClick={() => select(path)}
                >
                  <span className="flex w-44 shrink-0 items-baseline gap-1 truncate" style={{ paddingLeft: depth * 12 }}>
                    {parent ? (
                      <button
                        className="w-3 shrink-0 text-slate-500"
                        aria-label={open ? "Collapse" : "Expand"}
                        onClick={(event) => {
                          event.stopPropagation();
                          toggle(path);
                        }}
                      >
                        {open ? "▾" : "▸"}
                      </button>
                    ) : (
                      <span className="w-3 shrink-0" />
                    )}
                    <span className={node.instance ? "text-violet-700 italic" : node.error ? "text-red-700" : ""}>{node.name}</span>
                  </span>
                  <span className="w-16 shrink-0 truncate text-slate-500">{node.type}</span>
                  <span className="w-14 shrink-0 text-right text-slate-400">{node.offset === null ? "—" : hex(node.offset)}</span>
                  <span className="w-10 shrink-0 text-right text-slate-400">{node.length.toLocaleString()}</span>
                  <span className="min-w-0 flex-1 truncate" title={node.display}>
                    {node.display}
                    {node.count !== undefined && node.children && node.children.length < node.count && (
                      <span className="text-slate-400"> (first {node.children.length} shown)</span>
                    )}
                    {node.checksum && (
                      <span className={node.checksum.ok ? "text-emerald-700" : "text-red-700"}>
                        {node.checksum.ok ? ` ✓ ${node.checksum.algorithm}` : ` ✗ ${node.checksum.algorithm} is ${hex(node.checksum.computed)}`}
                      </span>
                    )}
                    {node.error && <span className="text-red-700"> ⚠ {node.error}</span>}
                  </span>
                </div>
              );
            })}
            {rows.length >= MAX_ROWS && <p className="px-2 text-slate-500">Showing the first {MAX_ROWS.toLocaleString()} rows; collapse some to see others.</p>}
            {report.truncated && <p className="px-2 text-slate-500">The tree keeps the first 20,000 fields; parsing continued past them.</p>}
          </div>
        </div>
        {source && <HexView source={source} highlight={highlight} onSelectOffset={(offset) => select(deepestAt(report.root, offset), true)} />}
      </div>
    </div>
  );
}
