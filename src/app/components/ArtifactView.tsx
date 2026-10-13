import { useEffect, useState } from "react";
import type { Suggestion } from "../../core/analysis/finding";
import type { Artifact } from "../../core/artifact/store";
import type { ByteSource } from "../../core/bytes/ByteSource";
import type { SourceSpan } from "../../core/bytes/span";
import { isTable, type Table } from "../../core/table";
import { describeValue, type Value } from "../../core/value";
import { sniffImageFormat } from "../../formats/image";
import { isStructReport } from "../../formats/ksy/tree";
import { downloadArtifact } from "../download";
import { store } from "../services";
import { FindingsList, isFindingList } from "./FindingsList";
import { HexView } from "./HexView";
import { ImagePreview } from "./ImagePreview";
import { LineageView } from "./Recipes";
import { StructView } from "./StructView";
import { TableView } from "./TableView";

const MAX_TEXT_DISPLAY = 200_000;
const PREVIEW_BYTES = 4096;
const BUTTON = "rounded border border-slate-300 bg-white px-2 py-1 text-xs hover:bg-slate-100";

function TextBody({ text }: { text: string }) {
  const truncated = text.length > MAX_TEXT_DISPLAY;
  return (
    <div className="flex flex-col gap-1">
      <textarea
        readOnly
        className="h-40 w-full resize-y rounded border border-slate-200 bg-white p-2 font-mono text-xs"
        value={truncated ? text.slice(0, MAX_TEXT_DISPLAY) : text}
      />
      {truncated && (
        <p className="text-xs text-amber-700">
          Showing the first {MAX_TEXT_DISPLAY.toLocaleString()} characters. Download for the full text.
        </p>
      )}
    </div>
  );
}

type BytesTab = "hex" | "preview" | "image";
const TAB_LABEL: Record<BytesTab, string> = { hex: "Hex", preview: "UTF-8 preview", image: "Image" };

const QUICK_ANALYSES: readonly Suggestion[] = [
  { operationId: "file.detect", label: "Detect type", then: [] },
  { operationId: "strings.extract", label: "Strings", then: [] },
  { operationId: "decode.auto", label: "Auto-decode", then: [] },
];

interface BodyActions {
  /** For reports: run a suggestion on the artifact the report describes. */
  onSuggest?: (suggestion: Suggestion) => void;
  /** For reports: show a byte range of the artifact the report describes. */
  onShowSpan?: (span: SourceSpan) => void;
  /** For reports: edit a suggestion's steps as pipeline nodes bound to the described artifact. */
  onOpenInPipeline?: (suggestion: Suggestion) => void;
  /** Run a suggestion on this artifact itself. */
  onSuggestHere?: (suggestion: Suggestion) => void;
  /** Byte range to reveal in the hex tab. */
  focus?: SourceSpan;
  /** For reports: the bytes of the artifact the report describes. */
  describedSource?: ByteSource;
}

function BytesBody({ source, focus, onSuggestHere }: { source: ByteSource } & BodyActions) {
  const [chosenTab, setChosenTab] = useState<BytesTab | null>(null);
  const [isImage, setIsImage] = useState(false);
  const [preview, setPreview] = useState<string | null>(null);
  const tab: BytesTab = chosenTab ?? (isImage ? "image" : "hex");

  useEffect(() => {
    if (focus) setChosenTab("hex");
  }, [focus]);

  useEffect(() => {
    let cancelled = false;
    void source.read(0, 8).then((head) => {
      if (!cancelled) setIsImage(sniffImageFormat(head) !== null);
    });
    return () => {
      cancelled = true;
    };
  }, [source]);

  useEffect(() => {
    if (tab !== "preview") return;
    let cancelled = false;
    void source.read(0, PREVIEW_BYTES).then((bytes) => {
      if (!cancelled) setPreview(new TextDecoder("utf-8", { fatal: false }).decode(bytes));
    });
    return () => {
      cancelled = true;
    };
  }, [source, tab]);

  const tabs: BytesTab[] = isImage ? ["image", "hex", "preview"] : ["hex", "preview"];
  return (
    <div className="flex flex-col gap-2">
      <div className="flex flex-wrap items-center gap-1 text-xs">
        {tabs.map((name) => (
          <button
            key={name}
            className={`rounded px-2 py-0.5 ${tab === name ? "bg-slate-800 text-white" : "bg-slate-200"}`}
            onClick={() => setChosenTab(name)}
          >
            {TAB_LABEL[name]}
          </button>
        ))}
        {onSuggestHere && (
          <span className="ml-auto flex items-center gap-1 text-slate-500">
            Analyse:
            {QUICK_ANALYSES.map((suggestion) => (
              <button key={suggestion.operationId} className={BUTTON} onClick={() => onSuggestHere(suggestion)}>
                {suggestion.label}
              </button>
            ))}
          </span>
        )}
      </div>
      {tab === "image" && <ImagePreview source={source} onExtract={onSuggestHere} />}
      {tab === "hex" && <HexView source={source} highlight={focus} />}
      {tab === "preview" && (
        <div className="flex flex-col gap-1">
          <pre className="max-h-80 overflow-auto rounded border border-slate-200 bg-white p-2 font-mono text-xs whitespace-pre-wrap">
            {preview ?? "Loading…"}
          </pre>
          <p className="text-xs text-slate-500">
            Lossy view of the first {PREVIEW_BYTES} bytes. The data itself is unchanged; use "Decode text" for an
            explicit conversion.
          </p>
        </div>
      )}
    </div>
  );
}

function StructuredBody({ data, onSuggest, onShowSpan, onOpenInPipeline, describedSource }: { data: unknown } & BodyActions) {
  if (isStructReport(data)) {
    return <StructView report={data} source={describedSource} onSuggest={onSuggest} onShowSpan={onShowSpan} onOpenInPipeline={onOpenInPipeline} />;
  }
  const record = typeof data === "object" && data !== null ? (data as Record<string, unknown>) : {};
  const tables = Array.isArray(record.tables) && record.tables.every(isTable) ? (record.tables as Table[]) : isTable(data) ? [data] : [];
  const findings = isFindingList(record.findings) ? record.findings : null;
  const json = (
    <pre className="max-h-80 overflow-auto rounded border border-slate-200 bg-white p-2 text-xs">
      {JSON.stringify(data, (_key, item: unknown) => (typeof item === "bigint" ? item.toString() : item), 2)}
    </pre>
  );
  if (!findings && tables.length === 0) return json;
  return (
    <div className="flex flex-col gap-2">
      {findings && <FindingsList findings={findings} onSuggest={onSuggest} onShowSpan={onShowSpan} onOpenInPipeline={onOpenInPipeline} />}
      {tables.map((table, index) => (
        <TableView key={index} table={table} />
      ))}
      {tables.length === 0 && (
        <details>
          <summary className="cursor-pointer text-xs text-slate-600">Full report</summary>
          {json}
        </details>
      )}
    </div>
  );
}

/** A value without the artifact header, e.g. a pipeline node's output before it is kept. */
export function ValueBody({ value, ...actions }: { value: Value } & BodyActions) {
  switch (value.type) {
    case "bytes":
      return <BytesBody source={value.source} {...actions} />;
    case "text":
      return <TextBody text={value.text} />;
    case "number":
      return (
        <p className="font-mono text-sm">
          {value.value.toString()} <span className="text-slate-500">(0x{value.value.toString(16)})</span>
        </p>
      );
    case "structured":
      return <StructuredBody data={value.data} {...actions} />;
  }
}

interface Props {
  artifact: Artifact;
  /** Omit to hide the button (e.g. when the artifact already is the input). */
  onUseAsInput?: (id: string) => void;
  /** Runs a suggested operation on the artifact with id `inputId`. */
  onSuggest?: (suggestion: Suggestion, inputId: string) => void;
  /** Shows a byte range of the artifact with id `artifactId` in its hex view. */
  onShowSpan?: (span: SourceSpan, artifactId: string) => void;
  onOpenInPipeline?: (suggestion: Suggestion, inputId: string) => void;
  focus?: SourceSpan;
}

export function ArtifactView({ artifact, onUseAsInput, onSuggest, onShowSpan, onOpenInPipeline, focus }: Props) {
  const copyText = artifact.value.type === "text" ? artifact.value.text : null;
  // A report describes the artifact it was produced from.
  const described = artifact.parents[0];
  const describedValue = described ? store.get(described)?.value : undefined;
  return (
    <section className="flex flex-col gap-2 rounded-lg border border-slate-200 bg-slate-50 p-3">
      <header className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-baseline gap-2">
          <span className="font-medium">{artifact.name}</span>
          <span className="text-xs text-slate-500">{describeValue(artifact.value)}</span>
        </div>
        <div className="flex gap-2">
          {onUseAsInput && (
            <button className={BUTTON} onClick={() => onUseAsInput(artifact.id)}>
              Use as input
            </button>
          )}
          {copyText !== null && (
            <button className={BUTTON} onClick={() => void navigator.clipboard.writeText(copyText)}>
              Copy
            </button>
          )}
          <button className={BUTTON} onClick={() => void downloadArtifact(artifact)}>
            Download
          </button>
        </div>
      </header>
      <LineageView artifactId={artifact.id} />
      <ValueBody
        key={artifact.id}
        value={artifact.value}
        onSuggest={onSuggest && described ? (suggestion) => onSuggest(suggestion, described) : undefined}
        onShowSpan={onShowSpan && described ? (span) => onShowSpan(span, described) : undefined}
        onOpenInPipeline={onOpenInPipeline && described ? (suggestion) => onOpenInPipeline(suggestion, described) : undefined}
        onSuggestHere={onSuggest ? (suggestion) => onSuggest(suggestion, artifact.id) : undefined}
        focus={focus}
        describedSource={describedValue?.type === "bytes" ? describedValue.source : undefined}
      />
    </section>
  );
}
