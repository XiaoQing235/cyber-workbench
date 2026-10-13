import { useState } from "react";
import type { Finding, Suggestion } from "../../core/analysis/finding";
import type { SourceSpan } from "../../core/bytes/span";

const SEVERITY_STYLE: Record<Finding["severity"], string> = {
  strong: "border-red-300 bg-red-50 text-red-900",
  medium: "border-amber-300 bg-amber-50 text-amber-900",
  weak: "border-slate-200 bg-white text-slate-700",
};

export function isFindingList(value: unknown): value is Finding[] {
  return (
    Array.isArray(value) &&
    value.every((item) => typeof item === "object" && item !== null && "severity" in item && "message" in item)
  );
}

interface Props {
  findings: readonly Finding[];
  onSuggest?: (suggestion: Suggestion) => void;
  /** Shows a finding's byte range in the analysed data. */
  onShowSpan?: (span: SourceSpan) => void;
  /** Turns a suggestion's steps into pipeline nodes for editing. */
  onOpenInPipeline?: (suggestion: Suggestion) => void;
}

const ACTION = "rounded border border-current px-2 py-0.5 text-xs hover:bg-white/60";

function SpanLink({ span, onShowSpan }: { span: SourceSpan; onShowSpan?: (span: SourceSpan) => void }) {
  const location = `@0x${span.offset.toString(16)} (${span.length} B)`;
  return onShowSpan ? (
    <button
      className="ml-2 font-mono text-xs underline decoration-dotted opacity-70 hover:opacity-100"
      title="Show these bytes in the hex view"
      onClick={() => onShowSpan(span)}
    >
      {location}
    </button>
  ) : (
    <span className="ml-2 font-mono text-xs opacity-60">{location}</span>
  );
}

export function FindingsList({ findings, onSuggest, onShowSpan, onOpenInPipeline }: Props) {
  const [dismissed, setDismissed] = useState<ReadonlySet<string>>(new Set());
  if (findings.length === 0) return <p className="text-sm text-slate-500">No findings.</p>;
  const visible = findings.filter((finding) => !dismissed.has(finding.id));
  return (
    <ul className="flex flex-col gap-1">
      {visible.map(({ id, ruleId, severity, message, span, evidence, suggestion }) => (
        <li
          key={id}
          className={`flex flex-wrap items-center justify-between gap-2 rounded border px-2 py-1 text-sm ${SEVERITY_STYLE[severity]}`}
        >
          <span className="min-w-0 flex-1">
            <span className="mr-2 text-xs font-semibold uppercase opacity-70">{severity}</span>
            {message}
            {span && <SpanLink span={span} onShowSpan={onShowSpan} />}
          </span>
          <span className="flex flex-wrap gap-1">
            {suggestion && onSuggest && (
              <button className={ACTION} onClick={() => onSuggest(suggestion)}>
                {suggestion.label} →
              </button>
            )}
            {suggestion && onOpenInPipeline && (
              <button className={ACTION} title="Edit these steps as pipeline nodes" onClick={() => onOpenInPipeline(suggestion)}>
                Open in pipeline
              </button>
            )}
            <button
              className={`${ACTION} opacity-60`}
              title="Reject: hide this finding"
              aria-label={`Dismiss: ${message}`}
              onClick={() => setDismissed(new Set([...dismissed, id]))}
            >
              Dismiss
            </button>
          </span>
          {(ruleId || (evidence && evidence.length > 0)) && (
            <details className="basis-full text-xs">
              <summary className="cursor-pointer opacity-70">
                Why?{ruleId && <span className="ml-1 font-mono">rule {ruleId}</span>}
                {evidence && ` · ${evidence.length} piece${evidence.length === 1 ? "" : "s"} of evidence`}
              </summary>
              <ul className="mt-1 flex flex-col gap-0.5 border-l-2 border-current/30 pl-2">
                {evidence?.map((item, index) => (
                  <li key={index}>
                    <span className="font-semibold uppercase opacity-70">{item.tier}</span> {item.kind}: {item.detail}
                    {item.span && <SpanLink span={item.span} onShowSpan={onShowSpan} />}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </li>
      ))}
      {dismissed.size > 0 && (
        <li className="text-xs text-slate-500">
          {dismissed.size} dismissed ·{" "}
          <button className="underline" onClick={() => setDismissed(new Set())}>
            show again
          </button>
        </li>
      )}
    </ul>
  );
}
