import { Fragment, useEffect, useRef, useState, type UIEvent } from "react";
import type { ByteSource } from "../../core/bytes/ByteSource";
import type { SourceSpan } from "../../core/bytes/span";

const BYTES_PER_ROW = 16;
const ROW_HEIGHT = 20;
const VISIBLE_ROWS = 16;
// Browsers cap element height (~17–33M px), so very large files map scroll position proportionally.
const MAX_SCROLL_HEIGHT = 8_000_000;
const MARK = "bg-amber-200 text-slate-900";

function printable(byte: number): string {
  return byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : ".";
}

const hex2 = (byte: number) => byte.toString(16).padStart(2, "0");

interface Props {
  source: ByteSource;
  /** Range to highlight; the view scrolls to it each time a new object is passed. */
  highlight?: SourceSpan;
  /** Makes bytes clickable, e.g. to select the structure field that contains them. */
  onSelectOffset?: (offset: number) => void;
}

/** Virtualised hex view. Only the visible window is ever read from the source. */
export function HexView({ source, highlight, onSelectOffset }: Props) {
  const totalRows = Math.max(1, Math.ceil(source.size / BYTES_PER_ROW));
  const viewportHeight = VISIBLE_ROWS * ROW_HEIGHT;
  const contentHeight = Math.max(viewportHeight, Math.min(totalRows * ROW_HEIGHT, MAX_SCROLL_HEIGHT));
  const maxFirstRow = Math.max(0, totalRows - VISIBLE_ROWS);

  const [firstRow, setFirstRow] = useState(0);
  const [view, setView] = useState<{ firstRow: number; bytes: Uint8Array } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  // Scroll positions map to rows with rounding on huge files, so the scroll event we cause is not re-mapped.
  const ignoreNextScroll = useRef(false);

  useEffect(() => {
    const container = containerRef.current;
    if (!highlight || !container) return;
    const row = Math.min(maxFirstRow, Math.max(0, Math.floor(highlight.offset / BYTES_PER_ROW) - 2));
    setFirstRow(row);
    const scrollTop = maxFirstRow > 0 ? (row / maxFirstRow) * (contentHeight - viewportHeight) : 0;
    if (Math.abs(container.scrollTop - scrollTop) >= 1) {
      ignoreNextScroll.current = true;
      container.scrollTop = scrollTop;
    }
    container.scrollIntoView({ block: "nearest", behavior: "smooth" });
  }, [highlight, maxFirstRow, contentHeight, viewportHeight]);

  useEffect(() => {
    let cancelled = false;
    source.read(firstRow * BYTES_PER_ROW, VISIBLE_ROWS * BYTES_PER_ROW).then(
      (bytes) => {
        if (!cancelled) setView({ firstRow, bytes });
      },
      (reason: unknown) => {
        if (!cancelled) setError(String(reason));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [source, firstRow]);

  const onScroll = (event: UIEvent<HTMLDivElement>) => {
    if (ignoreNextScroll.current) {
      ignoreNextScroll.current = false;
      return;
    }
    const maxScrollTop = contentHeight - viewportHeight;
    const ratio = maxScrollTop > 0 ? event.currentTarget.scrollTop / maxScrollTop : 0;
    setFirstRow(Math.min(maxFirstRow, Math.round(ratio * maxFirstRow)));
  };

  if (error) return <p className="p-3 text-sm text-red-700">Could not read data: {error}</p>;
  if (source.size === 0) return <p className="p-3 text-sm text-slate-500">(empty)</p>;

  const rows = [];
  if (view) {
    const markEnd = highlight ? highlight.offset + highlight.length : 0;
    for (let row = 0; row < VISIBLE_ROWS; row++) {
      const start = row * BYTES_PER_ROW;
      if (start >= view.bytes.length) break;
      const bytes = view.bytes.subarray(start, start + BYTES_PER_ROW);
      const offset = (view.firstRow + row) * BYTES_PER_ROW;
      const separator = (i: number) => (i === 7 ? "  " : " ");
      const marked = (i: number) => highlight !== undefined && offset + i >= highlight.offset && offset + i < markEnd;
      const hit = onSelectOffset !== undefined || (highlight !== undefined && offset < markEnd && offset + bytes.length > highlight.offset);
      const pick = (i: number) => (onSelectOffset ? () => onSelectOffset(offset + i) : undefined);
      const cell = (i: number) => `${marked(i) ? MARK : ""}${onSelectOffset ? " cursor-pointer hover:bg-sky-100" : ""}` || undefined;
      rows.push(
        <div key={offset} className="flex gap-4 whitespace-pre" style={{ height: ROW_HEIGHT }}>
          <span className="text-slate-400">{offset.toString(16).padStart(8, "0")}</span>
          <span className="w-[50ch]">
            {hit
              ? Array.from(bytes, (b, i) => (
                  <Fragment key={i}>
                    <span className={cell(i)} onClick={pick(i)}>
                      {hex2(b)}
                    </span>
                    {separator(i)}
                  </Fragment>
                ))
              : Array.from(bytes, (b, i) => hex2(b) + separator(i)).join("")}
          </span>
          <span className="text-slate-600">
            {hit
              ? Array.from(bytes, (b, i) => (
                  <span key={i} className={cell(i)} onClick={pick(i)}>
                    {printable(b)}
                  </span>
                ))
              : Array.from(bytes, printable).join("")}
          </span>
        </div>,
      );
    }
  }

  return (
    <div
      ref={containerRef}
      className="overflow-y-auto rounded border border-slate-200 bg-white px-3 font-mono text-xs leading-5"
      style={{ height: viewportHeight + 2 }}
      onScroll={onScroll}
    >
      <div style={{ height: contentHeight }}>
        <div className="sticky top-0">{rows}</div>
      </div>
    </div>
  );
}
