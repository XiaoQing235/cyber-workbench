import { useState } from "react";
import { cellText, toCsv, type Cell, type Table } from "../../core/table";
import { downloadBlob } from "../download";

const BUTTON = "rounded border border-slate-300 bg-white px-2 py-0.5 text-xs hover:bg-slate-100";
const SHOWN = 500;

function CellView({ cell }: { cell: Cell }) {
  if (cell === null) return <span className="text-slate-400 italic">NULL</span>;
  if (typeof cell === "object") {
    return (
      <span className="text-violet-700">
        BLOB {cell.size.toLocaleString()} B <span className="text-slate-500">{cell.blob}</span>
      </span>
    );
  }
  const text = String(cell);
  return <>{text.length > 300 ? `${text.slice(0, 300)}…` : text}</>;
}

export function TableView({ table }: { table: Table }) {
  const [all, setAll] = useState(false);
  const rows = all ? table.rows : table.rows.slice(0, SHOWN);
  return (
    <div className="flex flex-col gap-1">
      <div className="flex flex-wrap items-baseline gap-2 text-xs">
        {table.title && <span className="font-mono text-slate-700">{table.title}</span>}
        <span className="text-slate-500">
          {table.rows.length.toLocaleString()} row(s){table.truncated && " (cut at the row limit)"}
        </span>
        <button
          className={`${BUTTON} ml-auto`}
          onClick={() => downloadBlob(new Blob([toCsv(table)], { type: "text/csv" }), `${(table.title ?? "table").replace(/[^\w.-]+/g, "_").slice(0, 40)}.csv`)}
        >
          CSV
        </button>
      </div>
      <div className="max-h-96 overflow-auto rounded border border-slate-200 bg-white">
        <table className="w-full border-collapse font-mono text-xs">
          <thead className="sticky top-0 bg-slate-100">
            <tr>
              {table.columns.map((column, i) => (
                <th key={i} className="border-b border-slate-200 px-2 py-1 text-left font-semibold">
                  {column}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row, r) => (
              <tr key={r} className="odd:bg-white even:bg-slate-50">
                {row.map((cell, c) => (
                  <td
                    key={c}
                    className={`max-w-md truncate border-b border-slate-100 px-2 py-0.5 align-top ${typeof cell === "number" ? "text-right" : ""}`}
                    title={cellText(cell).slice(0, 2000)}
                  >
                    <CellView cell={cell} />
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!all && table.rows.length > SHOWN && (
        <button className={`${BUTTON} self-start`} onClick={() => setAll(true)}>
          Show all {table.rows.length.toLocaleString()} rows
        </button>
      )}
    </div>
  );
}
