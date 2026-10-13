/** Tabular structured data (query results, header listings), rendered by the table viewer. */

export type Cell = string | number | boolean | null | { blob: string; size: number };

export interface Table {
  title?: string;
  columns: string[];
  rows: Cell[][];
  /** More rows exist than are included. */
  truncated?: boolean;
}

export function isTable(value: unknown): value is Table {
  return typeof value === "object" && value !== null && Array.isArray((value as Table).columns) && Array.isArray((value as Table).rows);
}

export function cellText(cell: Cell): string {
  if (cell === null) return "";
  if (typeof cell === "object") return cell.blob;
  return String(cell);
}

export function toCsv(table: Table): string {
  const quote = (text: string) => (/[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text);
  return [table.columns, ...table.rows.map((row) => row.map(cellText))].map((row) => row.map(quote).join(",")).join("\r\n") + "\r\n";
}
