import type { Finding } from "../../core/analysis/finding";
import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import type { Cell, Table } from "../../core/table";
import { bytesFrom, structuredValue } from "../../core/value";
import { freelistPages, parseSqliteHeader, type SqliteHeader } from "../../formats/sqlite";
import { importPack } from "../../runtimes/files";
import type { Database, SqlValue } from "../../runtimes/sqlite";
import { bytesInput, MiB } from "../util";

const COMMON = { runtime: "wasm", deterministic: true, sideEffects: "none", streaming: false } as const;
const MAX_DB = 256 * MiB;
const hex = (value: number) => `0x${value.toString(16)}`;
const SECRET_NAMES = /flag|pass|secret|token|key|cred|hash|salt|auth/i;

export async function openDatabase(inputs: Parameters<typeof bytesInput>[0]): Promise<{ db: Database; bytes: Uint8Array; header: SqliteHeader }> {
  const bytes = await readAll(bytesInput(inputs));
  const header = parseSqliteHeader(bytes);
  if (!header) throw new OperationError("INVALID_INPUT", 'Not an SQLite 3 database (the file must start with "SQLite format 3")');
  const { loadSqlite } = await importPack("SQLite", () => import("../../runtimes/sqlite"));
  const SQL = await loadSqlite();
  try {
    return { db: new SQL.Database(bytes), bytes, header };
  } catch (error) {
    throw new OperationError("INVALID_INPUT", `SQLite could not open the file: ${String(error)}`);
  }
}

function cell(value: SqlValue): Cell {
  if (value instanceof Uint8Array) {
    const preview = Array.from(value.subarray(0, 32), (b) => b.toString(16).padStart(2, "0")).join(" ");
    return { blob: value.length > 32 ? `${preview} …` : preview, size: value.length };
  }
  if (typeof value === "bigint") return Number.isSafeInteger(Number(value)) ? Number(value) : value.toString();
  return value;
}

/** Runs every statement; statements that return columns become tables. */
function runSql(db: Database, sql: string, maxRows: number): { tables: Table[]; statements: number; changed: boolean } {
  const tables: Table[] = [];
  let statements = 0;
  let changed = false;
  // The iterator prepares the next statement while advancing, so a syntax error belongs to the next one.
  let running = false;
  try {
    for (const statement of db.iterateStatements(sql)) {
      statements++;
      running = true;
      try {
        const columns = statement.getColumnNames();
        const rows: Cell[][] = [];
        let truncated = false;
        while (statement.step()) {
          if (rows.length === maxRows) {
            truncated = true;
            break;
          }
          rows.push(statement.get(null, { useBigInt: true }).map(cell));
        }
        if (columns.length > 0) {
          const text = statement.getSQL().trim();
          tables.push({ title: text.length > 120 ? `${text.slice(0, 119)}…` : text, columns, rows, ...(truncated ? { truncated } : {}) });
        } else if (db.getRowsModified() > 0) {
          changed = true;
        }
      } finally {
        statement.free();
        running = false;
      }
    }
  } catch (error) {
    throw new OperationError("INVALID_PARAMS", `Statement ${running ? statements : statements + 1}: ${error instanceof Error ? error.message : String(error)}`);
  }
  return { tables, statements, changed };
}

const quoteName = (name: string) => `"${name.replace(/"/g, '""')}"`;

export const sqliteInspect = defineOperation<Record<string, never>>({
  spec: {
    ...COMMON,
    id: "sqlite.inspect",
    version: "1.0.0",
    title: "Inspect SQLite database",
    category: "Database",
    description: "List tables (with columns and row counts), views, indexes and triggers; check the header and freelist for deleted data.",
    keywords: ["sqlite", "database", "db", "tables", "schema", "deleted", "freelist", "history", "forensics"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    cost: "medium",
    limits: { maxInputBytes: MAX_DB },
  },
  async run(ctx, inputs) {
    const { db, bytes, header } = await openDatabase(inputs);
    try {
      const findings: Finding[] = [];
      const objects = runSql(db, "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type = 'table' DESC, name", 10_000).tables[0]?.rows ?? [];
      const rows: Cell[][] = [];
      for (const [type, name, table, sql] of objects) {
        let count: Cell = null;
        let columns: string[] = [];
        if (type === "table" && typeof name === "string") {
          ctx.throwIfAborted();
          try {
            count = runSql(db, `SELECT count(*) FROM ${quoteName(name)}`, 1).tables[0].rows[0][0];
            columns = runSql(db, `PRAGMA table_info(${quoteName(name)})`, 10_000).tables[0].rows.map((row) => String(row[1]));
          } catch {
            count = "error";
          }
          if (!name.startsWith("sqlite_")) {
            const suspicious = SECRET_NAMES.test(name) || columns.some((column) => SECRET_NAMES.test(column));
            findings.push({
              id: `sqlite.table:${name}`,
              ruleId: "sqlite.table",
              severity: suspicious ? "medium" : "weak",
              message: `Table ${name}: ${count} row(s); columns ${columns.join(", ") || "(none)"}`,
              ...(suspicious ? { evidence: [{ kind: "plausibility", tier: "medium", detail: "A table or column name suggests credentials, keys or flags." }] } : {}),
              suggestion: { operationId: "sqlite.query", params: { sql: `SELECT * FROM ${quoteName(name)} LIMIT 1000;` }, label: "Show rows", then: [] },
            });
          }
        }
        rows.push([type, name, table, count, columns.join(", "), sql]);
      }

      const pageBytes = header.pageSize;
      const free = header.freelistCount > 0 ? freelistPages(bytes, header) : { pages: [] };
      if (header.freelistCount > 0) {
        findings.unshift({
          id: "sqlite.freelist",
          ruleId: "sqlite.freelist",
          severity: "medium",
          message: `${header.freelistCount} free page(s) (${(header.freelistCount * pageBytes).toLocaleString()} bytes): deleted rows often survive there`,
          ...(free.pages.length > 0 ? { span: { offset: (free.pages[0] - 1) * pageBytes, length: pageBytes } } : {}),
          evidence: [
            {
              kind: "structure",
              tier: "medium",
              detail: `SQLite keeps pages freed by DELETE/DROP until VACUUM, usually without wiping them.${free.problem ? ` The freelist is damaged: ${free.problem}.` : ""}`,
            },
          ],
          suggestion: { operationId: "sqlite.free-pages", label: "Extract free pages and list strings", then: [{ operationId: "strings.extract" }] },
        });
      }
      if (header.writeVersion === 2 || header.readVersion === 2) {
        findings.push({
          id: "sqlite.wal",
          ruleId: "sqlite.wal",
          severity: "weak",
          message: "Write-ahead log mode: recent changes may only be in the separate -wal file",
          span: { offset: 18, length: 2 },
        });
      }
      const declared = header.versionValidFor === header.changeCounter ? header.pageCount * pageBytes : null;
      if (declared !== null && bytes.length > declared) {
        findings.push({
          id: "sqlite.trailing",
          ruleId: "sqlite.trailing",
          severity: "medium",
          message: `${(bytes.length - declared).toLocaleString()} byte(s) after the ${header.pageCount} pages the header declares`,
          span: { offset: declared, length: bytes.length - declared },
          suggestion: { operationId: "bytes.slice", params: { offset: declared, length: -1 }, label: "Extract the trailing bytes" },
        });
      } else if (declared !== null && bytes.length < declared) {
        findings.push({
          id: "sqlite.truncated",
          ruleId: "sqlite.truncated",
          severity: "medium",
          message: `The header declares ${header.pageCount} pages (${declared.toLocaleString()} bytes) but the file has ${bytes.length.toLocaleString()}`,
        });
      }

      const headerTable: Table = {
        title: "Header",
        columns: ["field", "value"],
        rows: [
          ["page size", header.pageSize],
          ["pages (header)", header.pageCount],
          ["free pages", header.freelistCount],
          ["first freelist trunk", header.firstFreelistTrunk],
          ["text encoding", header.textEncoding],
          ["journal", header.writeVersion === 2 ? "WAL" : "rollback"],
          ["auto-vacuum", header.vacuum],
          ["user version", header.userVersion],
          ["application id", hex(header.applicationId)],
          ["schema format", header.schemaFormat],
          ["change counter", header.changeCounter],
          ["written by SQLite", header.sqliteVersion],
        ],
      };
      const objectTable: Table = { title: "Schema", columns: ["type", "name", "table", "rows", "columns", "sql"], rows };
      const tableCount = objects.filter(([type, name]) => type === "table" && !String(name).startsWith("sqlite_")).length;
      ctx.diagnostic(`${tableCount} table(s), ${objects.length - tableCount} other schema object(s); ${header.freelistCount} free page(s).`);
      return { report: structuredValue({ kind: "sqlite", tables: [headerTable, objectTable], findings }) };
    } finally {
      db.close();
    }
  },
});

export const sqliteQuery = defineOperation<{ sql: string; maxRows: number }>({
  spec: {
    ...COMMON,
    id: "sqlite.query",
    version: "1.0.0",
    title: "Query SQLite database",
    category: "Database",
    description: "Run SQL against an in-memory copy of the database (the artifact never changes). Each statement that returns rows becomes a table.",
    keywords: ["sqlite", "sql", "query", "select", "database", "db", "table"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "result", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        sql: { type: "string", title: "SQL", default: "SELECT type, name, sql FROM sqlite_schema;", multiline: true, maxLength: 1_000_000 },
        maxRows: { type: "integer", title: "Rows per result (max)", minimum: 1, maximum: 100_000, default: 1000 },
      },
      required: ["sql", "maxRows"],
      additionalProperties: false,
    },
    cost: "medium",
    limits: { maxInputBytes: MAX_DB },
  },
  async run(ctx, inputs, params) {
    const { db } = await openDatabase(inputs);
    try {
      const { tables, statements, changed } = runSql(db, params.sql, params.maxRows);
      const rows = tables.reduce((sum, table) => sum + table.rows.length, 0);
      ctx.diagnostic(`${statements} statement(s), ${tables.length} result set(s), ${rows.toLocaleString()} row(s).`);
      if (changed) ctx.diagnostic("Changes were made to an in-memory copy only; the artifact is unchanged.");
      if (tables.some((table) => table.truncated)) ctx.diagnostic(`Some results were cut at ${params.maxRows.toLocaleString()} rows.`);
      return { result: structuredValue({ kind: "sql", tables }) };
    } finally {
      db.close();
    }
  },
});

export const sqliteValue = defineOperation<{ sql: string }>({
  spec: {
    ...COMMON,
    id: "sqlite.value",
    version: "1.0.0",
    title: "Extract SQLite value as bytes",
    category: "Database",
    description: "Run a query and output the first column of its first row as bytes: a BLOB as is, text as UTF-8. For files stored inside databases.",
    keywords: ["sqlite", "blob", "extract", "value", "file", "image"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: {
      type: "object",
      properties: { sql: { type: "string", title: "SQL returning one value", default: "SELECT data FROM files LIMIT 1;", multiline: true, maxLength: 100_000 } },
      required: ["sql"],
      additionalProperties: false,
    },
    cost: "medium",
    limits: { maxInputBytes: MAX_DB },
  },
  async run(ctx, inputs, params) {
    const { db } = await openDatabase(inputs);
    try {
      let value: SqlValue | undefined;
      try {
        for (const statement of db.iterateStatements(params.sql)) {
          try {
            if (value === undefined && statement.step()) value = statement.get(null, { useBigInt: true })[0];
          } finally {
            statement.free();
          }
        }
      } catch (error) {
        throw new OperationError("INVALID_PARAMS", error instanceof Error ? error.message : String(error));
      }
      if (value === undefined) throw new OperationError("INVALID_INPUT", "The query returned no rows");
      if (value === null) throw new OperationError("INVALID_INPUT", "The value is NULL");
      const bytes = value instanceof Uint8Array ? new Uint8Array(value) : new TextEncoder().encode(String(value));
      ctx.diagnostic(value instanceof Uint8Array ? `BLOB of ${bytes.length.toLocaleString()} bytes.` : `${typeof value} value, written as UTF-8 text.`);
      return { data: bytesFrom(bytes) };
    } finally {
      db.close();
    }
  },
});

export const sqliteFreePages = defineOperation<Record<string, never>>({
  spec: {
    runtime: "ts",
    deterministic: true,
    sideEffects: "none",
    streaming: false,
    id: "sqlite.free-pages",
    version: "1.0.0",
    title: "Extract SQLite free pages",
    category: "Database",
    description: "Concatenate the pages on the SQLite freelist, where deleted rows usually remain until VACUUM. Run Strings or carving on the result.",
    keywords: ["sqlite", "deleted", "freelist", "recover", "undelete", "forensics", "unallocated"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    cost: "low",
    limits: { maxInputBytes: MAX_DB },
  },
  async run(ctx, inputs) {
    const bytes = await readAll(bytesInput(inputs));
    const header = parseSqliteHeader(bytes);
    if (!header) throw new OperationError("INVALID_INPUT", 'Not an SQLite 3 database (the file must start with "SQLite format 3")');
    const { pages, problem } = freelistPages(bytes, header);
    if (problem) ctx.diagnostic(`The freelist is damaged (${problem}); the pages found before that are included.`);
    if (pages.length === 0) throw new OperationError("INVALID_INPUT", "The freelist is empty: no deleted pages are kept in this file");
    const out = new Uint8Array(pages.length * header.pageSize);
    pages.forEach((page, i) => out.set(bytes.subarray((page - 1) * header.pageSize, page * header.pageSize), i * header.pageSize));
    ctx.diagnostic(`${pages.length} page(s) of ${header.pageSize} bytes: ${pages.slice(0, 20).join(", ")}${pages.length > 20 ? ", …" : ""}.`);
    return { data: bytesFrom(out) };
  },
});
