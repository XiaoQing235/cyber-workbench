import initSqlJs, { type Database, type SqlJsStatic, type SqlValue } from "sql.js";
import wasmUrl from "sql.js/dist/sql-wasm.wasm?url";
import { once, readPackFile } from "../files";

export type { Database, SqlValue };

export const loadSqlite = once(async (): Promise<SqlJsStatic> => initSqlJs({ wasmBinary: await readPackFile("SQLite", wasmUrl) }));
