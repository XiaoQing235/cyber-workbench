import initSqlJs from "sql.js";
import sqlWasm from "sql.js/dist/sql-wasm.wasm?inline";
import { beforeAll, describe, expect, it } from "vitest";
import type { Bytes } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import type { Params } from "../core/operation/types";
import type { Table } from "../core/table";
import { bytesFrom, type Value } from "../core/value";
import { readBrowserHistory } from "../formats/browserHistory";
import { importWindowsTimeline } from "../formats/windowsTimeline";
import { setPackFileReader } from "../runtimes/files";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();
const wasm = Uint8Array.from(atob(sqlWasm.slice(sqlWasm.indexOf(",") + 1)), (c) => c.charCodeAt(0));
setPackFileReader(async (url) => {
  if (url.includes("sql-wasm")) return wasm;
  throw new Error(`No test file for ${url}`);
});

async function run(operationId: string, input: Bytes, params: Params = {}) {
  const result = await executeOperation(registry, { operationId, inputs: { data: bytesFrom(input) }, params });
  return { value: Object.values(result.outputs)[0] as Value | undefined, error: result.run.error, diagnostics: result.run.diagnostics };
}

const tablesOf = (value: Value | undefined) => (value as { data: { tables: Table[] } }).data.tables;

let database: Bytes;
let chromeHistory: Bytes;
let firefoxHistory: Bytes;

beforeAll(async () => {
  const SQL = await initSqlJs({ wasmBinary: wasm });
  const db = new SQL.Database();
  db.run("PRAGMA secure_delete = OFF");
  db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT)");
  db.run("INSERT INTO users (name, password) VALUES ('alice', 'hunter2'), ('bob', 'flag{sql_rows}')");
  db.run("CREATE TABLE files (name TEXT, data BLOB, size INTEGER)");
  db.run("INSERT INTO files VALUES (?, ?, ?)", ["logo.png", Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 1, 2, 3), 9007199254740993n]);
  db.run("CREATE TABLE messages (id INTEGER PRIMARY KEY, body TEXT)");
  for (let i = 0; i < 300; i++) db.run("INSERT INTO messages (body) VALUES (?)", [`message ${i} ${i === 150 ? "flag{deleted_but_not_gone}" : "x".repeat(40)}`]);
  db.run("DELETE FROM messages WHERE id > 20");
  db.run("CREATE INDEX users_name ON users (name)");
  database = new Uint8Array(db.export());
  db.close();
  const chrome = new SQL.Database();
  chrome.run("CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT)");
  chrome.run("CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER)");
  chrome.run("INSERT INTO urls VALUES (1, 'https://example.test/path', 'Example')");
  chrome.run("INSERT INTO visits VALUES (1, 1, ?)", [13380249600123456n]);
  chromeHistory = new Uint8Array(chrome.export());
  chrome.close();
  const firefox = new SQL.Database();
  firefox.run("CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT)");
  firefox.run("CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY, place_id INTEGER, visit_date INTEGER)");
  firefox.run("INSERT INTO moz_places VALUES (1, 'https://example.test/path', 'Example')");
  firefox.run("INSERT INTO moz_historyvisits VALUES (1, 1, ?)", [1735776000123456n]);
  firefoxHistory = new Uint8Array(firefox.export());
  firefox.close();
});

describe("SQLite pack", () => {
  it("normalizes Chromium and Firefox visit timestamps from their distinct epochs", async () => {
    const SQL = await initSqlJs({ wasmBinary: wasm });
    for (const [data, expected] of [[chromeHistory, "chromium"], [firefoxHistory, "firefox"]] as const) {
      const db = new SQL.Database(data);
      try {
        expect(readBrowserHistory(db, "auto", 10)).toEqual({
          browser: expected,
          visits: [{ visitId: "1", utc: "2025-01-02T00:00:00.123456Z", url: "https://example.test/path", title: "Example" }],
          truncated: false,
        });
      } finally { db.close(); }
    }
  });

  it("exports exact Chrome visit timestamps into the shared forensic timeline", async () => {
    const inspection = await executeOperation(registry, {
      operationId: "forensics.browser-history.inspect", inputs: { data: bytesFrom(chromeHistory) }, params: { browser: "auto", maxVisits: 10 },
    });
    expect(inspection.run.error).toBeUndefined();
    expect((inspection.outputs.report as { data: object }).data).toMatchObject({ browser: "chromium", visits: [{ utc: "2025-01-02T00:00:00.123456Z" }] });
    const exported = await executeOperation(registry, {
      operationId: "forensics.browser-history.timeline-export", inputs: { data: bytesFrom(chromeHistory) },
      params: { browser: "auto", maxVisits: 10, hostname: "LAB" },
    });
    expect(exported.run.error).toBeUndefined();
    const timeline = await importWindowsTimeline((exported.outputs.text as { text: string }).text, "plaso-jsonl", 0, 60);
    expect(timeline.events[0]).toMatchObject({ utc: "2025-01-02T00:00:00.123456Z", host: "LAB", artifact: "https://example.test/path", message: "Visit 1: Example" });
  });

  it("keeps separate browser visits with identical URL and timestamp when IDs differ", async () => {
    const SQL = await initSqlJs({ wasmBinary: wasm });
    const db = new SQL.Database(chromeHistory);
    db.run("INSERT INTO visits VALUES (2, 1, ?)", [13380249600123456n]);
    const bytes = new Uint8Array(db.export());
    db.close();
    const capped = await executeOperation(registry, {
      operationId: "forensics.browser-history.inspect", inputs: { data: bytesFrom(bytes) }, params: { browser: "auto", maxVisits: 1 },
    });
    expect((capped.outputs.report as { data: object }).data).toMatchObject({ visits: [{ visitId: "1" }], truncated: true });
    const exported = await executeOperation(registry, {
      operationId: "forensics.browser-history.timeline-export", inputs: { data: bytesFrom(bytes) },
      params: { browser: "auto", maxVisits: 2, hostname: "LAB" },
    });
    const timeline = await importWindowsTimeline((exported.outputs.text as { text: string }).text, "plaso-jsonl", 0, 60);
    expect(timeline).toMatchObject({ total: 2, duplicates: 0, events: [{ message: "Visit 1: Example" }, { message: "Visit 2: Example" }] });
  });

  it("inspects tables, flags secret-looking columns and deleted pages", async () => {
    const { value, diagnostics } = await run("sqlite.inspect", database);
    const report = (value as { data: { tables: Table[]; findings: { ruleId: string; severity: string; message: string; suggestion?: { operationId: string } }[] } }).data;
    const schema = report.tables[1];
    expect(schema.columns).toEqual(["type", "name", "table", "rows", "columns", "sql"]);
    expect(schema.rows.map((row) => [row[0], row[1], row[3]])).toEqual([
      ["table", "files", 1],
      ["table", "messages", 20],
      ["table", "users", 2],
      ["index", "users_name", null],
    ]);
    const byRule = (rule: string) => report.findings.filter((finding) => finding.ruleId === rule);
    expect(byRule("sqlite.freelist")[0]).toMatchObject({ severity: "medium", suggestion: { operationId: "sqlite.free-pages" } });
    expect(byRule("sqlite.table").map((finding) => [finding.message, finding.severity])).toEqual([
      ["Table files: 1 row(s); columns name, data, size", "weak"],
      ["Table messages: 20 row(s); columns id, body", "weak"],
      ["Table users: 2 row(s); columns id, name, password", "medium"],
    ]);
    expect(report.tables[0].rows.find((row) => row[0] === "page size")?.[1]).toBe(4096);
    expect(diagnostics[0]).toMatch(/^3 table\(s\), 1 other schema object\(s\); \d+ free page\(s\)\.$/);
  });

  it("runs queries on a copy: tables per statement, blobs, 64-bit integers, row caps", async () => {
    const sql = "SELECT name, password FROM users ORDER BY id; SELECT * FROM files; UPDATE users SET password = 'x'; SELECT count(*) FROM messages;";
    const { value, diagnostics } = await run("sqlite.query", database, { sql, maxRows: 1 });
    const tables = tablesOf(value);
    expect(tables.map((table) => table.title)).toEqual(["SELECT name, password FROM users ORDER BY id;", "SELECT * FROM files;", "SELECT count(*) FROM messages;"]);
    expect(tables[0]).toMatchObject({ columns: ["name", "password"], rows: [["alice", "hunter2"]], truncated: true });
    expect(tables[1].rows[0]).toEqual(["logo.png", { blob: "89 50 4e 47 01 02 03", size: 7 }, "9007199254740993"]);
    expect(diagnostics).toContain("Changes were made to an in-memory copy only; the artifact is unchanged.");
    // The artifact itself was not changed by the UPDATE.
    expect(tablesOf((await run("sqlite.query", database, { sql: "SELECT password FROM users WHERE id = 2" })).value)[0].rows).toEqual([["flag{sql_rows}"]]);
  });

  it("reports SQL errors with the statement number", async () => {
    const { error } = await run("sqlite.query", database, { sql: "SELECT 1; SELEC nope;" });
    expect(error).toMatchObject({ code: "INVALID_PARAMS", message: expect.stringMatching(/^Statement 2: .*syntax error/) });
  });

  it("extracts a BLOB as bytes", async () => {
    const { value } = await run("sqlite.value", database, { sql: "SELECT data FROM files WHERE name = 'logo.png'" });
    expect(await readAll((value as Extract<Value, { type: "bytes" }>).source)).toEqual(Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 1, 2, 3));
  });

  it("recovers deleted rows from free pages", async () => {
    const { value, diagnostics } = await run("sqlite.free-pages", database);
    const pages = await readAll((value as Extract<Value, { type: "bytes" }>).source);
    expect(pages.length % 4096).toBe(0);
    expect(new TextDecoder().decode(pages)).toContain("flag{deleted_but_not_gone}");
    expect(diagnostics[0]).toMatch(/^\d+ page\(s\) of 4096 bytes: /);
  });

  it("rejects non-databases and reports a missing pack as unavailable", async () => {
    expect((await run("sqlite.inspect", Uint8Array.of(1, 2, 3))).error?.code).toBe("INVALID_INPUT");
    setPackFileReader(async () => {
      throw new TypeError("Failed to fetch");
    });
    try {
      // A fresh worker would have to download the pack; this one already initialised it, so use a new module instance.
      const { readPackFile } = await import("../runtimes/files");
      await expect(readPackFile("SQLite", "/assets/pack-sqlite.wasm")).rejects.toMatchObject({
        code: "UNAVAILABLE",
        message: expect.stringMatching(/^The SQLite pack could not be loaded \(Failed to fetch\)\. If you are offline/),
      });
    } finally {
      setPackFileReader(async () => wasm);
    }
  });
});
