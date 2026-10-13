import type { Database, SqlValue } from "../runtimes/sqlite";
import { unixMicrosToUtc } from "./windowsTimeline";

const CHROME_TO_UNIX_MICROS = 11644473600000000n;

export interface BrowserVisit {
  visitId: string;
  utc: string;
  url: string;
  title: string;
}

export interface BrowserHistoryReport {
  browser: "chromium" | "firefox";
  visits: BrowserVisit[];
  truncated: boolean;
}

function rows(db: Database, sql: string, maxRows: number): SqlValue[][] {
  const result: SqlValue[][] = [];
  for (const statement of db.iterateStatements(sql)) {
    try {
      while (statement.step()) {
        result.push(statement.get(null, { useBigInt: true }));
        if (result.length >= maxRows) break;
      }
    } finally { statement.free(); }
  }
  return result;
}

function timestamp(value: SqlValue): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number" && Number.isSafeInteger(value)) return BigInt(value);
  throw new Error("Browser visit timestamp is not a lossless 64-bit integer");
}

export function readBrowserHistory(db: Database, requested: "auto" | "chromium" | "firefox", maxVisits: number): BrowserHistoryReport {
  if (!Number.isSafeInteger(maxVisits) || maxVisits < 1 || maxVisits > 5_000) throw new Error("Browser visit limit must be 1 to 5,000");
  db.run("PRAGMA query_only = ON");
  const names = new Set(rows(db, "SELECT name FROM sqlite_schema WHERE type = 'table'", 10_000).map(([value]) => value));
  const chromium = names.has("urls") && names.has("visits");
  const firefox = names.has("moz_places") && names.has("moz_historyvisits");
  if (requested === "auto" && chromium === firefox) throw new Error("Browser history schema is missing or ambiguous");
  const browser = requested === "auto" ? chromium ? "chromium" : "firefox" : requested;
  if ((browser === "chromium" && !chromium) || (browser === "firefox" && !firefox)) throw new Error(`Database does not have the ${browser} history tables`);
  const sql = browser === "chromium"
    ? `SELECT v.id, v.visit_time, u.url, COALESCE(u.title, '') FROM visits v JOIN urls u ON u.id = v.url WHERE v.visit_time > 0 ORDER BY v.visit_time, v.id LIMIT ${maxVisits + 1}`
    : `SELECT v.id, v.visit_date, p.url, COALESCE(p.title, '') FROM moz_historyvisits v JOIN moz_places p ON p.id = v.place_id WHERE v.visit_date > 0 ORDER BY v.visit_date, v.id LIMIT ${maxVisits + 1}`;
  const data = rows(db, sql, maxVisits + 1);
  const visits = data.slice(0, maxVisits).map(([id, visitTime, url, title]) => {
    if (typeof url !== "string" || url.length > 2_048 || typeof title !== "string" || title.length > 512) throw new Error("Browser URL or title is invalid or exceeds the output limit");
    const micros = timestamp(visitTime) - (browser === "chromium" ? CHROME_TO_UNIX_MICROS : 0n);
    return { visitId: timestamp(id).toString(), utc: unixMicrosToUtc(micros), url, title };
  });
  return { browser, visits, truncated: data.length > maxVisits };
}