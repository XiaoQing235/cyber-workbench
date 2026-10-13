const MAX_HAR_BYTES = 8 * 1024 * 1024;
const MAX_ENTRIES = 5_000;

export interface HarDiffReport {
  baselinePage: string;
  candidatePage: string;
  compared: number;
  matched: number;
  changed: { request: string; occurrence: number; baselineStatus: number; candidateStatus: number; baselineBodyBytes: number | null; candidateBodyBytes: number | null }[];
  missing: { request: string; occurrence: number }[];
  added: { request: string; occurrence: number }[];
  ignoredQueryKeys: string[];
  queryValuesIgnored: true;
  headersCookiesAndBodiesReturned: false;
}

export interface HarHeaderDiff {
  baselinePage: string;
  candidatePage: string;
  matched: number;
  changed: { request: string; occurrence: number; header: string; baselineValues: number; candidateValues: number }[];
  ignoredHeaders: string[];
  headerValuesReturned: false;
}

interface RequestSummary {
  request: string;
  status: number;
  bodyBytes: number | null;
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`HAR ${label} must be an object`);
  return value as Record<string, unknown>;
}

function text(value: unknown, label: string, maximum: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || /[\0-\x1f\x7f]/.test(value)) throw new Error(`HAR ${label} must be bounded text`);
  return value;
}

function bodySize(response: Record<string, unknown>): number | null {
  const content = response.content === undefined ? null : object(response.content, "response content");
  const size = content?.size ?? response.bodySize;
  return typeof size === "number" && Number.isSafeInteger(size) && size >= 0 ? size : null;
}

function captures(entries: unknown[], page: string, ignored: Set<string>): RequestSummary[] {
  const result: RequestSummary[] = [];
  for (const [index, value] of entries.entries()) {
    const entry = object(value, `entry ${index}`);
    if (entry.pageref !== page) continue;
    const request = object(entry.request, "request");
    const response = object(entry.response, "response");
    const method = text(request.method, "method", 16).toUpperCase();
    if (!/^[A-Z-]+$/.test(method)) throw new Error("HAR request method has an invalid token");
    const rawUrl = text(request.url, "URL", 4_096);
    let url: URL;
    try { url = new URL(rawUrl); }
    catch { throw new Error("HAR request URL is invalid"); }
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("HAR request URL must use HTTP or HTTPS");
    const names = [...new Set([...url.searchParams.keys()].map((key) => key.toLowerCase()).filter((key) => !ignored.has(key)))].sort();
    const pathname = url.pathname.split("/").map((part) => part.length > 48 ? ":long-segment" : part).join("/");
    const key = `${method} ${url.origin}${pathname}${names.length ? `?${names.join("&")}` : ""}`;
    if (key.length > 1_024) throw new Error("HAR normalized request key exceeds 1,024 characters");
    if (typeof response.status !== "number" || !Number.isSafeInteger(response.status) || response.status < 0 || response.status > 999) throw new Error("HAR response status is invalid");
    result.push({ request: key, status: response.status, bodyBytes: bodySize(response) });
  }
  return result;
}

export function diffHar(textValue: string, baselinePage = "", candidatePage = "", ignoredKeys = "cb,utm_source,utm_medium,utm_campaign", maxChanges = 1_000): HarDiffReport {
  if (new TextEncoder().encode(textValue).length > MAX_HAR_BYTES) throw new Error("HAR input exceeds the 8 MiB budget");
  let parsed: unknown;
  try { parsed = JSON.parse(textValue); }
  catch { throw new Error("HAR input must be valid JSON"); }
  const log = object(object(parsed, "document").log, "log");
  if (!/^1\.2(?:\.|$)/.test(text(log.version, "version", 16))) throw new Error("HAR input must use version 1.2");
  if (!Array.isArray(log.pages) || log.pages.length < 2 || log.pages.length > 64 || !Array.isArray(log.entries) || log.entries.length > MAX_ENTRIES) throw new Error("HAR requires two bounded pages and at most 5,000 entries");
  const pages = log.pages.map((value) => text(object(value, "page").id, "page ID", 256));
  if (new Set(pages).size !== pages.length) throw new Error("HAR page IDs must be unique");
  const baseline = baselinePage || pages[0];
  const candidate = candidatePage || pages[1];
  if (baseline === candidate || !pages.includes(baseline) || !pages.includes(candidate)) throw new Error("HAR baseline and candidate must be different page IDs");
  const keys = ignoredKeys.split(",").map((key) => key.trim().toLowerCase()).filter(Boolean);
  if (keys.length > 64 || keys.some((key) => !/^[a-z0-9_.-]{1,64}$/.test(key))) throw new Error("HAR ignored query keys must be a bounded comma-separated list");
  if (!Number.isSafeInteger(maxChanges) || maxChanges < 1 || maxChanges > 2_000) throw new Error("HAR change limit is outside 1 to 2,000");
  const ignored = new Set(keys);
  const base = captures(log.entries, baseline, ignored);
  const next = captures(log.entries, candidate, ignored);
  const groups = (items: RequestSummary[]): Map<string, RequestSummary[]> => {
    const map = new Map<string, RequestSummary[]>();
    for (const item of items) {
      if (!map.has(item.request)) map.set(item.request, []);
      map.get(item.request)!.push(item);
    }
    return map;
  };
  const before = groups(base);
  const after = groups(next);
  const changed: HarDiffReport["changed"] = [];
  const missing: HarDiffReport["missing"] = [];
  const added: HarDiffReport["added"] = [];
  const ensureRoom = () => {
    if (changed.length + missing.length + added.length >= maxChanges) throw new Error("HAR differences exceed the configured output budget");
  };
  let matched = 0;
  for (const key of new Set([...before.keys(), ...after.keys()])) {
    const earlier = before.get(key) ?? [];
    const later = after.get(key) ?? [];
    for (let index = 0; index < Math.max(earlier.length, later.length); index++) {
      if (!earlier[index]) { ensureRoom(); added.push({ request: key, occurrence: index + 1 }); }
      else if (!later[index]) { ensureRoom(); missing.push({ request: key, occurrence: index + 1 }); }
      else {
        matched++;
        if (earlier[index].status !== later[index].status || earlier[index].bodyBytes !== later[index].bodyBytes) {
          ensureRoom();
          changed.push({ request: key, occurrence: index + 1,
            baselineStatus: earlier[index].status, candidateStatus: later[index].status,
            baselineBodyBytes: earlier[index].bodyBytes, candidateBodyBytes: later[index].bodyBytes });
        }
      }
    }
  }
  return { baselinePage: baseline, candidatePage: candidate, compared: base.length + next.length, matched,
    changed, missing, added, ignoredQueryKeys: [...ignored].sort(), queryValuesIgnored: true, headersCookiesAndBodiesReturned: false };
}

/** Compare header multiplicities, never values. This is useful for noisy HAR captures without revealing secrets. */
export function diffHarHeaders(textValue: string, baselinePage = "", candidatePage = "", ignoredHeaders = "date,set-cookie,authorization", maxChanges = 1_000,
  side: "request" | "response" = "request"): HarHeaderDiff {
  if (new TextEncoder().encode(textValue).length > MAX_HAR_BYTES) throw new Error("HAR input exceeds the 8 MiB budget");
  let parsed: unknown;
  try { parsed = JSON.parse(textValue); } catch { throw new Error("HAR input must be valid JSON"); }
  const log = object(object(parsed, "document").log, "log");
  if (!Array.isArray(log.pages) || !Array.isArray(log.entries) || log.entries.length > MAX_ENTRIES || log.pages.length < 2 || log.pages.length > 64) throw new Error("HAR page or entry count exceeds its budget");
  const pages = log.pages.map((item) => text(object(item, "page").id, "page ID", 256));
  if (new Set(pages).size !== pages.length) throw new Error("HAR page IDs must be unique");
  const before = baselinePage || pages[0];
  const after = candidatePage || pages[1];
  if (before === after || !pages.includes(before) || !pages.includes(after)) throw new Error("HAR page IDs must be distinct and present");
  const ignored = ignoredHeaders.split(",").map((item) => item.trim().toLowerCase()).filter(Boolean);
  if (ignored.length > 64 || ignored.some((item) => !/^[a-z0-9-]{1,64}$/.test(item)) || !Number.isSafeInteger(maxChanges) || maxChanges < 1 || maxChanges > 2000) throw new Error("HAR header noise or change budget is invalid");
  const ignore = new Set(ignored);
  const groups = (page: string): Map<string, Map<string, number>[]> => {
    const map = new Map<string, Map<string, number>[]>();
    for (const item of log.entries as unknown[]) {
      const entry = object(item, "entry");
      if (entry.pageref !== page) continue;
      const request = object(entry.request, "request");
      const method = text(request.method, "method", 16).toUpperCase();
      const raw = text(request.url, "URL", 4096);
      let url: URL;
      try { url = new URL(raw); } catch { throw new Error("HAR request URL is invalid"); }
      if (!/^[A-Z-]+$/.test(method) || !["http:", "https:"].includes(url.protocol)) throw new Error("HAR request method or URL is invalid");
      const key = `${method} ${url.origin}${url.pathname}`;
      const message = side === "request" ? request : object(entry.response, "response");
      if (key.length > 1024 || !Array.isArray(message.headers) || message.headers.length > 256) throw new Error(`HAR ${side} headers exceed the budget`);
      const counts = new Map<string, number>();
      for (const header of message.headers) {
        const name = text(object(header, "header").name, "header name", 128).toLowerCase();
        if (!/^[a-z0-9-]+$/.test(name) || ignore.has(name)) continue;
        counts.set(name, (counts.get(name) ?? 0) + 1);
      }
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(counts);
    }
    return map;
  };
  const baseline = groups(before);
  const candidate = groups(after);
  const changed: HarHeaderDiff["changed"] = [];
  let matched = 0;
  for (const key of new Set([...baseline.keys(), ...candidate.keys()])) {
    const a = baseline.get(key) ?? [];
    const b = candidate.get(key) ?? [];
    for (let index = 0; index < Math.min(a.length, b.length); index++) {
      matched++;
      for (const header of new Set([...a[index].keys(), ...b[index].keys()])) {
        const baselineValues = a[index].get(header) ?? 0;
        const candidateValues = b[index].get(header) ?? 0;
        if (baselineValues !== candidateValues) {
          if (changed.length >= maxChanges) throw new Error("HAR header differences exceed the output budget");
          changed.push({ request: key, occurrence: index + 1, header, baselineValues, candidateValues });
        }
      }
    }
  }
  return { baselinePage: before, candidatePage: after, matched, changed, ignoredHeaders: [...ignore].sort(), headerValuesReturned: false };
}
