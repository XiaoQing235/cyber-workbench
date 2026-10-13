export interface TimelineEvent {
  utc: string;
  source: string;
  host: string;
  artifact: string;
  message: string;
  sourceIp?: string;
  destinationIp?: string;
  observedPaths?: string[];
  observedIdentities?: string[];
}

export interface TimelineReport {
  total: number;
  duplicates: number;
  linked: number;
  truncatedLinks: boolean;
  events: TimelineEvent[];
  links: { from: number; to: number; artifact: string; secondsApart: number }[];
}

export type TimelineFormat = "plaso-jsonl" | "hayabusa-csv" | "hayabusa-jsonl" | "mftecmd-csv" | "mixed-json";

export function unixMicrosToUtc(value: bigint): string {
  let millis = value / 1_000n;
  let remainder = value % 1_000n;
  if (remainder < 0n) { millis--; remainder += 1_000n; }
  const numeric = Number(millis);
  if (!Number.isSafeInteger(numeric) || !Number.isFinite(new Date(numeric).getTime())) throw new Error("Timeline microsecond timestamp is outside the supported date range");
  return new Date(numeric).toISOString().replace(/Z$/, `${String(remainder).padStart(3, "0")}Z`);
}

function bounded(value: unknown, label: string, maxLength: number): string {
  if (typeof value !== "string" || value.length > maxLength) throw new Error(`Timeline ${label} must be text of at most ${maxLength} characters`);
  return value;
}

function utc(value: unknown, timezoneOffsetMinutes: number): string {
  if (typeof value !== "string") throw new Error("Timeline timestamp must be text");
  const match = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})?$/.exec(value.trim());
  if (!match) throw new Error("Timeline timestamp needs YYYY-MM-DD HH:mm:ss and an explicit or configured timezone");
  const [, year, month, day, hours, minutes, seconds, fraction = "", zone] = match;
  const milliseconds = Number(fraction.padEnd(3, "0").slice(0, 3));
  const local = Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hours), Number(minutes), Number(seconds), milliseconds);
  const check = new Date(local);
  if (check.getUTCFullYear() !== Number(year) || check.getUTCMonth() + 1 !== Number(month) || check.getUTCDate() !== Number(day) || check.getUTCHours() !== Number(hours) || check.getUTCMinutes() !== Number(minutes) || check.getUTCSeconds() !== Number(seconds)) throw new Error("Timeline timestamp contains an invalid calendar date or time");
  const offset = !zone || zone === "Z" ? (!zone ? timezoneOffsetMinutes : 0)
    : (zone[0] === "+" ? 1 : -1) * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(4, 6)));
  if (Math.abs(offset) > 840 || (zone && zone !== "Z" && Number(zone.slice(4, 6)) >= 60)) throw new Error("Timeline timezone offset is invalid");
  return new Date(local - offset * 60_000).toISOString().replace(/Z$/, `${fraction.padEnd(6, "0").slice(3)}Z`);
}

function microseconds(value: string): bigint {
  return BigInt(Date.parse(value)) * 1_000n + BigInt(value.slice(-4, -1));
}

function pathKey(event: TimelineEvent): string {
  return `${event.host.toLowerCase()}\0${event.artifact.replaceAll("/", "\\").toLowerCase()}`;
}

function plasoEvent(value: unknown, timezoneOffsetMinutes: number): TimelineEvent {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Plaso record is not an event");
  const record = value as Record<string, unknown>;
  return {
    utc: utc(record.timestamp, timezoneOffsetMinutes),
    source: `plaso:${bounded(record.parser ?? "unknown", "parser", 128)}`,
    host: bounded(record.hostname ?? "", "hostname", 256),
    artifact: bounded(record.filename ?? record.path ?? "", "filename", 1_024),
    message: bounded(record.message ?? "", "message", 2_048),
  };
}

function hayabusaEvent(record: Record<string, unknown>, timezoneOffsetMinutes: number): TimelineEvent {
  const sourceIp = bounded(record.SourceIp ?? "", "source IP", 64);
  const destinationIp = bounded(record.DestinationIp ?? "", "destination IP", 64);
  return {
    utc: utc(record.Timestamp, timezoneOffsetMinutes),
    source: `hayabusa:${bounded(record.Channel, "channel", 128)}:${bounded(record.EventID, "event ID", 16)}`,
    host: bounded(record.Computer, "computer", 256),
    artifact: bounded(record.Path ?? record.TargetFilename ?? record.Image ?? "", "path", 1_024),
    message: bounded(record.Details, "details", 2_048),
    ...(sourceIp ? { sourceIp } : {}), ...(destinationIp ? { destinationIp } : {}),
  };
}

function hayabusaJsonlEvent(record: Record<string, unknown>, timezoneOffsetMinutes: number): TimelineEvent {
  const sourceIp = bounded(record.SourceIp ?? "", "source IP", 64);
  const destinationIp = bounded(record.DestinationIp ?? "", "destination IP", 64);
  const channel = bounded(record.Channel, "channel", 128);
  const id = record.EventID;
  if ((typeof id !== "number" || !Number.isSafeInteger(id) || id < 0 || id > 65535) &&
    (typeof id !== "string" || !/^\d{1,5}$/.test(id))) throw new Error("Hayabusa JSONL event ID is invalid");
  const observedPaths = [...new Set(["SourceImage", "TargetImage", "Image", "TargetFilename"]
    .map((key) => bounded(record[key] ?? "", key, 1_024)).filter(Boolean))];
  const domain = bounded(record.Domain ?? "", "account domain", 256);
  const account = bounded(record.AccountName ?? "", "account name", 256);
  const sid = bounded(record.UserID ?? "", "user SID", 256);
  const observedIdentities = [
    ...(domain && account && !/[\\\x00-\x1f]/.test(domain) && !/[\\\x00-\x1f]/.test(account) ? [`${domain}\\${account}`] : []),
    ...(sid && /^S-1-(?:\d+-){1,14}\d+$/.test(sid) ? [sid] : []),
  ];
  return {
    utc: utc(record.UtcTime ?? record["@timestamp"], timezoneOffsetMinutes),
    source: `hayabusa:${channel}:${id}`,
    host: bounded(record.Hostname ?? "", "hostname", 256),
    artifact: bounded(record.TargetFilename ?? record.Image ?? record.TargetImage ?? "", "path", 1_024),
    message: bounded(record.Message ?? "", "message", 2_048),
    ...(observedPaths.length ? { observedPaths } : {}),
    ...(observedIdentities.length ? { observedIdentities } : {}),
    ...(sourceIp ? { sourceIp } : {}), ...(destinationIp ? { destinationIp } : {}),
  };
}

function mftEvent(record: Record<string, unknown>, timezoneOffsetMinutes: number): TimelineEvent[] {
  const parent = bounded(record.ParentPath, "MFTECmd parent path", 1_024);
  const filename = bounded(record.FileName, "MFTECmd filename", 512);
  const host = bounded(record.Computer ?? "", "MFTECmd computer", 256);
  const path = `${parent.replace(/[\\/]$/, "")}\\${filename}`;
  const entries: TimelineEvent[] = [];
  for (const [column, label] of [["Created0x10", "created"], ["LastModified0x10", "modified"],
    ["LastRecordChange0x10", "record changed"], ["LastAccess0x10", "accessed"],
    ["Created0x30", "filename created"], ["LastModified0x30", "filename modified"],
    ["LastRecordChange0x30", "filename changed"], ["LastAccess0x30", "filename accessed"]] as const) {
    const value = record[column];
    if (value === undefined || value === "") continue;
    entries.push({ utc: utc(value, timezoneOffsetMinutes), source: `mftecmd:${column}`,
      host, artifact: path, message: `NTFS ${label} (${column})` });
  }
  return entries;
}

export async function importWindowsTimeline(text: string, format: TimelineFormat, timezoneOffsetMinutes: number, windowSeconds: number): Promise<TimelineReport> {
  if (!Number.isSafeInteger(timezoneOffsetMinutes) || timezoneOffsetMinutes < -720 || timezoneOffsetMinutes > 840 || !Number.isSafeInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > 3_600) throw new Error("Timeline timezone or correlation window is outside its configured bounds");
  const events: TimelineEvent[] = [];
  if (format === "plaso-jsonl" || format === "hayabusa-jsonl") {
    const lines = text.replace(/\r/g, "").split("\n").filter((line) => line.trim().length > 0);
    if (lines.length < 1 || lines.length > 5_000) throw new Error("Timeline requires 1 to 5,000 records");
    for (const [index, line] of lines.entries()) {
      let value: unknown;
      try { value = JSON.parse(line); }
      catch { throw new Error(`${format} line ${index + 1} is invalid`); }
      if (format === "plaso-jsonl") events.push(plasoEvent(value, timezoneOffsetMinutes));
      else {
        if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Hayabusa JSONL record must be an object");
        events.push(hayabusaJsonlEvent(value as Record<string, unknown>, timezoneOffsetMinutes));
      }
    }
  } else if (format === "hayabusa-csv" || format === "mftecmd-csv") {
    const { default: Papa } = await import("papaparse");
    const parsed = Papa.parse<Record<string, string>>(text, { header: true, delimiter: ",", skipEmptyLines: "greedy", dynamicTyping: false });
    if (parsed.errors.length > 0) throw new Error(`${format} is invalid: ${parsed.errors[0].message}`);
    const renamed = (parsed.meta as typeof parsed.meta & { renamedHeaders?: Record<string, string> }).renamedHeaders;
    if (renamed && Object.keys(renamed).length > 0) throw new Error(`${format} contains duplicate columns`);
    const fields = parsed.meta.fields ?? [];
    for (const required of format === "hayabusa-csv" ? ["Timestamp", "Computer", "Channel", "EventID", "Details"] : ["ParentPath", "FileName"]) {
      if (!fields.includes(required)) throw new Error(`${format} is missing ${required}`);
    }
    if (format === "mftecmd-csv" && !fields.some((field) => /^(?:Created|LastModified|LastRecordChange|LastAccess)0x(?:10|30)$/.test(field))) {
      throw new Error("MFTECmd CSV is missing timestamp columns");
    }
    if (parsed.data.length < 1 || parsed.data.length > 5_000) throw new Error("Timeline requires 1 to 5,000 records");
    for (const record of parsed.data) {
      if (format === "hayabusa-csv") events.push(hayabusaEvent(record, timezoneOffsetMinutes));
      else events.push(...mftEvent(record, timezoneOffsetMinutes));
      if (events.length > 5_000) throw new Error("Timeline exceeds 5,000 expanded events");
    }
  } else if (format === "mixed-json") {
    let parsed: unknown;
    try { parsed = JSON.parse(text); }
    catch { throw new Error("Mixed timeline must be valid JSON"); }
    if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 5_000) throw new Error("Mixed timeline requires 1 to 5,000 events");
    for (const [index, item] of parsed.entries()) {
      if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error(`Mixed timeline entry ${index} must be an object`);
      const wrapper = item as Record<string, unknown>;
      if (Object.keys(wrapper).some((name) => name !== "source" && name !== "event")) throw new Error(`Mixed timeline entry ${index} has unsupported fields`);
      if (wrapper.source === "plaso") events.push(plasoEvent(wrapper.event, timezoneOffsetMinutes));
      else if (wrapper.source === "hayabusa" && wrapper.event && typeof wrapper.event === "object" && !Array.isArray(wrapper.event)) events.push(hayabusaEvent(wrapper.event as Record<string, unknown>, timezoneOffsetMinutes));
      else throw new Error(`Mixed timeline entry ${index} has an unsupported source or event`);
    }
  } else throw new Error("Unsupported timeline format");

  events.sort((first, second) => first.utc.localeCompare(second.utc) || first.source.localeCompare(second.source) || first.host.localeCompare(second.host));
  const deduped: TimelineEvent[] = [];
  const seen = new Set<string>();
  for (const event of events) {
    const fingerprint = JSON.stringify([event.utc, event.source, event.host, event.artifact, event.message,
      event.sourceIp ?? "", event.destinationIp ?? "", event.observedPaths ?? [], event.observedIdentities ?? []]);
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    deduped.push(event);
  }
  const links: TimelineReport["links"] = [];
  const mostRecent = new Map<string, number>();
  let truncatedLinks = false;
  for (const [index, event] of deduped.entries()) {
    if (!event.host || !event.artifact) continue;
    const key = pathKey(event);
    const previous = mostRecent.get(key);
    if (previous !== undefined) {
      const secondsApart = Number(microseconds(event.utc) - microseconds(deduped[previous].utc)) / 1_000_000;
      if (secondsApart <= windowSeconds) {
        if (links.length === 1_000) truncatedLinks = true;
        else links.push({ from: previous, to: index, artifact: event.artifact, secondsApart });
      }
    }
    mostRecent.set(key, index);
  }
  return { total: deduped.length, duplicates: events.length - deduped.length, linked: links.length, truncatedLinks, events: deduped, links };
}
