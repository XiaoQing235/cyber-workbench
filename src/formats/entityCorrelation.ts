const MAX_BYTES = 2 * 1024 * 1024;
const MAX_EVENTS = 5000;
const MAX_LINKS = 2000;
import { inspectCloudTrail } from "./cloudTrail";
import { importWindowsTimeline, type TimelineFormat } from "./windowsTimeline";

export interface EntityEvent {
  id: string;
  utc: string;
  source: string;
  entities: { kind: "ip" | "domain" | "file" | "identity"; value: string }[];
}

export interface EntityReport {
  events: EntityEvent[];
  links: { from: number; to: number; entity: string; kind: EntityEvent["entities"][number]["kind"]; secondsApart: number }[];
  truncated: boolean;
}

/** Convert already parsed CloudTrail facts to the same explicit, offline entity-event schema. */
export function cloudTrailEntityEvents(json: string): EntityEvent[] {
  const report = inspectCloudTrail(json);
  const ids = new Set<string>();
  const events: EntityEvent[] = [];
  for (const event of report.events) {
    if (ids.has(event.eventId)) continue;
    ids.add(event.eventId);
    const entities: EntityEvent["entities"] = [];
    if (event.sourceAddress && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(event.sourceAddress) &&
      event.sourceAddress.split(".").every((part) => Number(part) <= 255)) entities.push({ kind: "ip", value: event.sourceAddress });
    if (event.principal) entities.push({ kind: "identity", value: event.principal });
    if (event.targetRoleArn) entities.push({ kind: "identity", value: event.targetRoleArn });
    for (const resource of event.resources) entities.push({ kind: "identity", value: resource });
    events.push({ id: event.eventId, utc: event.utc, source: `cloudtrail:${event.eventSource}:${event.eventName}`, entities: entities.slice(0, 16) });
  }
  return events;
}

function ipv4(value: string): string | null {
  if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value)) return null;
  return value.split(".").every((part) => Number(part) <= 255) ? value : null;
}

/** Use only explicit artifact paths and typed IP columns; free-form messages are not mined for guessed entities. */
export async function timelineEntityEvents(text: string, format: TimelineFormat, timezoneOffsetMinutes: number, sourceLabel = "timeline"): Promise<EntityEvent[]> {
  if (new TextEncoder().encode(text).length > 2_000_000) throw new Error("Timeline entity input exceeds 2 MB");
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(sourceLabel)) throw new Error("Timeline entity source label must be 1–64 letters, digits, dots, hyphens or underscores");
  const report = await importWindowsTimeline(text, format, timezoneOffsetMinutes, 60);
  const events = report.events.map((event, index) => {
    const entities: EntityEvent["entities"] = [];
    for (const path of [event.artifact, ...(event.observedPaths ?? [])]) {
      if (/^(?:[A-Za-z]:[\\/]|\\\\|\/)/.test(path) &&
        !entities.some((entry) => entry.kind === "file" && entry.value.replaceAll("/", "\\").toLowerCase() === path.replaceAll("/", "\\").toLowerCase())) {
        entities.push({ kind: "file", value: path });
      }
    }
    for (const value of [event.sourceIp, event.destinationIp]) {
      const address = value ? ipv4(value) : null;
      if (address && !entities.some((entry) => entry.kind === "ip" && entry.value === address)) entities.push({ kind: "ip", value: address });
    }
    for (const value of event.observedIdentities ?? []) {
      if (!entities.some((entry) => entry.kind === "identity" && entry.value.toLowerCase() === value.toLowerCase())) {
        entities.push({ kind: "identity", value });
      }
    }
    return { id: `${sourceLabel}-${index + 1}`, utc: event.utc, source: event.source, entities };
  });
  if (new TextEncoder().encode(JSON.stringify(events)).length > MAX_BYTES) throw new Error("Timeline entity output exceeds the correlation input budget");
  return events;
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Entity event must be an object");
  return value as Record<string, unknown>;
}

function text(value: unknown, name: string, max: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > max || /[\0-\x1f\x7f]/.test(value)) throw new Error(`Entity ${name} must be bounded text`);
  return value;
}

function timestamp(value: unknown): { utc: string; micros: bigint } {
  const input = text(value, "timestamp", 32);
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/.exec(input);
  if (!match) throw new Error("Entity timestamp needs an ISO UTC value");
  const [, year, month, day, hour, minute, second, fraction = ""] = match;
  const milliseconds = Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second));
  const date = new Date(milliseconds);
  if (!Number.isFinite(milliseconds) || date.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`) {
    throw new Error("Entity timestamp has an invalid calendar date");
  }
  const fractional = fraction.padEnd(6, "0");
  return { utc: `${year}-${month}-${day}T${hour}:${minute}:${second}.${fractional}Z`, micros: BigInt(milliseconds) * 1000n + BigInt(fractional) };
}

/** Correlate observed, explicit entities only. Matching identity and time are evidence, not causation. */
export function correlateEntities(json: string, windowSeconds: number): EntityReport {
  if (new TextEncoder().encode(json).length > MAX_BYTES || !Number.isSafeInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > 3600) {
    throw new Error("Entity input or correlation window exceeds its budget");
  }
  let parsed: unknown;
  try { parsed = JSON.parse(json); } catch { throw new Error("Entity events must be valid JSON"); }
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > MAX_EVENTS) throw new Error("Entity input needs 1–5,000 events");
  const seen = new Set<string>();
  const events: EntityEvent[] = parsed.map((raw, index) => {
    const event = object(raw);
    const id = text(event.id, `event ${index} ID`, 128);
    if (seen.has(id)) throw new Error(`Entity event ${id} is duplicated`);
    seen.add(id);
    const { utc } = timestamp(event.utc);
    if (!Array.isArray(event.entities) || event.entities.length > 16) throw new Error("Entity event exceeds its 16-entity budget");
    const entities: EntityEvent["entities"] = event.entities.map((item) => {
      const entity = object(item);
      const kind = entity.kind;
      if (kind !== "ip" && kind !== "domain" && kind !== "file" && kind !== "identity") throw new Error("Unknown entity type");
      return { kind, value: text(entity.value, "value", 1024) };
    });
    return { id, utc, source: text(event.source, "source", 128), entities };
  });
  events.sort((a, b) => a.utc.localeCompare(b.utc) || a.id.localeCompare(b.id));
  const latest = new Map<string, number>();
  const links: EntityReport["links"] = [];
  let truncated = false;
  for (const [index, event] of events.entries()) {
    for (const entity of event.entities) {
      const normalized = entity.kind === "file" ? entity.value.replaceAll("/", "\\").toLowerCase() : entity.value.toLowerCase();
      const key = `${entity.kind}\0${normalized}`;
      const before = latest.get(key);
      if (before !== undefined && before !== index) {
        const secondsApart = Number(timestamp(event.utc).micros - timestamp(events[before].utc).micros) / 1_000_000;
        if (secondsApart >= 0 && secondsApart <= windowSeconds) {
          if (links.length >= MAX_LINKS) truncated = true;
          else links.push({ from: before, to: index, entity: normalized, kind: entity.kind, secondsApart });
        }
      }
      latest.set(key, index);
    }
  }
  return { events, links, truncated };
}
