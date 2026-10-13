const MAX_EVENTS = 5_000;
const MAX_TEXT_BYTES = 2_000_000;

export interface CloudTrailEvent {
  eventId: string;
  utc: string;
  eventSource: string;
  eventName: string;
  accountId: string | null;
  principal: string | null;
  sourceAddress: string | null;
  region: string | null;
  targetRoleArn: string | null;
  resources: string[];
  readOnly: boolean | null;
  errorCode: string | null;
}

export interface CloudTrailReport {
  total: number;
  duplicateEventIds: number;
  services: { name: string; count: number }[];
  events: CloudTrailEvent[];
}

export interface CloudTrailRoleGraph {
  nodes: { arn: string; kinds: ("caller" | "target-role")[] }[];
  edges: { caller: string; role: string; outcome: "no-reported-error" | "reported-error"; count: number; firstUtc: string; lastUtc: string; eventIds: string[] }[];
  skippedDuplicateIds: number;
  skippedMissingIdentity: number;
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`CloudTrail ${label} must be an object`);
  return value as Record<string, unknown>;
}

function string(value: unknown, label: string, maximum: number, required = false): string | null {
  if (value === undefined || value === null) {
    if (required) throw new Error(`CloudTrail ${label} is required`);
    return null;
  }
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) throw new Error(`CloudTrail ${label} must be nonempty text of at most ${maximum} characters`);
  return value;
}

function eventUtc(value: unknown): string {
  const text = string(value, "eventTime", 32, true)!;
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$/.exec(text);
  if (!match) throw new Error("CloudTrail eventTime must be an ISO UTC timestamp");
  const [, year, month, day, hour, minute, second, fraction = ""] = match;
  const date = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second)));
  const expected = `${year}-${month}-${day}T${hour}:${minute}:${second}`;
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 19) !== expected) throw new Error("CloudTrail eventTime has an invalid calendar date");
  return `${expected}.${fraction.padEnd(6, "0")}Z`;
}

export function inspectCloudTrail(text: string): CloudTrailReport {
  if (new TextEncoder().encode(text).length > MAX_TEXT_BYTES) throw new Error("CloudTrail input exceeds the 2 MB budget");
  let input: unknown;
  try { input = JSON.parse(text); }
  catch {
    const lines = text.split(/\r?\n/).filter((line) => line.trim() !== "");
    if (lines.length < 1 || lines.length > MAX_EVENTS) throw new Error("CloudTrail JSONL must contain 1 to 5,000 records");
    try {
      input = lines.map((line) => {
        const parsed: unknown = JSON.parse(line);
        return object(parsed, "JSONL record");
      });
    }
    catch { throw new Error("CloudTrail input must be valid JSON or JSONL"); }
  }
  const records = Array.isArray(input) ? input : input && typeof input === "object" && "Records" in input ? object(input, "log").Records : [input];
  if (!Array.isArray(records) || records.length < 1 || records.length > MAX_EVENTS) throw new Error("CloudTrail input must contain 1 to 5,000 Records");
  const events: CloudTrailEvent[] = [];
  const services = new Map<string, number>();
  const seen = new Set<string>();
  let duplicateEventIds = 0;
  for (const [index, item] of records.entries()) {
    const record = object(item, `record ${index + 1}`);
    const identity = record.userIdentity === undefined ? null : object(record.userIdentity, "userIdentity");
    const request = record.requestParameters === undefined || record.requestParameters === null ? null : object(record.requestParameters, "requestParameters");
    const eventId = string(record.eventID, "eventID", 128, true)!;
    const eventSource = string(record.eventSource, "eventSource", 256, true)!;
    const eventName = string(record.eventName, "eventName", 256, true)!;
    const accountId = string(record.recipientAccountId ?? identity?.accountId, "account ID", 12);
    if (accountId !== null && !/^\d{12}$/.test(accountId)) throw new Error("CloudTrail account ID must have 12 digits");
    const rawResources = record.resources ?? [];
    if (!Array.isArray(rawResources) || rawResources.length > 64) throw new Error("CloudTrail resources must be a bounded list");
    const resources = rawResources.map((item) => string(object(item, "resource").ARN, "resource ARN", 1_024, true)!);
    if (record.readOnly !== undefined && record.readOnly !== null && typeof record.readOnly !== "boolean") throw new Error("CloudTrail readOnly must be a boolean");
    const event: CloudTrailEvent = {
      eventId, utc: eventUtc(record.eventTime ?? record["@timestamp"]), eventSource, eventName, accountId,
      principal: string(identity?.arn ?? identity?.principalId, "principal", 1_024),
      sourceAddress: string(record.sourceIPAddress, "source address", 256),
      region: string(record.awsRegion, "AWS region", 64),
      targetRoleArn: string(request?.roleArn, "target role ARN", 1_024),
      resources, readOnly: record.readOnly === undefined || record.readOnly === null ? null : record.readOnly as boolean,
      errorCode: string(record.errorCode, "error code", 256),
    };
    events.push(event);
    services.set(eventSource, (services.get(eventSource) ?? 0) + 1);
    if (seen.has(eventId)) duplicateEventIds++;
    seen.add(eventId);
  }
  return { total: events.length, duplicateEventIds, services: [...services].map(([name, count]) => ({ name, count })).sort((first, second) => first.name.localeCompare(second.name)), events };
}

export function observedRoleGraph(report: CloudTrailReport): CloudTrailRoleGraph {
  const nodes = new Map<string, Set<"caller" | "target-role">>();
  const edges = new Map<string, CloudTrailRoleGraph["edges"][number]>();
  const ids = new Set<string>();
  let skippedDuplicateIds = 0;
  let skippedMissingIdentity = 0;
  for (const event of report.events) {
    if (event.eventSource !== "sts.amazonaws.com" || !["AssumeRole", "AssumeRoleWithSAML", "AssumeRoleWithWebIdentity"].includes(event.eventName)) continue;
    if (ids.has(event.eventId)) { skippedDuplicateIds++; continue; }
    ids.add(event.eventId);
    if (!event.principal || !event.targetRoleArn) { skippedMissingIdentity++; continue; }
    if (!nodes.has(event.principal)) nodes.set(event.principal, new Set());
    if (!nodes.has(event.targetRoleArn)) nodes.set(event.targetRoleArn, new Set());
    nodes.get(event.principal)!.add("caller");
    nodes.get(event.targetRoleArn)!.add("target-role");
    const outcome = event.errorCode ? "reported-error" : "no-reported-error";
    const key = JSON.stringify([event.principal, event.targetRoleArn, outcome]);
    let edge = edges.get(key);
    if (!edge) {
      edge = { caller: event.principal, role: event.targetRoleArn, outcome, count: 0, firstUtc: event.utc, lastUtc: event.utc, eventIds: [] };
      edges.set(key, edge);
    }
    edge.count++;
    edge.eventIds.push(event.eventId);
    if (event.utc < edge.firstUtc) edge.firstUtc = event.utc;
    if (event.utc > edge.lastUtc) edge.lastUtc = event.utc;
  }
  return {
    nodes: [...nodes].map(([arn, kinds]) => ({ arn, kinds: [...kinds].sort() })).sort((first, second) => first.arn.localeCompare(second.arn)),
    edges: [...edges.values()].sort((first, second) => first.caller.localeCompare(second.caller) || first.role.localeCompare(second.role) || first.outcome.localeCompare(second.outcome)),
    skippedDuplicateIds, skippedMissingIdentity,
  };
}
