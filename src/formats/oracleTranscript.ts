export type OracleCondition = {
  mode: "status" | "length" | "contains" | "timing";
  statusValue: number;
  minimumBytes: number;
  contains: string;
  minimumMs: number;
};

interface OracleObservation {
  request: string;
  status: number;
  body: string;
  durationMs: number;
}

export interface OracleTranscriptReport {
  total: number;
  matched: number;
  repeatedRequests: number;
  noisyRequests: number;
  minorityResponses: number;
  medianMs: number;
  p95Ms: number;
  observations: { index: number; matched: boolean; status: number; bodyBytes: number; durationMs: number }[];
}

function observation(value: unknown, index: number): OracleObservation {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Oracle observation ${index} must be an object`);
  const entry = value as Record<string, unknown>;
  for (const key of Object.keys(entry)) if (!["request", "status", "body", "durationMs"].includes(key)) throw new Error(`Oracle observation ${index} has unsupported field ${key}`);
  if (typeof entry.request !== "string" || entry.request.length === 0 || entry.request.length > 2_048 || !/^[0-9a-f]+$/i.test(entry.request) || entry.request.length % 2 !== 0) throw new Error(`Oracle observation ${index} request must be bounded hex`);
  if (!Number.isInteger(entry.status) || (entry.status as number) < 100 || (entry.status as number) > 599) throw new Error(`Oracle observation ${index} status must be an HTTP status code`);
  if (typeof entry.body !== "string" || entry.body.length > 4_096) throw new Error(`Oracle observation ${index} body exceeds the 4,096-character limit`);
  if (typeof entry.durationMs !== "number" || !Number.isFinite(entry.durationMs) || entry.durationMs < 0 || entry.durationMs > 60_000) throw new Error(`Oracle observation ${index} duration is invalid`);
  return { request: entry.request.toLowerCase(), status: entry.status as number, body: entry.body, durationMs: entry.durationMs };
}

export function analyzeOracleTranscript(text: string, condition: OracleCondition): OracleTranscriptReport {
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { throw new Error("Oracle transcript must be valid JSON"); }
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 256) throw new Error("Oracle transcript requires 1 to 256 observations");
  if (!Number.isSafeInteger(condition.statusValue) || condition.statusValue < 100 || condition.statusValue > 599 ||
    !Number.isSafeInteger(condition.minimumBytes) || condition.minimumBytes < 0 || condition.minimumBytes > 16_384 ||
    typeof condition.contains !== "string" || condition.contains.length > 256 ||
    !Number.isFinite(condition.minimumMs) || condition.minimumMs < 0 || condition.minimumMs > 60_000) throw new Error("Oracle response condition is invalid");
  if (condition.mode === "contains" && condition.contains.length === 0) throw new Error("Oracle content condition cannot be empty");
  if (!["status", "length", "contains", "timing"].includes(condition.mode)) throw new Error("Oracle response condition mode is unsupported");

  const groups = new Map<string, { count: number; matches: number }>();
  const observations = parsed.map((value, index) => {
    const entry = observation(value, index);
    const bodyBytes = new TextEncoder().encode(entry.body).length;
    const matched = condition.mode === "status" ? entry.status === condition.statusValue
      : condition.mode === "length" ? bodyBytes >= condition.minimumBytes
        : condition.mode === "contains" ? entry.body.includes(condition.contains)
          : entry.durationMs >= condition.minimumMs;
    const group = groups.get(entry.request) ?? { count: 0, matches: 0 };
    group.count++;
    if (matched) group.matches++;
    groups.set(entry.request, group);
    return { index, matched, status: entry.status, bodyBytes, durationMs: entry.durationMs };
  });
  const times = observations.map((item) => item.durationMs).sort((first, second) => first - second);
  const middle = Math.floor(times.length / 2);
  const medianMs = times.length % 2 === 0 ? (times[middle - 1] + times[middle]) / 2 : times[middle];
  const repeated = [...groups.values()].filter((group) => group.count > 1);
  return {
    total: observations.length, matched: observations.filter((item) => item.matched).length,
    repeatedRequests: repeated.length,
    noisyRequests: repeated.filter((group) => group.matches > 0 && group.matches < group.count).length,
    minorityResponses: repeated.reduce((sum, group) => sum + Math.min(group.matches, group.count - group.matches), 0),
    medianMs, p95Ms: times[Math.ceil(times.length * 0.95) - 1], observations,
  };
}