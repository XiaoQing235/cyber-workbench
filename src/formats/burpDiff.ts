import { diffHar, diffHarHeaders, type HarDiffReport, type HarHeaderDiff } from "./harDiff";

const MAX_BURP_BYTES = 8 * 1024 * 1024;
const MAX_ITEMS = 5_000;

function record(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Burp ${label} must be an object`);
  return value as Record<string, unknown>;
}

function field(value: unknown, label: string, max: number): string {
  if (typeof value !== "string" || value.length < 1 || value.length > max || /[\0-\x1f\x7f]/.test(value)) {
    throw new Error(`Burp ${label} must be bounded text`);
  }
  return value;
}

function xmlUrl(value: unknown): string {
  if (typeof value !== "string") throw new Error("Burp URL must be text");
  // Entity processing stays disabled in the parser. Decode only the five built-in XML entities.
  const decoded = value.replace(/&(?:amp|lt|gt|quot|apos);/g, (entity) => ({
    "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'",
  })[entity]!);
  if (/&(?:#|[a-zA-Z]+;)/.test(decoded)) throw new Error("Burp URL contains an unsupported XML entity");
  return field(decoded, "URL", 4_096);
}

async function parseItems(text: string, baselineCount: number): Promise<Record<string, unknown>[]> {
  if (new TextEncoder().encode(text).length > MAX_BURP_BYTES) throw new Error("Burp export exceeds the 8 MiB budget");
  const { XMLParser, XMLValidator } = await import("fast-xml-parser");
  if (/<!DOCTYPE|<!ENTITY/i.test(text) || XMLValidator.validate(text) !== true) throw new Error("Burp XML contains a declaration or is malformed");
  const parsed = record(new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@", processEntities: false,
    parseTagValue: false, parseAttributeValue: false, trimValues: true, maxNestedTags: 16 }).parse(text), "document");
  if (!Object.hasOwn(parsed, "items") || Object.keys(parsed).some((key) => key !== "items" && key !== "?xml")) {
    throw new Error("Burp export must contain only an items root");
  }
  const root = record(parsed.items, "items root");
  if (Object.keys(root).some((key) => key !== "item" && key !== "@burpVersion" && key !== "@exportTime")) {
    throw new Error("Burp export contains unsupported root fields");
  }
  const items = Array.isArray(root.item) ? root.item : root.item === undefined ? [] : [root.item];
  if (items.length < 2 || items.length > MAX_ITEMS) throw new Error("Burp export needs 2–5,000 items");
  if (!Number.isSafeInteger(baselineCount) || baselineCount < 1 || baselineCount >= items.length) {
    throw new Error("Burp baseline count must leave at least one candidate item");
  }
  return items.map((value, index) => record(value, `item ${index + 1}`));
}

/** Compares ordered halves of Burp's XML item export; request/response payloads are never decoded. */
export async function diffBurp(text: string, baselineCount: number, ignoredQueryKeys: string, maxChanges: number): Promise<HarDiffReport> {
  const entries = (await parseItems(text, baselineCount)).map((item, index) => {
    const method = field(item.method, "method", 16);
    const url = xmlUrl(item.url);
    const status = Number(item.status);
    if (typeof item.status !== "string" || !/^\d{3}$/.test(item.status) || !Number.isSafeInteger(status) || status > 999) {
      throw new Error(`Burp item ${index + 1} has no valid response status`);
    }
    if (!Object.hasOwn(item, "request") || !Object.hasOwn(item, "response")) {
      throw new Error(`Burp item ${index + 1} has no request or response payload`);
    }
    // Burp's response length is a wire/message size, not HAR's decoded body size.
    // Do not compare it as though it were a body length.
    return { pageref: index < baselineCount ? "baseline" : "candidate", request: { method, url }, response: { status } };
  });
  return diffHar(JSON.stringify({ log: { version: "1.2", pages: [{ id: "baseline" }, { id: "candidate" }], entries } }),
    "baseline", "candidate", ignoredQueryKeys, maxChanges);
}

function messageHeaders(payload: unknown, side: "request" | "response"): { name: string }[] {
  const message = record(payload, `${side} payload`);
  const encoded = message["#text"];
  if (typeof encoded !== "string") throw new Error(`Burp ${side} payload is missing`);
  const base64 = message["@base64"];
  if (base64 !== "true" && base64 !== "false") throw new Error(`Burp ${side} encoding is unsupported`);
  if (encoded.length > 128 * 1024) throw new Error(`Burp ${side} exceeds its header budget`);
  let bytes: Uint8Array;
  if (base64 === "true") {
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) throw new Error(`Burp ${side} has invalid base64`);
    bytes = Uint8Array.from(atob(encoded), (char) => char.charCodeAt(0));
  } else bytes = new TextEncoder().encode(encoded);
  if (bytes.length > 64 * 1024) throw new Error(`Burp ${side} exceeds its 64 KiB budget`);
  let end = -1;
  for (let i = 0; i < bytes.length - 1; i++) {
    if (bytes[i] === 13 && bytes[i + 1] === 10 && bytes[i + 2] === 13 && bytes[i + 3] === 10) { end = i; break; }
    if (bytes[i] === 10 && bytes[i + 1] === 10) { end = i; break; }
  }
  if (end < 0 || end > 32 * 1024) throw new Error(`Burp ${side} header block is missing or exceeds 32 KiB`);
  const lines = new TextDecoder("latin1").decode(bytes.subarray(0, end)).split(/\r?\n/);
  if (!(side === "request" ? /^[A-Z-]+ \S+ HTTP\/\d(?:\.\d)?$/ : /^HTTP\/\d(?:\.\d)? \d{3}(?: .*)?$/).test(lines.shift() ?? "")) {
    throw new Error(`Burp ${side} line is invalid`);
  }
  if (lines.length > 256) throw new Error(`Burp ${side} has too many headers`);
  return lines.map((line) => {
    const match = /^([!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}):[ \t]*[^\r\n]*$/.exec(line);
    if (!match) throw new Error(`Burp ${side} has a malformed header`);
    return { name: match[1] };
  });
}

/** Compare header-name multiplicities in Burp request messages; never return header values or payloads. */
export async function diffBurpHeaders(text: string, baselineCount: number, ignoredHeaders: string, maxChanges: number,
  side: "request" | "response" = "request"): Promise<HarHeaderDiff> {
  const items = await parseItems(text, baselineCount);
  const entries = items.map((item, index) => ({ pageref: index < baselineCount ? "baseline" : "candidate",
    request: { method: field(item.method, "method", 16), url: xmlUrl(item.url), ...(side === "request" ? { headers: messageHeaders(item.request, side) } : {}) },
    ...(side === "response" ? { response: { headers: messageHeaders(item.response, side) } } : {}) }));
  return diffHarHeaders(JSON.stringify({ log: { pages: [{ id: "baseline" }, { id: "candidate" }], entries } }),
    "baseline", "candidate", ignoredHeaders, maxChanges, side);
}
