import type { Bytes } from "../../core/bytes/ByteSource";

export interface HttpMessage {
  kind: "request" | "response";
  startLine: string;
  headers: [string, string][];
  /** Body with chunked transfer coding removed; content coding (gzip…) is left as sent. */
  body: Bytes;
  chunked: boolean;
}

const REQUEST = /^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE|PROPFIND) \S+ HTTP\/\d(\.\d)?$/;
const RESPONSE = /^HTTP\/\d(\.\d)? \d{3}/;
const NO_BODY = /^HTTP\/\d(\.\d)? (1\d\d|204|304)/;

function find(data: Uint8Array, pattern: readonly number[], from: number): number {
  outer: for (let i = from; i + pattern.length <= data.length; i++) {
    for (let j = 0; j < pattern.length; j++) if (data[i + j] !== pattern[j]) continue outer;
    return i;
  }
  return -1;
}

const CRLF = [13, 10];
const BLANK_LINE = [13, 10, 13, 10];
const latin1 = (bytes: Uint8Array) => Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");

function dechunk(data: Bytes, start: number): { body: Bytes; next: number } {
  const parts: Bytes[] = [];
  let at = start;
  for (;;) {
    const lineEnd = find(data, CRLF, at);
    if (lineEnd < 0) break;
    const size = parseInt(latin1(data.subarray(at, lineEnd)).split(";")[0].trim(), 16);
    if (!Number.isFinite(size) || size < 0) break;
    at = lineEnd + 2;
    if (size === 0) {
      const trailerEnd = find(data, CRLF, at);
      const blank = find(data, BLANK_LINE, at);
      at = trailerEnd === at ? at + 2 : blank < 0 ? data.length : blank + 4;
      break;
    }
    parts.push(data.subarray(at, Math.min(data.length, at + size)));
    at += size + 2;
  }
  const body = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    body.set(part, offset);
    offset += part.length;
  }
  return { body, next: Math.min(at, data.length) };
}

/** The HTTP/1.x messages sent in one direction of a TCP stream, in order. */
export function parseHttp(data: Bytes, maxMessages = 1000): HttpMessage[] {
  const messages: HttpMessage[] = [];
  let at = 0;
  while (at < data.length && messages.length < maxMessages) {
    const headerEnd = find(data, BLANK_LINE, at);
    if (headerEnd < 0) break;
    const lines = latin1(data.subarray(at, headerEnd)).split("\r\n");
    const startLine = lines[0];
    const kind = REQUEST.test(startLine) ? "request" : RESPONSE.test(startLine) ? "response" : null;
    if (!kind) break;
    const headers = lines.slice(1).map((line): [string, string] => {
      const colon = line.indexOf(":");
      return colon < 0 ? [line.trim(), ""] : [line.slice(0, colon).trim(), line.slice(colon + 1).trim()];
    });
    const header = (name: string) => headers.find(([key]) => key.toLowerCase() === name)?.[1];
    const bodyStart = headerEnd + 4;
    let body: Bytes;
    let next: number;
    let chunked = false;
    if (header("transfer-encoding")?.toLowerCase().includes("chunked")) {
      chunked = true;
      ({ body, next } = dechunk(data, bodyStart));
    } else if (header("content-length") !== undefined) {
      const length = Math.max(0, parseInt(header("content-length") ?? "0", 10) || 0);
      body = data.subarray(bodyStart, Math.min(data.length, bodyStart + length));
      next = bodyStart + length;
    } else if (kind === "response" && !NO_BODY.test(startLine)) {
      body = data.subarray(bodyStart);
      next = data.length;
    } else {
      body = data.subarray(bodyStart, bodyStart);
      next = bodyStart;
    }
    messages.push({ kind, startLine, headers, body, chunked });
    at = next;
  }
  return messages;
}

export const headerValue = (message: HttpMessage, name: string) =>
  message.headers.find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
