import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { OperationError } from "../core/operation/errors";
import type { OperationContext } from "../core/operation/types";
import type { Value } from "../core/value";

export const MiB = 1024 * 1024;
export const CHUNK_SIZE = MiB;

/**
 * Lets queued messages (such as a cancel request) run during long synchronous loops.
 * Awaiting an already-resolved promise is not enough: that only drains microtasks.
 */
export function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

export function bytesInput(inputs: Readonly<Record<string, Value>>, name = "data"): ByteSource {
  const value = inputs[name];
  if (value?.type !== "bytes") throw new OperationError("INPUT_TYPE", `Input "${name}" must be bytes`);
  return value.source;
}

export function textInput(inputs: Readonly<Record<string, Value>>, name = "text"): string {
  const value = inputs[name];
  if (value?.type !== "text") throw new OperationError("INPUT_TYPE", `Input "${name}" must be text`);
  return value.text;
}

/** Visits a source chunk by chunk, checking for cancellation between chunks. */
export async function forEachChunk(
  ctx: OperationContext,
  source: ByteSource,
  visit: (chunk: Bytes, offset: number) => void,
  chunkSize = CHUNK_SIZE,
): Promise<void> {
  for (let offset = 0; offset < source.size; offset += chunkSize) {
    ctx.throwIfAborted();
    visit(await source.read(offset, chunkSize), offset);
  }
}

/** Builds a same-sized output by transforming each chunk in place. */
export async function mapChunks(
  ctx: OperationContext,
  source: ByteSource,
  transform: (chunk: Bytes, offset: number) => void,
  chunkSize = CHUNK_SIZE,
): Promise<Bytes> {
  const out = new Uint8Array(source.size);
  await forEachChunk(
    ctx,
    source,
    (chunk, offset) => {
      transform(chunk, offset);
      out.set(chunk, offset);
    },
    chunkSize,
  );
  return out;
}

const HEX_DIGITS = "0123456789abcdef";

export function isHexDigit(code: number): boolean {
  return (code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x46) || (code >= 0x61 && code <= 0x66);
}

function hexDigitValue(code: number): number {
  if (code <= 0x39) return code - 0x30;
  return (code | 0x20) - 0x61 + 10;
}

/**
 * Parses hex text. Whitespace is always ignored. With `ignoreSeparators`, "0x" / "\x"
 * prefixes and the separators : , ; - _ . are ignored too.
 */
export function parseHex(input: string, ignoreSeparators: boolean): Bytes {
  const cleaned = ignoreSeparators
    ? input.replace(/0x|\\x/gi, "").replace(/[\s:,;\-_.]/g, "")
    : input.replace(/\s/g, "");
  for (let i = 0; i < cleaned.length; i++) {
    if (!isHexDigit(cleaned.charCodeAt(i))) {
      throw new OperationError("INVALID_INPUT", `Invalid hex character ${JSON.stringify(cleaned[i])}`);
    }
  }
  if (cleaned.length % 2 !== 0) {
    throw new OperationError("INVALID_INPUT", `Hex input has an odd number of digits (${cleaned.length})`);
  }
  const out = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = (hexDigitValue(cleaned.charCodeAt(2 * i)) << 4) | hexDigitValue(cleaned.charCodeAt(2 * i + 1));
  }
  return out;
}

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += HEX_DIGITS[byte >> 4] + HEX_DIGITS[byte & 15];
  return out;
}
