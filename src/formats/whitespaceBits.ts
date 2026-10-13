import type { Bytes } from "../core/bytes/ByteSource";

export interface WhitespaceBitsReport {
  mode: "line-end" | "zero-width";
  bitOrder: "msb-first" | "lsb-first";
  bits: number;
  bytes: number;
  leftoverBits: number;
  truncated: boolean;
  firstOffsets: number[];
}

export function extractWhitespaceBits(text: string, mode: WhitespaceBitsReport["mode"], bitOrder: WhitespaceBitsReport["bitOrder"], maxBytes: number, signal?: AbortSignal): { bytes: Bytes; report: WhitespaceBitsReport } {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 1_000_000) throw new Error("Whitespace output limit must be 1 to 1,000,000 bytes");
  const result: number[] = [];
  const firstOffsets: number[] = [];
  let bits = 0;
  let accumulator = 0;
  let filled = 0;
  let truncated = false;
  const add = (bit: number, offset: number): boolean => {
    if (bits >= maxBytes * 8) { truncated = true; return false; }
    if (firstOffsets.length < 64) firstOffsets.push(offset);
    accumulator = bitOrder === "msb-first" ? (accumulator << 1) | bit : accumulator | (bit << filled);
    bits++;
    if (++filled === 8) {
      result.push(accumulator);
      accumulator = 0;
      filled = 0;
    }
    return true;
  };

  if (mode === "line-end") {
    for (let start = 0; start <= text.length;) {
      if (signal?.aborted) throw signal.reason;
      let end = start;
      while (end < text.length && text[end] !== "\r" && text[end] !== "\n") end++;
      let trailing = end;
      while (trailing > start && (text[trailing - 1] === " " || text[trailing - 1] === "\t")) trailing--;
      for (let offset = trailing; offset < end; offset++) {
        if (!add(text[offset] === "\t" ? 1 : 0, offset)) break;
      }
      if (truncated || end === text.length) break;
      start = end + (text[end] === "\r" && text[end + 1] === "\n" ? 2 : 1);
    }
  } else if (mode === "zero-width") {
    for (let offset = 0; offset < text.length; offset++) {
      if (offset % 16_384 === 0 && signal?.aborted) throw signal.reason;
      if (text[offset] !== "\u200b" && text[offset] !== "\u200c") continue;
      if (!add(text[offset] === "\u200c" ? 1 : 0, offset)) break;
    }
  } else throw new Error(`Unsupported whitespace bit mode ${String(mode)}`);
  return { bytes: Uint8Array.from(result), report: { mode, bitOrder, bits, bytes: result.length, leftoverBits: filled, truncated, firstOffsets } };
}