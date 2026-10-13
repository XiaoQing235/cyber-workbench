import type { ByteSource, Bytes } from "../bytes/ByteSource";

export type InflateFormat = "zlib" | "gzip" | "deflate-raw";

const STREAM_FORMAT: Record<InflateFormat, CompressionFormat> = {
  zlib: "deflate",
  gzip: "gzip",
  "deflate-raw": "deflate-raw",
};

export interface InflateResult {
  bytes: Bytes;
  /** Set when the stream failed after producing output (truncated input or trailing junk). */
  error?: string;
  /** Output reached `stopAfter` and decompression was stopped early. */
  stoppedEarly: boolean;
}

export class InflateLimitError extends Error {
  constructor(readonly limit: number) {
    super(`Decompressed output exceeds ${limit} bytes (possible decompression bomb)`);
    this.name = "InflateLimitError";
  }
}

export interface InflateOptions {
  /** Hard ceiling on output size; exceeding it throws InflateLimitError. */
  maxOutputBytes: number;
  /** Stop reading once this many bytes are available (e.g. the size an image needs). */
  stopAfter?: number;
  signal?: AbortSignal;
}

/**
 * Decompresses with the browser's native DecompressionStream. Output is collected with a size
 * limit, so a decompression bomb fails fast instead of exhausting the tab's memory.
 */
export async function inflate(source: ByteSource, format: InflateFormat, options: InflateOptions): Promise<InflateResult> {
  const stream = source.stream().pipeThrough(new DecompressionStream(STREAM_FORMAT[format]) as ReadableWritablePair<Bytes, Bytes>);
  const reader = stream.getReader();
  const chunks: Bytes[] = [];
  let total = 0;
  let error: string | undefined;
  let stoppedEarly = false;
  try {
    for (;;) {
      options.signal?.throwIfAborted();
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > options.maxOutputBytes) throw new InflateLimitError(options.maxOutputBytes);
      chunks.push(value);
      if (options.stopAfter !== undefined && total >= options.stopAfter) {
        stoppedEarly = true;
        break;
      }
    }
  } catch (caught) {
    if (caught instanceof InflateLimitError || options.signal?.aborted) {
      void reader.cancel().catch(() => {});
      throw caught;
    }
    // Some runtimes (Node) reject with an empty message; never let that read as "no error".
    error = (caught instanceof Error ? caught.message : String(caught)) || "the compressed stream is truncated or corrupt";
  }
  if (stoppedEarly) void reader.cancel().catch(() => {});

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { bytes, stoppedEarly, ...(error !== undefined ? { error } : {}) };
}
