/** Caller-owned bytes backed by a plain (non-shared) ArrayBuffer. */
export type Bytes = Uint8Array<ArrayBuffer>;

/**
 * Read-only, random-access view of binary data. Every component reads bytes through this
 * interface, so large inputs are only loaded whole when an operation genuinely needs that.
 */
export interface ByteSource {
  readonly size: number;
  /**
   * Returns a new array owned by the caller. The result is shorter than `length` only when
   * the range reaches the end of the data. Reading at `offset === size` returns no bytes.
   */
  read(offset: number, length: number): Promise<Bytes>;
  stream(start?: number, end?: number, chunkSize?: number): ReadableStream<Bytes>;
}
