import type { ByteSource, Bytes } from "./ByteSource";

export const DEFAULT_CHUNK_SIZE = 1 << 20;

function assertNonNegativeInteger(name: string, value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${name} must be a non-negative integer, got ${value}`);
  }
}

/** Validates a read request and returns the number of bytes actually available. */
function clampRange(size: number, offset: number, length: number): number {
  assertNonNegativeInteger("offset", offset);
  assertNonNegativeInteger("length", length);
  if (offset > size) {
    throw new RangeError(`offset ${offset} is beyond the end of the data (${size} bytes)`);
  }
  return Math.min(length, size - offset);
}

abstract class BaseByteSource implements ByteSource {
  abstract readonly size: number;

  /** Called only with an in-bounds, non-empty range. Must return a caller-owned array. */
  protected abstract readRange(offset: number, length: number): Promise<Bytes>;

  read(offset: number, length: number): Promise<Bytes> {
    const available = clampRange(this.size, offset, length);
    if (available === 0) return Promise.resolve(new Uint8Array(0));
    return this.readRange(offset, available);
  }

  stream(start = 0, end = this.size, chunkSize = DEFAULT_CHUNK_SIZE): ReadableStream<Bytes> {
    if (end < start || end > this.size) {
      throw new RangeError(`invalid stream range ${start}..${end} for ${this.size} bytes`);
    }
    clampRange(this.size, start, end - start);
    if (!Number.isSafeInteger(chunkSize) || chunkSize <= 0) {
      throw new RangeError(`chunkSize must be a positive integer, got ${chunkSize}`);
    }
    let position = start;
    return new ReadableStream<Bytes>({
      pull: async (controller) => {
        if (position >= end) {
          controller.close();
          return;
        }
        const length = Math.min(chunkSize, end - position);
        const chunk = await this.readRange(position, length);
        position += length;
        controller.enqueue(chunk);
      },
    });
  }
}

/** In-memory bytes. Takes ownership of the array: callers must not modify it afterwards. */
export class MemorySource extends BaseByteSource {
  readonly size: number;
  readonly bytes: Bytes;

  constructor(bytes: Bytes) {
    super();
    this.bytes = bytes;
    this.size = bytes.byteLength;
  }

  protected readRange(offset: number, length: number): Promise<Bytes> {
    return Promise.resolve(this.bytes.slice(offset, offset + length));
  }
}

/** A File or Blob, read lazily in ranges. Dropping a 1 GB file costs nothing until it is read. */
export class BlobSource extends BaseByteSource {
  readonly size: number;
  readonly blob: Blob;

  constructor(blob: Blob) {
    super();
    this.blob = blob;
    this.size = blob.size;
  }

  protected async readRange(offset: number, length: number): Promise<Bytes> {
    return new Uint8Array(await this.blob.slice(offset, offset + length).arrayBuffer());
  }
}

/** A zero-copy window into another source. */
export class SliceSource extends BaseByteSource {
  readonly size: number;
  readonly parent: ByteSource;
  readonly offset: number;

  constructor(parent: ByteSource, offset: number, length: number) {
    super();
    assertNonNegativeInteger("offset", offset);
    assertNonNegativeInteger("length", length);
    if (offset + length > parent.size) {
      throw new RangeError(
        `slice ${offset}+${length} exceeds the parent size of ${parent.size} bytes`,
      );
    }
    this.parent = parent;
    this.offset = offset;
    this.size = length;
  }

  protected readRange(offset: number, length: number): Promise<Bytes> {
    return this.parent.read(this.offset + offset, length);
  }
}

/** Several sources presented as one, without copying (e.g. reassembled stream fragments). */
export class ConcatSource extends BaseByteSource {
  readonly size: number;
  readonly parts: readonly ByteSource[];
  private readonly starts: number[];

  constructor(parts: readonly ByteSource[]) {
    super();
    this.parts = [...parts];
    this.starts = [];
    let total = 0;
    for (const part of this.parts) {
      this.starts.push(total);
      total += part.size;
    }
    this.size = total;
  }

  protected async readRange(offset: number, length: number): Promise<Bytes> {
    const out = new Uint8Array(length);
    let written = 0;
    let index = this.partIndexAt(offset);
    while (written < length) {
      const part = this.parts[index];
      const within = offset + written - this.starts[index];
      const count = Math.min(part.size - within, length - written);
      if (count > 0) {
        out.set(await part.read(within, count), written);
        written += count;
      }
      index++;
    }
    return out;
  }

  private partIndexAt(position: number): number {
    for (let i = 0; i < this.parts.length; i++) {
      if (position < this.starts[i] + this.parts[i].size) return i;
    }
    throw new RangeError(`position ${position} is beyond the end of the data`);
  }
}

/** Placeholder for bytes that are not available, e.g. from a workspace exported without files. */
export class MissingSource extends BaseByteSource {
  readonly size: number;

  constructor(size: number) {
    super();
    assertNonNegativeInteger("size", size);
    this.size = size;
  }

  protected readRange(): Promise<Bytes> {
    return Promise.reject(new Error("The bytes of this artifact are not available (it was imported without files)"));
  }
}

/** Reads a whole source into memory, refusing sources larger than `maxBytes`. */
export async function readAll(source: ByteSource, maxBytes = Number.POSITIVE_INFINITY): Promise<Bytes> {
  if (source.size > maxBytes) {
    throw new RangeError(`data is ${source.size} bytes, which exceeds the ${maxBytes} byte limit`);
  }
  return source.read(0, source.size);
}

/**
 * Converts a source to a Blob for structured cloning (e.g. into a Worker). File-backed sources,
 * slices and concatenations stay lazy: no bytes are read here.
 */
export async function toBlob(source: ByteSource): Promise<Blob> {
  if (source instanceof BlobSource) return source.blob;
  if (source instanceof MemorySource) return new Blob([source.bytes]);
  if (source instanceof SliceSource) {
    return (await toBlob(source.parent)).slice(source.offset, source.offset + source.size);
  }
  if (source instanceof ConcatSource) {
    return new Blob(await Promise.all(source.parts.map(toBlob)));
  }
  return new Blob([await readAll(source)]);
}
