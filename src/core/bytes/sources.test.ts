import { describe, expect, it } from "vitest";
import { BlobSource, ConcatSource, MemorySource, SliceSource, readAll, toBlob } from "./sources";

const bytes = (...values: number[]) => Uint8Array.from(values);
const range = (n: number) => Uint8Array.from({ length: n }, (_, i) => i & 255);

async function collect(stream: ReadableStream<Uint8Array>): Promise<number[]> {
  const out: number[] = [];
  for await (const chunk of stream) out.push(...chunk);
  return out;
}

describe("MemorySource", () => {
  it("reads ranges and clamps at the end", async () => {
    const source = new MemorySource(bytes(1, 2, 3, 4));
    expect([...(await source.read(1, 2))]).toEqual([2, 3]);
    expect([...(await source.read(2, 100))]).toEqual([3, 4]);
    expect((await source.read(4, 10)).length).toBe(0);
  });

  it("rejects out-of-range and invalid reads", () => {
    const source = new MemorySource(bytes(1, 2));
    expect(() => source.read(3, 1)).toThrow(RangeError);
    expect(() => source.read(-1, 1)).toThrow(RangeError);
    expect(() => source.read(0.5, 1)).toThrow(RangeError);
  });

  it("returns copies, so callers cannot mutate the source", async () => {
    const source = new MemorySource(bytes(9, 9));
    const first = await source.read(0, 2);
    first[0] = 0;
    expect([...(await source.read(0, 2))]).toEqual([9, 9]);
  });

  it("streams in chunks and reassembles exactly", async () => {
    const source = new MemorySource(range(1000));
    expect(await collect(source.stream(0, 1000, 64))).toEqual([...range(1000)]);
    expect(await collect(source.stream(10, 20, 3))).toEqual([...range(1000).slice(10, 20)]);
  });
});

describe("BlobSource", () => {
  it("reads lazily from a Blob", async () => {
    const source = new BlobSource(new Blob([range(300)]));
    expect(source.size).toBe(300);
    expect([...(await source.read(250, 10))]).toEqual([...range(300).slice(250, 260)]);
  });
});

describe("SliceSource", () => {
  it("is a window into its parent", async () => {
    const slice = new SliceSource(new MemorySource(range(100)), 10, 20);
    expect(slice.size).toBe(20);
    expect([...(await slice.read(5, 5))]).toEqual([15, 16, 17, 18, 19]);
    expect([...(await slice.read(15, 100))]).toEqual([25, 26, 27, 28, 29]);
  });

  it("must fit inside the parent", () => {
    expect(() => new SliceSource(new MemorySource(range(10)), 5, 6)).toThrow(RangeError);
  });
});

describe("ConcatSource", () => {
  it("reads across part boundaries, skipping empty parts", async () => {
    const source = new ConcatSource([
      new MemorySource(bytes(1, 2, 3)),
      new MemorySource(bytes()),
      new BlobSource(new Blob([bytes(4, 5)])),
      new SliceSource(new MemorySource(bytes(6, 7, 8, 9)), 0, 3),
    ]);
    expect(source.size).toBe(8);
    expect([...(await readAll(source))]).toEqual([1, 2, 3, 4, 5, 6, 7, 8]);
    expect([...(await source.read(2, 4))]).toEqual([3, 4, 5, 6]);
  });
});

describe("readAll and toBlob", () => {
  it("enforces the size limit", async () => {
    await expect(readAll(new MemorySource(range(10)), 9)).rejects.toThrow(RangeError);
  });

  it("round-trips every source kind through a Blob", async () => {
    const parent = new BlobSource(new Blob([range(50)]));
    const source = new ConcatSource([new SliceSource(parent, 40, 10), new MemorySource(bytes(255))]);
    const blob = await toBlob(source);
    expect([...new Uint8Array(await blob.arrayBuffer())]).toEqual([...range(50).slice(40), 255]);
  });
});
