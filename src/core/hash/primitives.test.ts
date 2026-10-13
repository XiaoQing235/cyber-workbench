import { describe, expect, it } from "vitest";
import { BlobSource, MemorySource } from "../bytes/sources";
import { compress } from "../../formats/testing/fixtures";
import { readZip, writeZip, zipEntryData, ZipError } from "../archive/zip";
import { Sha256, sha256Source, toHexString } from "./sha256";

const hex = (bytes: Uint8Array) => toHexString(new Sha256().update(bytes).digest());
const ascii = (text: string) => new TextEncoder().encode(text);

describe("SHA-256", () => {
  it("matches the standard test vectors", () => {
    expect(hex(new Uint8Array(0))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(hex(ascii("abc"))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(hex(ascii("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
  });

  it("gives the same digest as WebCrypto however the input is split", async () => {
    const data = Uint8Array.from({ length: 300_001 }, (_, i) => (i * 7919) & 255);
    const expected = toHexString(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
    for (const step of [1, 63, 64, 65, 4096, 100_000]) {
      const hash = new Sha256();
      for (let offset = 0; offset < data.length; offset += step) hash.update(data.subarray(offset, offset + step));
      expect(toHexString(hash.digest())).toBe(expected);
    }
    expect(await sha256Source(new BlobSource(new Blob([data])))).toBe(expected);
    expect(await sha256Source(new MemorySource(data))).toBe(expected);
  });
});

describe("ZIP", () => {
  it("round-trips entries without copying them", async () => {
    const big = new Uint8Array(70_000).map((_, i) => i & 255);
    const archive = await writeZip([
      { name: "manifest.json", data: new Blob(['{"a":1}']) },
      { name: "files/ünïcode.bin", data: new Blob([big]) },
      { name: "empty", data: new Blob([]) },
    ]);
    const entries = await readZip(archive);
    expect(entries.map((entry) => [entry.name, entry.size])).toEqual([
      ["manifest.json", 7],
      ["files/ünïcode.bin", 70_000],
      ["empty", 0],
    ]);
    expect(await (await zipEntryData(entries[0], 1024)).text()).toBe('{"a":1}');
    expect(new Uint8Array(await (await zipEntryData(entries[1], 1 << 20)).arrayBuffer())).toEqual(big);
  });

  it("reads deflated entries written by other tools", async () => {
    const content = ascii("hello hello hello hello");
    const deflated = await compress(content, "deflate-raw");
    const stored = await readZip(await writeZip([{ name: "x.txt", data: new Blob([content]) }]));
    const archive = await writeZip([{ name: "x.txt", data: new Blob([deflated]) }]);
    const bytes = new Uint8Array(await archive.arrayBuffer());
    const view = new DataView(bytes.buffer);
    // Rewrite the headers as a deflate entry: method 8, original CRC and size.
    const central = bytes.length - 22 - 46 - 5;
    for (const [at, base] of [
      [0, 4],
      [central, 6],
    ] as const) {
      view.setUint16(at + base + 4, 8, true);
      view.setUint32(at + base + 10, stored[0].crc32, true);
      view.setUint32(at + base + 18, content.length, true);
    }
    const [entry] = await readZip(new Blob([bytes]));
    expect(new TextDecoder().decode(await (await zipEntryData(entry, 1024)).arrayBuffer())).toBe("hello hello hello hello");
  });

  it("detects corruption and rejects non-archives", async () => {
    const archive = new Uint8Array(await (await writeZip([{ name: "a", data: new Blob([ascii("payload")]) }])).arrayBuffer());
    archive[31] ^= 1;
    const [entry] = await readZip(new Blob([archive]));
    await expect(zipEntryData(entry, 1024)).rejects.toThrow(/CRC/);
    await expect(readZip(new Blob([ascii("not a zip at all")]))).rejects.toBeInstanceOf(ZipError);
  });
});
