import { describe, expect, it } from "vitest";
import { deflateSync } from "node:zlib";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractRenPyIndex, extractRenPyMember, inspectRenPy, listRenPyMembers } from "./renpy";

const fixture = () => new MemorySource(new TextEncoder().encode("RPA-3.0 0000000000000026 1234ABCD\nDATAFAKE-ZLIB-PICKLE"));
// Independently generated with Python pickle.dumps(..., protocol=4), then zlib.compress.
const PYTHON_INDEX = "eJxrYJmqxgABtVN6uIuTizILSvSKCiqTp8RO8Xq/2kTI6ySQcGZydJrSPiWxWA8AcYsQlQ==";
const PYTHON_PROTOCOL2 = "eJxrYKotZIjgZmBgKE4uyiwo0SsqqEwuZIwtZPJ6v9pEyOskkEiOT85PSU0u5krNAzG4CpkjmIAaHJ0KWSLYgIycxJLMPMNC1rZCtqBC9vZCjsRiPQC0Uxom";

describe("static Ren'Py RPA-3.0 header", () => {
  it("locates and exposes index bytes without executing pickle", async () => {
    const source = fixture();
    expect(await inspectRenPy(source)).toEqual({ version: "RPA-3.0", indexOffset: 38,
      indexBytes: 16, key: "0x1234abcd", indexFormat: "pickle", indexExecuted: false });
    expect(new TextDecoder().decode(await readAll(await extractRenPyIndex(source)))).toBe("FAKE-ZLIB-PICKLE");
    const result = await executeOperation(createDefaultRegistry(), { operationId: "reverse.renpy.inspect", inputs: { data: bytesValue(source) }, params: {} });
    expect(result.run.status).toBe("success");
  });

  it("rejects corrupted signatures and out-of-file index offsets", async () => {
    const bad = fixture().bytes.slice(); bad[4] = 0x32;
    await expect(inspectRenPy(new MemorySource(bad))).rejects.toThrow(/RPA-3.0/);
    const offset = fixture().bytes.slice(); offset.set(new TextEncoder().encode("ffffffffffffffff"), 8);
    await expect(inspectRenPy(new MemorySource(offset))).rejects.toThrow(/index exceeds/);
  });

  it("lists a restricted literal index and rejects opcodes that could invoke constructors", async () => {
    const key = 0x1234abcd;
    const name = new TextEncoder().encode("data/hello.txt");
    const bytes = new Uint8Array(5 + name.length + 3 + 4 + 1 + 4 + 6);
    const view = new DataView(bytes.buffer);
    let at = 0;
    bytes.set([0x80, 2, 0x7d, 0x55, name.length], at); at += 5;
    bytes.set(name, at); at += name.length;
    bytes.set([0x5d, 0x28, 0x4a], at); at += 3;
    view.setUint32(at, (34 ^ key) >>> 0, true); at += 4;
    bytes[at++] = 0x4a;
    view.setUint32(at, (4 ^ key) >>> 0, true); at += 4;
    bytes.set([0x55, 0, 0x74, 0x61, 0x73, 0x2e], at);
    const compressed = deflateSync(bytes);
    const header = `RPA-3.0 ${"26".padStart(16, "0")} 1234ABCD\n`;
    const archive = new Uint8Array(38 + compressed.length);
    archive.set(new TextEncoder().encode(header));
    archive.set(new TextEncoder().encode("DATA"), 34);
    archive.set(compressed, 38);
    const members = await listRenPyMembers(new MemorySource(archive));
    expect(members).toEqual([{ path: "data/hello.txt", offset: 34, bytes: 4, prefixBytes: 0, prefix: [] }]);
    expect(new TextDecoder().decode(await readAll(await extractRenPyMember(new MemorySource(archive), "data/hello.txt")))).toBe("DATA");
    const registry = await executeOperation(createDefaultRegistry(), { operationId: "reverse.renpy.member-extract",
      inputs: { data: bytesValue(new MemorySource(archive)) }, params: { path: "data/hello.txt" } });
    expect(registry.run.status).toBe("success");
    const unsafe = bytes.slice(); unsafe[2] = 0x63; // GLOBAL
    const zipped = deflateSync(unsafe);
    const bad = new Uint8Array(38 + zipped.length);
    bad.set(archive.subarray(0, 38)); bad.set(zipped, 38);
    await expect(listRenPyMembers(new MemorySource(bad))).rejects.toThrow(/dictionary layout/);
  });

  it("restores stored prefixes ahead of selected member bytes", async () => {
    const name = new TextEncoder().encode("script.rpyc");
    const key = 0x1234abcd;
    const index = new Uint8Array(5 + name.length + 3 + 4 + 1 + 4 + 2 + 2 + 4);
    const view = new DataView(index.buffer);
    let at = 0;
    index.set([0x80, 2, 0x7d, 0x55, name.length], at); at += 5;
    index.set(name, at); at += name.length;
    index.set([0x5d, 0x28, 0x4a], at); at += 3;
    view.setUint32(at, (34 ^ key) >>> 0, true); at += 4;
    index[at++] = 0x4a;
    view.setUint32(at, (4 ^ key) >>> 0, true); at += 4;
    index.set([0x55, 2, 0x41, 0x42, 0x74, 0x61, 0x73, 0x2e], at);
    const compressed = deflateSync(index);
    const bytes = new Uint8Array(38 + compressed.length);
    bytes.set(new TextEncoder().encode("RPA-3.0 0000000000000026 1234ABCD\nDATA"));
    bytes.set(compressed, 38);
    expect(new TextDecoder().decode(await readAll(await extractRenPyMember(new MemorySource(bytes), "script.rpyc")))).toBe("ABDATA");
    await expect(extractRenPyMember(new MemorySource(bytes), "missing")).rejects.toThrow(/not present/);
    view.setUint32(5 + name.length + 3, (0xffffff00 ^ key) >>> 0, true);
    const invalid = new Uint8Array(38 + deflateSync(index).length);
    invalid.set(bytes.subarray(0, 38)); invalid.set(deflateSync(index), 38);
    await expect(listRenPyMembers(new MemorySource(invalid))).rejects.toThrow(/archive extent/);
  });

  it("accepts Python-generated protocol-4 literal byte strings without invoking pickle", async () => {
    const zipped = Uint8Array.from(atob(PYTHON_INDEX), (character) => character.charCodeAt(0));
    const bytes = new Uint8Array(38 + zipped.length);
    bytes.set(new TextEncoder().encode("RPA-3.0 0000000000000026 1234ABCD\nDATA"));
    bytes.set(zipped, 38);
    expect(new TextDecoder().decode(await readAll(await extractRenPyMember(new MemorySource(bytes), "script.rpyc")))).toBe("ABDATA");
  });

  it("recognizes only Python protocol-2 literal latin1 byte prefixes", async () => {
    const zipped = Uint8Array.from(atob(PYTHON_PROTOCOL2), (character) => character.charCodeAt(0));
    const bytes = new Uint8Array(38 + zipped.length);
    bytes.set(new TextEncoder().encode("RPA-3.0 0000000000000026 1234ABCD\nDATA"));
    bytes.set(zipped, 38);
    expect(new TextDecoder().decode(await readAll(await extractRenPyMember(new MemorySource(bytes), "script.rpyc")))).toBe("ABDATA");
  });
});
