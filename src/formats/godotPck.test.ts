import fixtureUrl from "./testing/godot-4.7.2.pck?inline";
import encryptedUrl from "./testing/godot-4.7.2-encrypted.pck?inline";
import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractGodotPckFile, inspectGodotPck } from "./godotPck";

const fixture = Uint8Array.from(atob(fixtureUrl.slice(fixtureUrl.indexOf(",") + 1)), (character) => character.charCodeAt(0));
const encryptedFixture = Uint8Array.from(atob(encryptedUrl.slice(encryptedUrl.indexOf(",") + 1)), (character) => character.charCodeAt(0));
const source = (bytes: Uint8Array = fixture) => new MemorySource(bytes.slice());

describe("Godot V4 PCK archive", () => {
  it("inventories and extracts a file produced by official Godot 4.7.2", async () => {
    const report = await inspectGodotPck(source());
    expect(report).toMatchObject({ formatVersion: 4, engineVersion: "4.7.2", fileBase: 128, directoryOffset: 192,
      encryptedDirectory: false, trailingBytes: 0, files: [{ path: "levels/hello.txt", offset: 128, size: 38, md5: "e41f6f397dc1b843b5346275a9464855", encrypted: false }] });
    const extracted = await extractGodotPckFile(source(), "levels/hello.txt");
    expect(extracted.md5Matched).toBe(true);
    expect(new TextDecoder().decode(await readAll(extracted.data))).toBe("Hello from official Godot PCK fixture.");
  });

  it("rejects unsafe paths, truncated extents, and corrupt member checksums", async () => {
    const unsafe = fixture.slice();
    unsafe.set(new TextEncoder().encode("../escape.txtxxx"), 200);
    await expect(inspectGodotPck(source(unsafe))).rejects.toThrow(/unsafe/);
    const outside = fixture.slice();
    new DataView(outside.buffer).setBigUint64(216, 0xffffffffn, true);
    await expect(inspectGodotPck(source(outside))).rejects.toThrow(/exceeds packed file data/);
    const corrupt = fixture.slice();
    corrupt[128] ^= 1;
    await expect(extractGodotPckFile(source(corrupt), "levels/hello.txt")).rejects.toThrow(/MD5 checksum/);
  });

  it("reports an encrypted directory without treating ciphertext as file metadata", async () => {
    expect(await inspectGodotPck(source(encryptedFixture))).toMatchObject({ engineVersion: "4.7.2", fileBase: 128, directoryOffset: 224,
      encryptedDirectory: true, files: [], trailingBytes: null });
    await expect(extractGodotPckFile(source(encryptedFixture), "levels/hello.txt")).rejects.toThrow(/encrypted directory/);
  });

  it("exposes inventory and explicit extraction through Reverse operations", async () => {
    const registry = createDefaultRegistry();
    const data = bytesValue(source());
    const inspected = await executeOperation(registry, { operationId: "reverse.godot-pck.inspect", inputs: { data }, params: {} });
    expect(inspected.run.status).toBe("success");
    expect(inspected.outputs.report).toMatchObject({ type: "structured", data: { files: [{ path: "levels/hello.txt" }] } });
    const extracted = await executeOperation(registry, { operationId: "reverse.godot-pck.extract", inputs: { data }, params: { path: "levels/hello.txt" } });
    expect(extracted.run.status).toBe("success");
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected Godot member bytes");
    expect(new TextDecoder().decode(await readAll(extracted.outputs.data.source))).toBe("Hello from official Godot PCK fixture.");
    expect(extracted.run.diagnostics).toEqual(["Extracted levels/hello.txt (38 bytes); its declared MD5 matched (not an authenticity proof)."]);
  });
});
