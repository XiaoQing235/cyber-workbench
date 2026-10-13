import fixtureUrl from "./testing/pyinstaller-6.16.pkg?inline";
import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractPyInstallerEntry, inspectPyInstaller } from "./pyInstaller";
import { extractPyInstallerPyc } from "./pyInstaller";
import { extractPythonMarshal, inspectPythonBytecode } from "./pythonBytecode";

const fixture = Uint8Array.from(atob(fixtureUrl.slice(fixtureUrl.indexOf(",") + 1)), (character) => character.charCodeAt(0));
const source = (bytes: Uint8Array = fixture) => new MemorySource(bytes.slice());

describe("PyInstaller CArchive", () => {
  it("lists and extracts entries from an official PyInstaller 6.16 writer", async () => {
    const report = await inspectPyInstaller(source());
    expect(report).toMatchObject({ pythonVersion: "3.13", pythonLibrary: "libpython3.13.dylib", archiveOffset: 0, archiveEnd: 354,
      tocBytes: 80, trailingBytes: 0, executed: false });
    expect(report.entries).toMatchObject([
      { name: "packed_main", typecode: "s", offset: 0, storedBytes: 146, unpackedBytes: 167, compressed: true },
      { name: "assets/data.txt", typecode: "x", offset: 146, storedBytes: 40, unpackedBytes: 32, compressed: true },
    ]);
    const extracted = await extractPyInstallerEntry(source(), "assets/data.txt");
    expect(new TextDecoder().decode(await readAll(extracted.data))).toBe("PyInstaller archive fixture data");
    expect((await readAll((await extractPyInstallerEntry(source(), "packed_main")).data)).length).toBe(167);
  });

  it("finds the official archive inside a binary with a prefix and trailing padding", async () => {
    const embedded = new Uint8Array(100 + fixture.length + 80);
    embedded.set(fixture, 100);
    const report = await inspectPyInstaller(source(embedded));
    expect(report).toMatchObject({ archiveOffset: 100, archiveEnd: 454, trailingBytes: 80,
      entries: [{ name: "packed_main", offset: 100 }, { name: "assets/data.txt", offset: 246 }] });
    const { data } = await extractPyInstallerEntry(source(embedded), "assets/data.txt");
    expect(new TextDecoder().decode(await readAll(data))).toBe("PyInstaller archive fixture data");
  });

  it("rejects forged offsets, traversal, broken cookie and corrupt compressed bytes", async () => {
    const cookie = fixture.slice();
    cookie[fixture.length - 88] = 0;
    await expect(inspectPyInstaller(source(cookie))).rejects.toThrow(/cookie/);
    const extent = fixture.slice();
    new DataView(extent.buffer).setUint32(186 + 4, 186, false);
    await expect(inspectPyInstaller(source(extent))).rejects.toThrow(/extent/);
    const traversal = fixture.slice();
    traversal.set(new TextEncoder().encode("../bad.txt"), 186 + 18);
    await expect(inspectPyInstaller(source(traversal))).rejects.toThrow(/unsafe/);
    const corrupt = fixture.slice();
    corrupt[146] ^= 1;
    await expect(extractPyInstallerEntry(source(corrupt), "assets/data.txt")).rejects.toThrow(/zlib decompression/);
  });

  it("reconstructs a synthetic 3.13 PYC header without unmarshalling its script", async () => {
    const reconstructed = await extractPyInstallerPyc(source(), "packed_main");
    expect(reconstructed).toMatchObject({ pythonVersion: "3.13", marshalBytes: 167 });
    expect(await inspectPythonBytecode(reconstructed.data)).toMatchObject({ pythonVersion: "3.13", sourceSize: 0, marshalBytes: 167, executed: false });
    expect(await readAll(await extractPythonMarshal(reconstructed.data))).toEqual(await readAll((await extractPyInstallerEntry(source(), "packed_main")).data));
    await expect(extractPyInstallerPyc(source(), "assets/data.txt")).rejects.toThrow(/marshaled Python/);
    const unsupported = fixture.slice();
    new DataView(unsupported.buffer).setUint32(unsupported.length - 88 + 20, 314, false);
    await expect(extractPyInstallerPyc(source(unsupported), "packed_main")).rejects.toThrow(/No supported .pyc magic/);
  });

  it("runs static Reverse operations without executing the contained Python script", async () => {
    const registry = createDefaultRegistry();
    const data = bytesValue(source());
    const inspected = await executeOperation(registry, { operationId: "reverse.pyinstaller.inspect", inputs: { data }, params: {} });
    expect(inspected.run.status).toBe("success");
    expect(inspected.outputs.report).toMatchObject({ type: "structured", data: { pythonVersion: "3.13", executed: false,
      entries: [{ name: "packed_main", typecode: "s" }, { name: "assets/data.txt", typecode: "x" }] } });
    const extracted = await executeOperation(registry, { operationId: "reverse.pyinstaller.extract", inputs: { data }, params: { name: "assets/data.txt" } });
    expect(extracted.run.status).toBe("success");
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected PyInstaller bytes");
    expect(new TextDecoder().decode(await readAll(extracted.outputs.data.source))).toBe("PyInstaller archive fixture data");
    const rebuilt = await executeOperation(registry, { operationId: "reverse.pyinstaller.pyc-rebuild", inputs: { data }, params: { name: "packed_main" } });
    expect(rebuilt.run.status).toBe("success");
    expect(rebuilt.outputs.report).toMatchObject({ type: "structured", data: { pythonVersion: "3.13", marshalBytes: 167, syntheticHeader: true, executed: false } });
    if (rebuilt.outputs.data?.type !== "bytes") throw new Error("Expected a reconstructed .pyc");
    const checked = await executeOperation(registry, { operationId: "reverse.python.pyc.inspect", inputs: { data: rebuilt.outputs.data }, params: {} });
    expect(checked.outputs.report).toMatchObject({ type: "structured", data: { pythonVersion: "3.13", marshalBytes: 167, executed: false } });
  });
});
