import { describe, expect, it } from "vitest";
import { writeZip } from "../core/archive/zip";
import { BlobSource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractJavaEntry, inspectJavaArchive } from "./javaArchive";

async function jar(className = "Hello.class") {
  const manifest = "Manifest-Version: 1.0\r\nMain-Class: Hello\r\nX-Token: FAKE-HIDDEN-MANIFEST-SECRET\r\n\r\n";
  const classBytes = Uint8Array.of(0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 68, 0x7b);
  const archive = await writeZip([
    { name: "META-INF/MANIFEST.MF", data: new Blob([manifest]) },
    { name: className, data: new Blob([classBytes]) },
  ]);
  return { source: new BlobSource(archive), classBytes };
}

describe("Java JAR offline inspection", () => {
  it("reports selected manifest fields, class major and entries without leaking extra manifest values", async () => {
    const fixture = await jar();
    const report = await inspectJavaArchive(fixture.source);
    expect(report).toMatchObject({ manifest: { version: "1.0", mainClass: "Hello" }, firstClassMajor: 68, classes: 1, signatureVerified: false });
    expect(report.entries.some((entry) => entry.path === "Hello.class" && entry.bytes === fixture.classBytes.length)).toBe(true);
    expect(JSON.stringify(report)).not.toContain("FAKE-HIDDEN-MANIFEST-SECRET");
    expect(await readAll(await extractJavaEntry(fixture.source, "Hello.class"))).toEqual(fixture.classBytes);
  });

  it("rejects unsafe paths and unknown entries before extracting", async () => {
    const fixture = await jar("../escape.class");
    await expect(inspectJavaArchive(fixture.source)).rejects.toThrow(/traversal/);
    const safe = await jar();
    await expect(extractJavaEntry(safe.source, "missing.class")).rejects.toThrow(/missing/);
  });

  it("exposes selected JAR metadata and CRC-checked extraction through Reverse operations", async () => {
    const { source, classBytes } = await jar();
    const registry = createDefaultRegistry();
    const data = bytesValue(source);
    const inspected = await executeOperation(registry, { operationId: "reverse.java.jar.inspect", inputs: { data }, params: {} });
    expect(inspected.run.status).toBe("success");
    expect(inspected.outputs.report).toMatchObject({ type: "structured", data: { firstClassMajor: 68, classes: 1 } });
    const extracted = await executeOperation(registry, { operationId: "reverse.java.jar.extract", inputs: { data }, params: { path: "Hello.class" } });
    expect(extracted.run.status).toBe("success");
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected JAR entry bytes");
    expect(await readAll(extracted.outputs.data.source)).toEqual(classBytes);
  });
});