import { describe, expect, it } from "vitest";
import { writeZip } from "../core/archive/zip";
import { BlobSource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractIpaEntry, inspectIpa } from "./iosIpa";

const NATIVE = `YnBsaXN0MDDZAQIDBAUGBwgJCgsMDQ4QERITXxAaQ0ZCdW5kbGVTaG9ydFZlcnNpb25TdHJpbmdfEBJD
RkJ1bmRsZUlkZW50aWZpZXJfEBhOU0NhbWVyYVVzYWdlRGVzY3JpcHRpb25fEBNDRkJ1bmRsZURpc3Bs
YXlOYW1lXxAcVUlSZXF1aXJlZERldmljZUNhcGFiaWxpdGllc18QEkNGQnVuZGxlRXhlY3V0YWJsZVlG
YWtlVG9rZW5fEA9DRkJ1bmRsZVZlcnNpb25fEBBNaW5pbXVtT1NWZXJzaW9uVTEuMi4zXxATY29tLmV4
YW1wbGUuZml4dHVyZV8QGUZpeHR1cmUgY2FtZXJhIHBlcm1pc3Npb25bRml4dHVyZSBBcHChD1Vhcm02
NFdGaXh0dXJlXxAVRkFLRS1ISURERU4tSVBBLVZBTFVFUjQ1VDE1LjAACAAbADgATQBoAH4AnQCyALwA
zgDhAOcA/QEZASUBJwEtATUBTQFQAAAAAAAAAgEAAAAAAAAAFAAAAAAAAAAAAAAAAAAAAVU=`;
const plist = () => Uint8Array.from(atob(NATIVE.replace(/\s/g, "")), (character) => character.charCodeAt(0));

async function fixture() {
  const archive = await writeZip([{ name: "Payload/Fixture.app/Info.plist", data: new Blob([plist()]) },
    { name: "Payload/Fixture.app/assets/note.txt", data: new Blob(["IPA asset"]) }]);
  return new BlobSource(archive);
}

describe("iOS IPA binary-plist inventory", () => {
  it("matches plutil fields without returning unrelated values and extracts a file explicitly", async () => {
    const source = await fixture();
    const report = await inspectIpa(source);
    expect(report).toMatchObject({ appPath: "Payload/Fixture.app/", bundleId: "com.example.fixture", executable: "Fixture", displayName: "Fixture App",
      version: "1.2.3", build: "45", minimumOS: "15.0", requiredCapabilities: ["arm64"], usageDescriptionKeys: ["NSCameraUsageDescription"], binaryPlist: true, signatureVerified: false });
    expect(JSON.stringify(report)).not.toContain("FAKE-HIDDEN-IPA-VALUE");
    expect(new TextDecoder().decode(await readAll(await extractIpaEntry(source, "Payload/Fixture.app/assets/note.txt")))).toBe("IPA asset");
  });

  it("rejects an IPA without an app Info.plist", async () => {
    const empty = new BlobSource(await writeZip([{ name: "README", data: new Blob(["no app"]) }]));
    await expect(inspectIpa(empty)).rejects.toThrow(/exactly one/);
  });

  it("returns redacted IPA metadata and an explicitly selected file through the registry", async () => {
    const registry = createDefaultRegistry();
    const data = bytesValue(await fixture());
    const inspected = await executeOperation(registry, { operationId: "forensics.ios.ipa.inspect", inputs: { data }, params: {} });
    expect(inspected.run.status).toBe("success");
    expect(inspected.outputs.report).toMatchObject({ type: "structured", data: { bundleId: "com.example.fixture", otherPlistValuesReturned: false } });
    expect(JSON.stringify(inspected.outputs)).not.toContain("FAKE-HIDDEN-IPA-VALUE");
    const extracted = await executeOperation(registry, {
      operationId: "forensics.ios.ipa.extract", inputs: { data }, params: { path: "Payload/Fixture.app/assets/note.txt" },
    });
    expect(extracted.run.status).toBe("success");
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected IPA file bytes");
    expect(new TextDecoder().decode(await readAll(extracted.outputs.data.source))).toBe("IPA asset");
  });
});