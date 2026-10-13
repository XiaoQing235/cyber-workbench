import { describe, expect, it } from "vitest";
import { writeZip } from "../core/archive/zip";
import { BlobSource, MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractApkDex, inspectAndroidManifest, inspectApk } from "./androidManifest";

describe("Android binary XML manifest guard", () => {
  it("rejects a rootless AXML chunk despite the underlying parser accepting it", async () => {
    const rootless = Uint8Array.of(3, 0, 8, 0, 8, 0, 0, 0);
    await expect(inspectAndroidManifest(new MemorySource(rootless))).rejects.toThrow(/no manifest root/);
  });

  it("rejects truncated or inconsistent binary XML boundaries", async () => {
    await expect(inspectAndroidManifest(new MemorySource(Uint8Array.of(3, 0, 8, 0, 9, 0, 0, 0)))).rejects.toThrow(/invalid XML boundaries/);
  });
  const NATIVE = `AwAIAIAGAAABABwAvAMAABsAAAAAAAAAAAAAAIgAAAAAAAAAAAAAAA4AAAAaAAAAMgAAAEYAAABkAAAA
fgAAAJgAAAC8AAAA1gAAAPwAAAAyAQAAUAEAAFoBAABiAQAAdAEAAIgBAACaAQAA1AEAAO4BAAAYAgAA
cAIAAIQCAACWAgAAygIAAP4CAAAgAwAABQBsAGEAYgBlAGwAAAAEAG4AYQBtAGUAAAAKAGQAZQBiAHUA
ZwBnAGEAYgBsAGUAAAAIAGUAeABwAG8AcgB0AGUAZAAAAA0AbQBpAG4AUwBkAGsAVgBlAHIAcwBpAG8A
bgAAAAsAdgBlAHIAcwBpAG8AbgBDAG8AZABlAAAACwB2AGUAcgBzAGkAbwBuAE4AYQBtAGUAAAAQAHQA
YQByAGcAZQB0AFMAZABrAFYAZQByAHMAaQBvAG4AAAALAGEAbABsAG8AdwBCAGEAYwBrAHUAcAAAABEA
YwBvAG0AcABpAGwAZQBTAGQAawBWAGUAcgBzAGkAbwBuAAAAGQBjAG8AbQBwAGkAbABlAFMAZABrAFYA
ZQByAHMAaQBvAG4AQwBvAGQAZQBuAGEAbQBlAAAADQAuAE0AYQBpAG4AQQBjAHQAaQB2AGkAdAB5AAAA
AwAxAC4AMAAAAAIAMQA1AAAABwBGAGkAeAB0AHUAcgBlAAAACABhAGMAdABpAHYAaQB0AHkAAAAHAGEA
bgBkAHIAbwBpAGQAAAAbAGEAbgBkAHIAbwBpAGQALgBwAGUAcgBtAGkAcwBzAGkAbwBuAC4ASQBOAFQA
RQBSAE4ARQBUAAAACwBhAHAAcABsAGkAYwBhAHQAaQBvAG4AAAATAGMAbwBtAC4AZQB4AGEAbQBwAGwA
ZQAuAGYAaQB4AHQAdQByAGUAAAAqAGgAdAB0AHAAOgAvAC8AcwBjAGgAZQBtAGEAcwAuAGEAbgBkAHIA
bwBpAGQALgBjAG8AbQAvAGEAcABrAC8AcgBlAHMALwBhAG4AZAByAG8AaQBkAAAACABtAGEAbgBpAGYA
ZQBzAHQAAAAHAHAAYQBjAGsAYQBnAGUAAAAYAHAAbABhAHQAZgBvAHIAbQBCAHUAaQBsAGQAVgBlAHIA
cwBpAG8AbgBDAG8AZABlAAAAGABwAGwAYQB0AGYAbwByAG0AQgB1AGkAbABkAFYAZQByAHMAaQBvAG4A
TgBhAG0AZQAAAA8AdQBzAGUAcwAtAHAAZQByAG0AaQBzAHMAaQBvAG4AAAAIAHUAcwBlAHMALQBzAGQA
awAAAIABCAA0AAAAAQABAQMAAQEPAAEBEAABAQwCAQEbAgEBHAIBAXACAQGAAgEBcgUBAXMFAQEAARAA
GAAAAAIAAAD/////EAAAABQAAAACARAAsAAAAAIAAAD//////////xUAAAAUABQABwAAAAAAAAAUAAAA
BQAAAP////8IAAAQAQAAABQAAAAGAAAADAAAAAgAAAMMAAAAFAAAAAkAAAD/////CAAAECMAAAAUAAAA
CgAAAA0AAAAIAAADDQAAAP////8WAAAAEwAAAAgAAAMTAAAA/////xcAAAD/////CAAAECMAAAD/////
GAAAAP////8IAAAQDwAAAAIBEABMAAAABgAAAP//////////GgAAABQAFAACAAAAAAAAABQAAAAEAAAA
/////wgAABAVAAAAFAAAAAcAAAD/////CAAAECMAAAADARAAGAAAAAYAAAD//////////xoAAAACARAA
OAAAAAcAAAD//////////xkAAAAUABQAAQAAAAAAAAAUAAAAAQAAABEAAAAIAAADEQAAAAMBEAAYAAAA
BwAAAP//////////GQAAAAIBEABgAAAACAAAAP//////////EgAAABQAFAADAAAAAAAAABQAAAAAAAAA
DgAAAAgAAAMOAAAAFAAAAAIAAAD/////CAAAEv////8UAAAACAAAAP////8IAAAS/////wIBEABMAAAA
CQAAAP//////////DwAAABQAFAACAAAAAAAAABQAAAABAAAACwAAAAgAAAMLAAAAFAAAAAMAAAD/////
CAAAEv////8DARAAGAAAAAkAAAD//////////w8AAAADARAAGAAAAAgAAAD//////////xIAAAADARAA
GAAAAAIAAAD//////////xUAAAABARAAGAAAAAIAAAD/////EAAAABQAAAA=`;
  const native = () => new MemorySource(Uint8Array.from(atob(NATIVE.replace(/\s/g, "")), (character) => character.charCodeAt(0)));

  it("matches aapt2 package, permissions, SDK and exported activity metadata", async () => {
    const report = await inspectAndroidManifest(native());
    expect(report).toMatchObject({ packageName: "com.example.fixture", versionCode: "1", minSdk: "21", targetSdk: "35",
      permissions: ["android.permission.INTERNET"], application: { debuggable: "true", allowBackup: "true" },
      exportedComponents: [{ kind: "activity", name: ".MainActivity" }], binaryXmlBytes: 1664 });
    expect(JSON.stringify(report)).not.toContain("Fixture");
  });

  it("inspects APK manifest and extracts selected DEX without treating signature artifacts as verified", async () => {
    const dex = Uint8Array.of(0x64, 0x65, 0x78, 0x0a);
    const archive = await writeZip([{ name: "AndroidManifest.xml", data: new Blob([native().bytes]) },
      { name: "classes.dex", data: new Blob([dex]) }, { name: "META-INF/FIXTURE.SF", data: new Blob(["claims only"]) }]);
    const source = new BlobSource(archive);
    const report = await inspectApk(source);
    expect(report).toMatchObject({ manifest: { packageName: "com.example.fixture" }, dexFiles: [{ path: "classes.dex", bytes: 4 }], signatureArtifacts: ["META-INF/FIXTURE.SF"], signatureVerified: false });
    expect(await readAll(await extractApkDex(source, 0))).toEqual(dex);
    await expect(extractApkDex(source, 1)).rejects.toThrow(/out of range/);
    const registry = createDefaultRegistry();
    const input = bytesValue(source);
    const inspected = await executeOperation(registry, { operationId: "reverse.android.apk.inspect", inputs: { data: input }, params: {} });
    expect(inspected.run.status).toBe("success");
    expect(inspected.outputs.report).toMatchObject({ type: "structured", data: { manifest: { packageName: "com.example.fixture" }, signatureVerified: false } });
    const extracted = await executeOperation(registry, { operationId: "reverse.android.apk.dex-extract", inputs: { data: input }, params: {} });
    expect(extracted.run.status).toBe("success");
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected APK DEX bytes");
    expect(await readAll(extracted.outputs.data.source)).toEqual(dex);
  });
});