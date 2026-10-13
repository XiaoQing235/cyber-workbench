import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractUnityTextAsset, inspectUnityBundle } from "./unityBundle";

const fixture = (variant: "uncompressed" | "lz4") => new Uint8Array(readFileSync(new URL(`./testing/unity-2019-shared-${variant}.bundle`, import.meta.url)));

describe("bounded UnityFS game assets", () => {
  it("matches a Unity-editor-produced TextAsset through raw and LZ4 bundles", async () => {
    for (const variant of ["uncompressed", "lz4"] as const) {
      const bytes = fixture(variant);
      const report = await inspectUnityBundle(new MemorySource(bytes));
      expect(report).toMatchObject({ format: "UnityFS", version: 7, unityRevision: "2019.4.41f2", packedBytes: bytes.length,
        files: [{ path: "CAB-71fca072df859359e7a6b09ff7151c53", bytes: 4_316 }] });
      expect(report.assets.find((asset) => asset.type === "TextAsset")).toMatchObject({ name: "hello",
        path: "assets/fixtures/shared/hello.txt", bytes: 76 });
      const result = await executeOperation(createDefaultRegistry(), { operationId: "reverse.unity.bundle.inspect", inputs: { data: bytesFrom(bytes) }, params: {} });
      expect(result.run.error).toBeUndefined();
      expect(result.outputs.report).toMatchObject({ type: "structured", data: { version: 7, unityRevision: "2019.4.41f2" } });
      const extracted = await extractUnityTextAsset(new MemorySource(bytes), "assets/fixtures/shared/hello.txt");
      expect(extracted.name).toBe("hello");
      expect(new TextDecoder().decode(extracted.data)).toBe("Hello from unity-asset-reader fixtures.\nLine 2: é€😀\n");
      expect(createHash("sha256").update(extracted.data).digest("hex")).toBe("3606049155e66b287de2e2ff7d5c19473df8c3f6ae817c2c67856ff74783ba06");
      const extraction = await executeOperation(createDefaultRegistry(), { operationId: "reverse.unity.textasset.extract",
        inputs: { data: bytesFrom(bytes) }, params: { path: "assets/fixtures/shared/hello.txt" } });
      expect(extraction.run.error).toBeUndefined();
      if (extraction.outputs.data?.type !== "bytes") throw new Error("Expected Unity TextAsset bytes");
      expect(await extraction.outputs.data.source.read(0, 58)).toEqual(extracted.data);
    }
  });

  it("reads the same TextAsset from a Unity 6000 UnityFS v8 bundle", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/unity-6000-shared-lz4.bundle", import.meta.url)));
    const report = await inspectUnityBundle(new MemorySource(bytes));
    expect(report).toMatchObject({ format: "UnityFS", version: 8, unityRevision: "6000.3.25f1", packedBytes: 1_241,
      files: [{ path: "CAB-71fca072df859359e7a6b09ff7151c53", bytes: 2_832 }] });
    expect(report.assets.find((asset) => asset.type === "TextAsset")).toMatchObject({ name: "hello", path: "assets/fixtures/shared/hello.txt" });
    const extracted = await extractUnityTextAsset(new MemorySource(bytes), "assets/fixtures/shared/hello.txt");
    expect(createHash("sha256").update(extracted.data).digest("hex")).toBe("3606049155e66b287de2e2ff7d5c19473df8c3f6ae817c2c67856ff74783ba06");
  });

  it("rejects bogus bundle extents, expanded blocks and unknown formats before loading", async () => {
    const inflated = fixture("lz4");
    const view = new DataView(inflated.buffer);
    view.setUint32(40, 0x7fffffff);
    await expect(inspectUnityBundle(new MemorySource(inflated))).rejects.toThrow(/blocks-info budget/);
    const forgedOutput = fixture("uncompressed");
    new DataView(forgedOutput.buffer).setUint32(42, 0x7fffffff);
    await expect(inspectUnityBundle(new MemorySource(forgedOutput))).rejects.toThrow(/blocks-info budget/);
    const altered = fixture("uncompressed");
    altered[0] ^= 1;
    await expect(inspectUnityBundle(new MemorySource(altered))).rejects.toThrow(/Only standalone UnityFS/);
    await expect(inspectUnityBundle(new MemorySource(fixture("lz4").subarray(0, 200)))).rejects.toThrow(/bundle extent/);
    await expect(extractUnityTextAsset(new MemorySource(fixture("lz4")), "missing.txt")).rejects.toThrow(/does not exist/);
  });
});