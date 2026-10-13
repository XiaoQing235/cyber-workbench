import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { MemorySource, readAll } from "../core/bytes/sources";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { applyOciLayers, extractVisibleOciFile, inspectOciImage, inspectOciLayer } from "./ociLayer";

const encoder = new TextEncoder();

function layer(members: { path: string; data: string | Uint8Array; type?: string }[]): Uint8Array<ArrayBuffer> {
  const chunks: Uint8Array[] = [];
  for (const member of members) {
    const header = new Uint8Array(512);
    header.set(encoder.encode(member.path));
    const content = typeof member.data === "string" ? encoder.encode(member.data) : member.data;
    header.set(encoder.encode(content.length.toString(8).padStart(11, "0") + "\0"), 124);
    header.fill(0x20, 148, 156);
    header[156] = member.type?.charCodeAt(0) ?? 0x30;
    header.set(encoder.encode("ustar\0"), 257);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.set(encoder.encode(checksum.toString(8).padStart(6, "0") + "\0 "), 148);
    chunks.push(header, content, new Uint8Array((512 - content.length % 512) % 512));
  }
  chunks.push(new Uint8Array(1024));
  const bytes = new Uint8Array(chunks.reduce((sum, chunk) => sum + chunk.length, 0));
  let position = 0;
  for (const chunk of chunks) { bytes.set(chunk, position); position += chunk.length; }
  return bytes;
}

function pax(key: string, value: string): string {
  const body = ` ${key}=${value}\n`;
  let length = body.length + 1;
  while (String(length).length + body.length !== length) length = String(length).length + body.length;
  return `${length}${body}`;
}

describe("OCI layer whiteouts", () => {
  it("classifies ordinary files, deletion markers, and opaque directories", async () => {
    const report = await inspectOciLayer(new MemorySource(layer([
      { path: "./etc/new.conf", data: "new" }, { path: "./var/.wh.old.txt", data: "" }, { path: "./etc/.wh..wh..opq", data: "" },
    ])));
    expect(report).toMatchObject({ files: 1, whiteouts: 1, opaqueDirectories: 1, regularFilesOnly: true });
    expect(report.entries).toEqual([
      { path: "etc/new.conf", kind: "file", bytes: 3, target: null },
      { path: "var/.wh.old.txt", kind: "whiteout", bytes: 0, target: "var/old.txt" },
      { path: "etc/.wh..wh..opq", kind: "opaque", bytes: 0, target: "etc" },
    ]);
  });

  it("rejects nonempty markers, traversal, and damaged tar checksums", async () => {
    await expect(inspectOciLayer(new MemorySource(layer([{ path: ".wh.secret", data: "x" }])))).rejects.toThrow(/must be empty/);
    await expect(inspectOciLayer(new MemorySource(layer([{ path: "../outside", data: "x" }])))).rejects.toThrow(/unsafe path/);
    const damaged = layer([{ path: "etc/a", data: "x" }]);
    damaged[0] ^= 1;
    await expect(inspectOciLayer(new MemorySource(damaged))).rejects.toThrow(/checksum/);
    const truncated = layer([{ path: "etc/a", data: "x" }]).slice(0, 513);
    await expect(inspectOciLayer(new MemorySource(truncated))).rejects.toThrow(/member exceeds the archive/);
  });

  it("uses PAX long-path overrides and rejects malformed or conflicting extensions", async () => {
    const path = `etc/${"long-directory/".repeat(8)}config.txt`;
    const archive = layer([{ path: "PaxHeaders", type: "x", data: pax("path", path) }, { path: "short.txt", data: "contents" }]);
    expect((await inspectOciLayer(new MemorySource(archive))).entries[0].path).toBe(path);
    await expect(inspectOciLayer(new MemorySource(layer([{ path: "PaxHeaders", type: "x", data: "99 path=bad\n" }, { path: "short.txt", data: "x" }])))).rejects.toThrow(/PAX record exceeds/);
    await expect(inspectOciLayer(new MemorySource(layer([{ path: "PaxHeaders", type: "x", data: pax("size", "999") }, { path: "short.txt", data: "x" }])))).rejects.toThrow(/PAX size disagrees/);
  });

  it("lists layer whiteouts through the Forensics operation without reading payloads", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.oci.layer.inspect", inputs: { data: bytesFrom(layer([
        { path: "etc/.wh..wh..opq", data: "" }, { path: "etc/new.conf", data: "new" },
      ])) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { opaqueDirectories: 1, files: 1 } });
  });

  it("applies upper-layer whiteouts and opacity before keeping same-layer additions", async () => {
    const base = await inspectOciLayer(new MemorySource(layer([
      { path: "etc/keep.conf", data: "keep" }, { path: "etc/old.conf", data: "old" }, { path: "var/data.txt", data: "data" },
    ])));
    const upper = await inspectOciLayer(new MemorySource(layer([
      { path: "etc/new.conf", data: "new" }, { path: "var/.wh.data.txt", data: "" }, { path: "etc/.wh..wh..opq", data: "" },
    ])));
    const merged = applyOciLayers([base, upper]);
    expect(merged).toMatchObject({ layers: 2, visible: [{ path: "etc/new.conf", layer: 1, bytes: 3 }] });
    expect(merged.hidden).toEqual(expect.arrayContaining([
      { path: "etc/keep.conf", layer: 1, reason: "opaque" },
      { path: "etc/old.conf", layer: 1, reason: "opaque" },
      { path: "var/data.txt", layer: 1, reason: "whiteout" },
    ]));
  });

  it("merges ordered Docker-save layer members from one bounded tar input", async () => {
    const base = layer([{ path: "etc/keep.conf", data: "keep" }, { path: "var/data.txt", data: "data" }]);
    const upper = layer([{ path: "etc/new.conf", data: "new" }, { path: "etc/.wh..wh..opq", data: "" }, { path: "var/.wh.data.txt", data: "" }]);
    const manifest = JSON.stringify([{ Config: "config.json", RepoTags: ["fixture:latest"], Layers: ["base/layer.tar", "upper/layer.tar"] }]);
    const archive = layer([{ path: "manifest.json", data: manifest }, { path: "base/layer.tar", data: base }, { path: "upper/layer.tar", data: upper }]);
    const merged = await inspectOciImage(new MemorySource(archive));
    expect(merged).toMatchObject({ layers: 2, repositoryTags: ["fixture:latest"], visible: [{ path: "etc/new.conf", layer: 1 }] });
    expect(merged.hidden).toEqual(expect.arrayContaining([{ path: "var/data.txt", layer: 1, reason: "whiteout" }, { path: "etc/keep.conf", layer: 1, reason: "opaque" }]));
    expect(new TextDecoder().decode(await readAll(await extractVisibleOciFile(new MemorySource(archive), "etc/new.conf")))).toBe("new");
    await expect(extractVisibleOciFile(new MemorySource(archive), "etc/keep.conf")).rejects.toThrow(/not visible/);
    await expect(extractVisibleOciFile(new MemorySource(archive), "var/data.txt")).rejects.toThrow(/not visible/);
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.oci.image.inspect", inputs: { data: bytesFrom(archive) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { layers: 2, visible: [{ path: "etc/new.conf", layer: 1 }] } });
    const extracted = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.oci.image.extract", inputs: { data: bytesFrom(archive) }, params: { path: "etc/new.conf" },
    });
    expect(extracted.run.status).toBe("success");
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected visible OCI file bytes");
    expect(new TextDecoder().decode(await readAll(extracted.outputs.data.source))).toBe("new");
    const hidden = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.oci.image.extract", inputs: { data: bytesFrom(archive) }, params: { path: "etc/keep.conf" },
    });
    expect(hidden.run.error?.code).toBe("INVALID_INPUT");
    const badManifest = layer([{ path: "manifest.json", data: JSON.stringify([{ Layers: ["../escape/layer.tar"] }]) }]);
    await expect(inspectOciImage(new MemorySource(badManifest))).rejects.toThrow(/unsafe path/);
  });
});