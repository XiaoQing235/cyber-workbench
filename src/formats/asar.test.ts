import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractAsarFile, inspectAsar } from "./asar";

const encoder = new TextEncoder();
const DIGEST = "fe81a4bd98cafa9fedc91b7eaa184baad7685889f150759813cc275f5f568723";

function asar(hash = DIGEST, fileName = "note.txt"): MemorySource {
  const content = encoder.encode("ASAR nested fixture");
  const json = encoder.encode(JSON.stringify({ files: { assets: { files: { [fileName]: { size: content.length, offset: "0", integrity: { algorithm: "SHA256", hash } } } } } }));
  const bufferBytes = Math.ceil((json.length + 4) / 4) * 4;
  const output = new Uint8Array(12 + bufferBytes + content.length);
  const view = new DataView(output.buffer);
  view.setUint32(0, 4, true);
  view.setUint32(4, bufferBytes + 4, true);
  view.setUint32(8, bufferBytes, true);
  view.setUint32(12, json.length, true);
  output.set(json, 16);
  output.set(content, 12 + bufferBytes);
  return new MemorySource(output);
}

describe("Electron ASAR envelope", () => {
  it("reads nested file metadata without trusting declared hashes as verified", async () => {
    const report = await inspectAsar(asar());
    expect(report).toMatchObject({ directories: 1, integrityChecked: false, files: [{ path: "assets/note.txt", bytes: 19, offset: 0, declaredSha256: DIGEST }] });
    const file = await extractAsarFile(asar(), "assets/note.txt");
    expect(file.integrityVerified).toBe(true);
    expect(new TextDecoder().decode(await readAll(file.data))).toBe("ASAR nested fixture");
  });

  it("rejects forged integrity, path traversal, and truncated declared extents", async () => {
    await expect(extractAsarFile(asar("0".repeat(64)), "assets/note.txt")).rejects.toThrow(/failed its declared SHA-256/);
    await expect(inspectAsar(asar(DIGEST, "../escape.txt"))).rejects.toThrow(/unsafe/);
    await expect(inspectAsar(new MemorySource(asar().bytes.slice(0, -1)))).rejects.toThrow(/exceeds archive data/);
    const corrupt = asar().bytes.slice();
    new DataView(corrupt.buffer).setUint32(12, 0xfffffff0, true);
    await expect(inspectAsar(new MemorySource(corrupt))).rejects.toThrow(/header lengths/);
  });

  it("exposes bounded ASAR metadata and explicit verified extraction through Reverse operations", async () => {
    const registry = createDefaultRegistry();
    const data = bytesValue(asar());
    const report = await executeOperation(registry, { operationId: "reverse.asar.inspect", inputs: { data }, params: {} });
    expect(report.run.status).toBe("success");
    expect(report.outputs.report).toMatchObject({ type: "structured", data: { integrityChecked: false, files: [{ path: "assets/note.txt" }] } });
    const extracted = await executeOperation(registry, { operationId: "reverse.asar.extract", inputs: { data }, params: { path: "assets/note.txt" } });
    expect(extracted.run.status).toBe("success");
    expect(extracted.run.diagnostics.join(" ")).toMatch(/SHA-256 verified/);
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected ASAR file bytes");
    expect(new TextDecoder().decode(await readAll(extracted.outputs.data.source))).toBe("ASAR nested fixture");
  });
});