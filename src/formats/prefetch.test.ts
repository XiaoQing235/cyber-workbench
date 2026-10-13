import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { inspectPrefetch } from "./prefetch";
import { importWindowsTimeline } from "./windowsTimeline";

const FILETIME = 133801632000000000n;

function prefetchFixture(version: 17 | 23 | 26 | 30, variant: 1 | 2 = 1): Uint8Array<ArrayBuffer> {
  const size = version === 30 ? variant === 1 ? 304 : 296 : ({ 17: 160, 23: 240, 26: 308 } as const)[version];
  const bytes = new Uint8Array(size);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, version, true);
  bytes.set([0x53, 0x43, 0x43, 0x41], 4);
  view.setUint32(12, size, true);
  for (const [index, char] of [..."TOOL.EXE"].entries()) view.setUint16(16 + index * 2, char.charCodeAt(0), true);
  view.setUint32(76, 0xaabbccdd, true);
  if (version === 30) view.setUint32(84, variant === 1 ? 304 : 296, true);
  view.setBigUint64(version === 17 ? 0x78 : 0x80, FILETIME, true);
  if (version === 26 || version === 30) view.setBigUint64(0x88, FILETIME - 600_000_000n, true);
  view.setUint32(version === 17 ? 0x90 : version === 23 ? 0x98 : version === 30 && variant === 2 ? 0xc8 : 0xd0, 7, true);
  return bytes;
}

describe("Windows Prefetch metadata", () => {
  it("inspects the original Plaso CMD.EXE Prefetch file", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/plaso-cmd-prefetch.pf", import.meta.url)));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("34fcc95fb4e8b5c3f3b9898062cfdae0b0f56b1e");
    const report = await inspectPrefetch(new MemorySource(bytes));
    expect(report).toMatchObject({ executable: "CMD.EXE", declaredBytes: 11986, version: 17,
      lastRun: { utc: expect.stringMatching(/^\d{4}-\d{2}-\d{2}T/) } });
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.prefetch.inspect",
      inputs: { data: bytesFrom(bytes) }, params: {} });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: report });
  });
  it("reads independent version-specific SCCA header offsets and timestamps", async () => {
    for (const version of [17, 23, 26] as const) {
      const bytes = prefetchFixture(version);
      const report = await inspectPrefetch(new MemorySource(bytes));
      expect(report).toMatchObject({ version, executable: "TOOL.EXE", hash: "0xaabbccdd", declaredBytes: bytes.length,
        runCount: 7, lastRun: { filetime: FILETIME.toString(), utc: "2025-01-01T00:00:00.000000Z" } });
      expect(report.olderRuns).toHaveLength(version === 26 ? 1 : 0);
      const result = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.prefetch.inspect", inputs: { data: bytesFrom(bytes) }, params: {} });
      expect(result.run.error).toBeUndefined();
      expect(result.outputs.report).toMatchObject({ type: "structured", data: { version, runCount: 7, executable: "TOOL.EXE" } });
    }
  });

  it("rejects MAM compression, unsupported versions, truncated headers and false sizes", async () => {
    const compressed = prefetchFixture(26);
    compressed.set([0x4d, 0x41, 0x4d], 0);
    await expect(inspectPrefetch(new MemorySource(compressed))).rejects.toThrow(/MAM/);
    const unknown = prefetchFixture(30);
    new DataView(unknown.buffer).setUint32(84, 300, true);
    await expect(inspectPrefetch(new MemorySource(unknown))).rejects.toThrow(/variant is unsupported/);
    await expect(inspectPrefetch(new MemorySource(prefetchFixture(26).subarray(0, 100)))).rejects.toThrow(/header or 8 MiB budget/);
    const falseSize = prefetchFixture(17);
    new DataView(falseSize.buffer).setUint32(12, 999, true);
    await expect(inspectPrefetch(new MemorySource(falseSize))).rejects.toThrow(/declared extent differs/);
  });

  it("supports both uncompressed Windows 10 v30 information variants", async () => {
    for (const variant of [1, 2] as const) {
      const report = await inspectPrefetch(new MemorySource(prefetchFixture(30, variant)));
      expect(report).toMatchObject({ version: 30, variant, runCount: 7, olderRuns: [{ utc: "2024-12-31T23:59:00.000000Z" }] });
    }
  });

  it("exports v26 execution history into the offline Windows timeline", async () => {
    const bytes = prefetchFixture(26);
    const result = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.prefetch.timeline-export",
      inputs: { data: bytesFrom(bytes) }, params: { hostname: "LAB" } });
    expect(result.run.error).toBeUndefined();
    if (result.outputs.text?.type !== "text") throw new Error("Expected Prefetch timeline text");
    const timeline = await importWindowsTimeline(result.outputs.text.text, "plaso-jsonl", 0, 3_600);
    expect(timeline).toMatchObject({ total: 2 });
    expect(timeline.events.map((event) => event.utc)).toEqual(["2024-12-31T23:59:00.000000Z", "2025-01-01T00:00:00.000000Z"]);
    expect(result.outputs.text.text).toContain("TOOL.EXE");
  });

  it("retains FILETIME microseconds in Prefetch reports and timeline records", async () => {
    const bytes = prefetchFixture(17);
    new DataView(bytes.buffer).setBigUint64(0x78, FILETIME + 123_450n, true);
    const report = await inspectPrefetch(new MemorySource(bytes));
    expect(report.lastRun).toMatchObject({ utc: "2025-01-01T00:00:00.012345Z", filetime: (FILETIME + 123_450n).toString() });
    const exported = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.prefetch.timeline-export",
      inputs: { data: bytesFrom(bytes) }, params: { hostname: "" } });
    if (exported.outputs.text?.type !== "text") throw new Error("Expected Prefetch timestamp text");
    expect((await importWindowsTimeline(exported.outputs.text.text, "plaso-jsonl", 0, 3_600)).events[0].utc).toBe("2025-01-01T00:00:00.012345Z");
  });
});
