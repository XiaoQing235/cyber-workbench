import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { inspectLnk } from "./lnk";
import { importWindowsTimeline } from "./windowsTimeline";

const SHORTCUT = Uint8Array.from(atob("TAAAAAEUAgAAAAAAwAAAAAAAAEadAQAAAAAAAACYX+KgXNsBAPYvlaFc2wEAVABIolzbAQAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAKMAFAAfUOBP0CDqOmkQotgIACswMJ0ZAC9DOlwAAAAAAAAAAAAAAAAAAAAAAAAANAAyAAAAAABLXUifEABUZW1wAAAgAAMABADvvktdSJ9LXUifFAAAAFQAZQBtAHAAAAAUAEAAMgAAAAAAS11InxAAdG9vbC5leGUAACgAAwAEAO++S11In0tdSJ8UAAAAdABvAG8AbAAuAGUAeABlAAAAGAAAABAARgBpAHgAdAB1AHIAZQAgAHMAaABvAHIAdABjAHUAdAAQAEMAOgBcAFQAZQBtAHAAXAB0AG8AbwBsAC4AZQB4AGUABwBDADoAXABUAGUAbQBwAAAAAAA="), (character) => character.charCodeAt(0));
const REMOTE_PREFIX = Uint8Array.from(atob("TAAAAAEUAgAAAAAAwAAAAAAAAEaGAgAAAAAAAAAVgeZeWd0BABWB5l5Z3QEAFYHmXlndAQAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAEgAAAAcAAAAAgAAAAAAAAAAAAAAHAAAAEcAAAArAAAAAgAAABQAAAAAAAAAAAACAFxcU0VSVkVSXFNIQVJFAHRvb2wuZXhlAA4AUgBlAG0AbwB0AGUAIABmAGkAeAB0AHUAcgBlAA=="), (character) => character.charCodeAt(0));

function remoteShortcut(): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(REMOTE_PREFIX.length + 788 + 4);
  bytes.set(REMOTE_PREFIX);
  const view = new DataView(bytes.buffer);
  view.setUint32(REMOTE_PREFIX.length, 788, true);
  view.setUint32(REMOTE_PREFIX.length + 4, 0xa0000001, true);
  const target = "\\\\SERVER\\share\\tool.exe";
  bytes.set(new TextEncoder().encode(target), REMOTE_PREFIX.length + 8);
  for (let index = 0; index < target.length; index++) view.setUint16(REMOTE_PREFIX.length + 268 + index * 2, target.charCodeAt(index), true);
  return bytes;
}

describe("Windows ShellLink inspection", () => {
  it("inspects the original Plaso NeroInfoTool shortcut", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/plaso-nero-shortcut.lnk", import.meta.url)));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("366b5fe1d579cff479062ac663d913a73b21ce43");
    const report = await inspectLnk(new MemorySource(bytes));
    expect(report).toMatchObject({ hasLinkInfo: true, targetPath: "C:\\Program Files (x86)\\Nero\\Nero 9\\Nero InfoTool\\InfoTool.exe",
      created: { utc: expect.stringMatching(/^\d{4}-/) } });
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.lnk.inspect",
      inputs: { data: bytesFrom(bytes) }, params: {} });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: report });
  });
  it("reads a real shortcut's bounded Unicode strings and exact FILETIMEs", async () => {
    const report = await inspectLnk(new MemorySource(SHORTCUT));
    expect(report).toMatchObject({
      targetPath: "C:\\Temp\\tool.exe", relativePath: "C:\\Temp\\tool.exe", workingDirectory: "C:\\Temp",
      description: "Fixture shortcut", hasLinkInfo: false,
      created: { utc: "2025-01-01T23:00:00.000000Z" },
      accessed: { utc: "2025-01-01T23:05:00.000000Z" },
      modified: { utc: "2025-01-01T23:10:00.000000Z" },
    });
    expect(report.created?.filetime).toMatch(/^\d{17,18}$/);
    expect(report.idListBytes).toBeGreaterThan(0);
  });

  it("rejects invalid signatures and truncated ID list extents", async () => {
    const invalid = SHORTCUT.slice();
    invalid[4] ^= 1;
    await expect(inspectLnk(new MemorySource(invalid))).rejects.toThrow(/not a ShellLink/);
    const truncated = SHORTCUT.slice();
    new DataView(truncated.buffer).setUint16(76, 0xffff, true);
    await expect(inspectLnk(new MemorySource(truncated))).rejects.toThrow(/ID list exceeds/);
  });

  it("resolves an explicit UNC target without treating the network share as the target file", async () => {
    const report = await inspectLnk(new MemorySource(remoteShortcut()));
    expect(report).toMatchObject({
      targetPath: "\\\\SERVER\\share\\tool.exe", targetSource: "environment", networkShare: "\\\\SERVER\\SHARE", hasLinkInfo: true,
    });
    const badNetwork = remoteShortcut();
    new DataView(badNetwork.buffer).setUint32(76 + 20, 0xffff, true);
    await expect(inspectLnk(new MemorySource(badNetwork))).rejects.toThrow(/network LinkInfo offset is invalid/);
    const badSuffix = remoteShortcut();
    new DataView(badSuffix.buffer).setUint32(76 + 24, 16, true);
    await expect(inspectLnk(new MemorySource(badSuffix))).rejects.toThrow(/path points into its header/);
    const badBlock = remoteShortcut();
    new DataView(badBlock.buffer).setUint32(REMOTE_PREFIX.length, 789, true);
    await expect(inspectLnk(new MemorySource(badBlock))).rejects.toThrow(/environment target block is invalid/);
    const ansiOnly = remoteShortcut();
    ansiOnly.fill(0, REMOTE_PREFIX.length + 268, REMOTE_PREFIX.length + 788);
    expect((await inspectLnk(new MemorySource(ansiOnly))).targetPath).toBe("\\\\SERVER\\share\\tool.exe");
  });

  it("exports target-file timestamps that feed the existing timeline importer", async () => {
    const registry = createDefaultRegistry();
    const inspection = await executeOperation(registry, { operationId: "forensics.lnk.inspect", inputs: { data: bytesFrom(SHORTCUT) }, params: {} });
    expect(inspection.run.error).toBeUndefined();
    expect((inspection.outputs.report as { data: object }).data).toMatchObject({ targetPath: "C:\\Temp\\tool.exe" });
    const exported = await executeOperation(registry, { operationId: "forensics.lnk.timeline-export", inputs: { data: bytesFrom(SHORTCUT) }, params: { hostname: "LAB" } });
    expect(exported.run.error).toBeUndefined();
    const text = (exported.outputs.text as { text: string }).text;
    expect(text).toContain("LNK target file creation time");
    const timeline = await importWindowsTimeline(text, "plaso-jsonl", 0, 3_600);
    expect(timeline).toMatchObject({ total: 3, linked: 2 });
    expect(timeline.events[0].utc).toBe("2025-01-01T23:00:00.000000Z");
  });
});
