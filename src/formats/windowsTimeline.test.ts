import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { importWindowsTimeline, unixMicrosToUtc } from "./windowsTimeline";

describe("Windows timeline import and correlation", () => {
  it("imports the published two-event Hayabusa JSONL sample without inventing file paths", async () => {
    const bytes = readFileSync(new URL("./testing/hayabusa-upstream-test.jsonl", import.meta.url));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("a2a894ca991fa3253c367527cc66acfea65b8f4c");
    const report = await importWindowsTimeline(bytes.toString("utf-8"), "hayabusa-jsonl", 0, 60);
    expect(report).toMatchObject({ total: 2, duplicates: 0, linked: 0, events: [
      { utc: "2020-05-02T02:55:23.551000Z", host: "test.local", source: "hayabusa:Microsoft-Windows-Sysmon/Operational:10",
        artifact: "C:\\windows\\System32\\svchost.exe" },
      { utc: "2020-05-02T02:55:28.893000Z", host: "test2.local", source: "hayabusa:Microsoft-Windows-Sysmon/Operational:11",
        artifact: "C:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat" },
    ] });
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.timeline.import",
      inputs: { text: textValue(bytes.toString("utf-8")) }, params: { format: "hayabusa-jsonl", timezoneOffsetMinutes: 0, windowSeconds: 60 } });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: report });
  });
  it("preserves Unix microseconds including fractions before 1970", () => {
    expect(unixMicrosToUtc(1735776000123456n)).toBe("2025-01-02T00:00:00.123456Z");
    expect(unixMicrosToUtc(-1n)).toBe("1969-12-31T23:59:59.999999Z");
  });

  it("normalizes Plaso timestamps from a declared UTC+10 offset, deduplicates, and links a path", async () => {
    const first = { timestamp: "2025-01-02 10:00:00", parser: "lnk", hostname: "LAB", filename: "C:\\Temp\\tool.exe", message: "Shortcut opened" };
    const next = { ...first, timestamp: "2025-01-02T00:00:05Z", parser: "evtx", message: "Process created" };
    const report = await importWindowsTimeline([next, first, first].map((event) => JSON.stringify(event)).join("\n"), "plaso-jsonl", 600, 10);
    expect(report).toMatchObject({ total: 2, duplicates: 1, linked: 1, truncatedLinks: false });
    expect(report.events.map((event) => event.utc)).toEqual(["2025-01-02T00:00:00.000000Z", "2025-01-02T00:00:05.000000Z"]);
    expect(report.links).toEqual([{ from: 0, to: 1, artifact: "C:\\Temp\\tool.exe", secondsApart: 5 }]);
  });

  it("parses quoted Hayabusa CSV details and correlates case-insensitive Windows paths", async () => {
    const csv = 'Timestamp,Computer,Channel,EventID,Details,Path\n2025-01-02T00:00:00Z,LAB,Sysmon,1,"Created, process",C:\\TEMP\\tool.exe\n2025-01-02T00:00:03Z,lab,Sysmon,7,"Loaded, module",C:\\Temp\\tool.exe\n';
    const report = await importWindowsTimeline(csv, "hayabusa-csv", 0, 5);
    expect(report).toMatchObject({ total: 2, linked: 1, events: [{ message: "Created, process" }, { message: "Loaded, module" }] });
    expect(report.links[0]).toMatchObject({ from: 0, to: 1, secondsApart: 3 });
  });

  it("imports bounded KAPE MFTECmd CSV timestamps without conflating $SI and $FN", async () => {
    const csv = 'ParentPath,FileName,Created0x10,LastModified0x10,Created0x30,Computer\n' +
      'C:\\Temp,tool.exe,2025-01-02 10:00:00,2025-01-02T00:00:03Z,2025-01-02T00:00:04Z,LAB\n';
    const report = await importWindowsTimeline(csv, "mftecmd-csv", 600, 10);
    expect(report).toMatchObject({ total: 3, linked: 2 });
    expect(report.events.map((event) => event.source)).toEqual(["mftecmd:Created0x10", "mftecmd:LastModified0x10", "mftecmd:Created0x30"]);
    expect(report.events[0]).toMatchObject({ utc: "2025-01-02T00:00:00.000000Z", host: "LAB", artifact: "C:\\Temp\\tool.exe" });
    const registered = await executeOperation(createDefaultRegistry(), { operationId: "forensics.timeline.import",
      inputs: { text: textValue(csv) }, params: { format: "mftecmd-csv", timezoneOffsetMinutes: 600, windowSeconds: 10 } });
    expect(registered.outputs.report).toMatchObject({ type: "structured", data: { linked: 2 } });
  });

  it("rejects malformed MFTECmd headers and expansion beyond the event budget", async () => {
    await expect(importWindowsTimeline("ParentPath,FileName\nC:\\Temp,tool.exe", "mftecmd-csv", 0, 1)).rejects.toThrow(/timestamp columns/);
    const row = "C:\\Temp,tool.exe,2025-01-02T00:00:00Z,2025-01-02T00:00:01Z\n";
    await expect(importWindowsTimeline(`ParentPath,FileName,Created0x10,Created0x30\n${row.repeat(2501)}`, "mftecmd-csv", 0, 1)).rejects.toThrow(/expanded events/);
  });

  it("links a Plaso shortcut and a Hayabusa process record in one mixed input", async () => {
    const input = JSON.stringify([
      { source: "hayabusa", event: { Timestamp: "2025-01-02T00:00:05Z", Computer: "lab", Channel: "Sysmon", EventID: "1", Details: "Created", Image: "c:/temp/tool.exe" } },
      { source: "plaso", event: { timestamp: "2025-01-02 10:00:00", parser: "lnk", hostname: "LAB", filename: "C:\\Temp\\tool.exe", message: "Opened" } },
    ]);
    const report = await importWindowsTimeline(input, "mixed-json", 600, 10);
    expect(report).toMatchObject({ total: 2, linked: 1, events: [{ source: "plaso:lnk" }, { source: "hayabusa:Sysmon:1" }] });
    expect(report.links).toEqual([{ from: 0, to: 1, artifact: "c:/temp/tool.exe", secondsApart: 5 }]);
  });

  it("keeps events one microsecond apart distinct during deduplication and correlation", async () => {
    const source = { parser: "evtx", hostname: "LAB", filename: "C:\\Temp\\tool.exe", message: "Repeated" };
    const input = [
      { ...source, timestamp: "2025-01-02T00:00:00.000001Z" },
      { ...source, timestamp: "2025-01-02T00:00:00.000002Z" },
    ].map((event) => JSON.stringify(event)).join("\n");
    const report = await importWindowsTimeline(input, "plaso-jsonl", 0, 1);
    expect(report.events.map((event) => event.utc)).toEqual(["2025-01-02T00:00:00.000001Z", "2025-01-02T00:00:00.000002Z"]);
    expect(report).toMatchObject({ total: 2, duplicates: 0, links: [{ secondsApart: 0.000001 }] });
  });

  it("rejects ambiguous local times with invalid dates and missing required columns", async () => {
    const bad = JSON.stringify({ timestamp: "2025-02-30 10:00:00", parser: "evtx" });
    await expect(importWindowsTimeline(bad, "plaso-jsonl", 0, 5)).rejects.toThrow(/invalid calendar date/);
    await expect(importWindowsTimeline("Timestamp,Computer\n2025-01-01T00:00:00Z,host", "hayabusa-csv", 0, 5)).rejects.toThrow(/missing Channel/);
    await expect(importWindowsTimeline("Timestamp,Timestamp,Computer,Channel,EventID,Details\n2025-01-01T00:00:00Z,other,host,Sysmon,1,message", "hayabusa-csv", 0, 5)).rejects.toThrow(/duplicate columns/);
    await expect(importWindowsTimeline(bad, "plaso-jsonl", 900, 5)).rejects.toThrow(/timezone or correlation window/);
  });

  it("produces a bounded cross-event report through the registry", async () => {
    const events = [
      { timestamp: "2025-01-02 10:00:00", parser: "lnk", hostname: "LAB", filename: "C:\\Temp\\tool.exe", message: "Opened" },
      { timestamp: "2025-01-02T00:00:05Z", parser: "evtx", hostname: "LAB", filename: "C:\\Temp\\tool.exe", message: "Executed" },
    ];
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.timeline.import", inputs: { text: textValue(events.map((event) => JSON.stringify(event)).join("\n")) },
      params: { format: "plaso-jsonl", timezoneOffsetMinutes: 600, windowSeconds: 10 },
    });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: object }).data).toMatchObject({ total: 2, linked: 1 });
    expect(result.run.diagnostics).toEqual(["Imported 2 event(s), removed 0 duplicate(s), and linked 1 host/path event(s)."]);
  });
});
