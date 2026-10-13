import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { cloudTrailEntityEvents, correlateEntities, timelineEntityEvents } from "./entityCorrelation";

const records = JSON.stringify([
  { id: "cloud-1", utc: "2025-01-02T00:00:00Z", source: "cloudtrail", entities: [
    { kind: "ip", value: "192.0.2.1" }, { kind: "identity", value: "arn:aws:iam::123456789012:user/alice" }] },
  { id: "host-1", utc: "2025-01-02T00:00:04Z", source: "sysmon", entities: [
    { kind: "ip", value: "192.0.2.1" }, { kind: "file", value: "C:/Temp/Tool.exe" }] },
  { id: "disk-1", utc: "2025-01-02T00:00:05Z", source: "mft", entities: [
    { kind: "file", value: "c:\\temp\\tool.exe" }] },
  { id: "cloud-2", utc: "2025-01-02T00:10:00Z", source: "cloudtrail", entities: [
    { kind: "ip", value: "192.0.2.1" }] },
]);

describe("bounded cross-source entity graph", () => {
  it("links shared IP and Windows paths inside the time window, without assuming causation", async () => {
    const report = correlateEntities(records, 10);
    expect(report.links).toEqual([
      { from: 0, to: 1, entity: "192.0.2.1", kind: "ip", secondsApart: 4 },
      { from: 1, to: 2, entity: "c:\\temp\\tool.exe", kind: "file", secondsApart: 1 },
    ]);
    expect(report.truncated).toBe(false);
    const result = await executeOperation(createDefaultRegistry(), { operationId: "forensics.entities.correlate",
      inputs: { text: textValue(records) }, params: { windowSeconds: 10 } });
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { links: report.links } });
  });

  it("rejects duplicate IDs, unknown entity types, and excessive events", () => {
    const single = { id: "dup", utc: "2025-01-02T00:00:00Z", source: "one", entities: [] };
    expect(() => correlateEntities(JSON.stringify([single, single]), 10)).toThrow(/duplicated/);
    expect(() => correlateEntities(JSON.stringify([{ ...single, entities: [{ kind: "secret", value: "x" }] }]), 10)).toThrow(/Unknown entity/);
    expect(() => correlateEntities(JSON.stringify(Array.from({ length: 5001 }, (_, index) => ({ ...single, id: `${index}` }))), 10)).toThrow(/5,000/);
  });

  it("orders mixed-precision UTC timestamps correctly and rejects invalid calendar dates", () => {
    const input = JSON.stringify([
      { id: "late", utc: "2025-01-02T00:00:00.100001Z", source: "b", entities: [{ kind: "domain", value: "example.test" }] },
      { id: "early", utc: "2025-01-02T00:00:00.1Z", source: "a", entities: [{ kind: "domain", value: "example.test" }] },
    ]);
    const report = correlateEntities(input, 1);
    expect(report.events.map((event) => event.id)).toEqual(["early", "late"]);
    expect(report.links[0].secondsApart).toBeCloseTo(0.000001);
    expect(() => correlateEntities(JSON.stringify([{ id: "bad", utc: "2025-02-30T00:00:00Z", source: "a", entities: [] }]), 1)).toThrow(/invalid calendar/);
  });

  it("drafts CloudTrail identity/IP observations for correlation with host events", async () => {
    const cloud = JSON.stringify({ Records: [{ eventID: "cloud-one", eventTime: "2025-01-02T00:00:00Z",
      eventSource: "sts.amazonaws.com", eventName: "AssumeRole", sourceIPAddress: "192.0.2.1",
      userIdentity: { arn: "arn:aws:iam::123456789012:user/alice" }, requestParameters: { roleArn: "arn:aws:iam::123456789012:role/reader" } }] });
    const drafted = cloudTrailEntityEvents(cloud);
    expect(drafted).toMatchObject([{ id: "cloud-one", entities: [
      { kind: "ip", value: "192.0.2.1" }, { kind: "identity", value: "arn:aws:iam::123456789012:user/alice" },
      { kind: "identity", value: "arn:aws:iam::123456789012:role/reader" },
    ] }]);
    const host = { id: "host-one", utc: "2025-01-02T00:00:03Z", source: "sysmon",
      entities: [{ kind: "ip", value: "192.0.2.1" }] };
    expect(correlateEntities(JSON.stringify([...drafted, host]), 10).links).toMatchObject([{ from: 0, to: 1, kind: "ip", secondsApart: 3 }]);
    const exported = await executeOperation(createDefaultRegistry(), { operationId: "forensics.cloudtrail.entities",
      inputs: { text: textValue(cloud) }, params: {} });
    expect(exported.outputs.text).toMatchObject({ type: "text", text: JSON.stringify(drafted) });
  });

  it("exports imported MFTECmd and Plaso paths as observed cross-source file entities", async () => {
    const csv = "ParentPath,FileName,Created0x10,Computer\nC:\\Temp,tool.exe,2025-01-02T00:00:05Z,LAB\n";
    const disk = await timelineEntityEvents(csv, "mftecmd-csv", 0, "disk");
    const jsonl = JSON.stringify({ timestamp: "2025-01-02T00:00:00Z", parser: "lnk", hostname: "LAB",
      filename: "c:/temp/tool.exe", message: "Other path mentioned: C:/PRIVATE/key" });
    const host = await timelineEntityEvents(jsonl, "plaso-jsonl", 0, "host");
    expect(host[0].entities).toEqual([{ kind: "file", value: "c:/temp/tool.exe" }]);
    expect(disk[0].entities).toEqual([{ kind: "file", value: "C:\\Temp\\tool.exe" }]);
    expect(correlateEntities(JSON.stringify([...host, ...disk]), 10).links)
      .toMatchObject([{ from: 0, to: 1, kind: "file", secondsApart: 5 }]);
    const exported = await executeOperation(createDefaultRegistry(), { operationId: "forensics.timeline.entities",
      inputs: { text: textValue(csv) }, params: { format: "mftecmd-csv", timezoneOffsetMinutes: 0, sourceLabel: "disk" } });
    expect(exported.outputs.text).toMatchObject({ type: "text", text: JSON.stringify(disk) });
    const relative = JSON.stringify({ timestamp: "2025-01-02T00:00:00Z", parser: "evtx", filename: "notes.txt", message: "192.0.2.1" });
    expect((await timelineEntityEvents(relative, "plaso-jsonl", 0))[0].entities).toEqual([]);
    await expect(timelineEntityEvents(csv, "mftecmd-csv", 900)).rejects.toThrow(/timezone/);
    await expect(timelineEntityEvents(csv, "mftecmd-csv", 0, "../disk")).rejects.toThrow(/source label/);
  });

  it("correlates explicit Hayabusa IPv4 columns with CloudTrail while ignoring messages and malformed IPs", async () => {
    const cloud = cloudTrailEntityEvents(JSON.stringify({ Records: [{ eventID: "cloud-ip", eventTime: "2025-01-02T00:00:00Z",
      eventSource: "sts.amazonaws.com", eventName: "AssumeRole", sourceIPAddress: "192.0.2.1" }] }));
    const csv = "Timestamp,Computer,Channel,EventID,Details,SourceIp,DestinationIp,Image\n" +
      "2025-01-02T00:00:03Z,LAB,Sysmon,3,203.0.113.9,192.0.2.1,999.0.2.1,C:\\Temp\\tool.exe\n";
    const host = await timelineEntityEvents(csv, "hayabusa-csv", 0, "host");
    expect(host[0].entities).toEqual([{ kind: "file", value: "C:\\Temp\\tool.exe" }, { kind: "ip", value: "192.0.2.1" }]);
    expect(correlateEntities(JSON.stringify([...cloud, ...host]), 10).links)
      .toEqual([{ from: 0, to: 1, kind: "ip", entity: "192.0.2.1", secondsApart: 3 }]);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.timeline.entities",
      inputs: { text: textValue(csv) }, params: { format: "hayabusa-csv", timezoneOffsetMinutes: 0, sourceLabel: "host" } });
    expect(operation.outputs.text).toMatchObject({ type: "text", text: JSON.stringify(host) });
    const revised = csv.replace("192.0.2.1,999.0.2.1", "010.0.2.1,192.0.2.1");
    expect((await timelineEntityEvents(revised, "hayabusa-csv", 0, "host"))[0].entities)
      .toEqual([{ kind: "file", value: "C:\\Temp\\tool.exe" }, { kind: "ip", value: "192.0.2.1" }]);
  });

  it("drafts only explicit file paths from the published Hayabusa JSONL sample", async () => {
    const input = readFileSync(new URL("./testing/hayabusa-upstream-test.jsonl", import.meta.url), "utf-8");
    const drafted = await timelineEntityEvents(input, "hayabusa-jsonl", 0, "hayabusa");
    expect(drafted).toMatchObject([
      { id: "hayabusa-1", entities: [
        { kind: "file", value: "C:\\windows\\System32\\svchost.exe" },
        { kind: "identity", value: "NT AUTHORITY\\SYSTEM" },
        { kind: "identity", value: "S-1-5-18" },
      ] },
      { id: "hayabusa-2", entities: [
        { kind: "file", value: "C:\\Windows\\ServiceState\\EventLog\\Data\\lastalive1.dat" },
        { kind: "file", value: "C:\\windows\\System32\\svchost.exe" },
        { kind: "identity", value: "NT AUTHORITY\\SYSTEM" },
        { kind: "identity", value: "S-1-5-18" },
      ] },
    ]);
    expect(drafted[0].entities).toHaveLength(3);
    expect(drafted[1].entities).toHaveLength(4);
    expect(correlateEntities(JSON.stringify(drafted), 10).links).toEqual([
      { from: 0, to: 1, entity: "c:\\windows\\system32\\svchost.exe", kind: "file", secondsApart: 5.342 },
      { from: 0, to: 1, entity: "nt authority\\system", kind: "identity", secondsApart: 5.342 },
      { from: 0, to: 1, entity: "s-1-5-18", kind: "identity", secondsApart: 5.342 },
    ]);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.timeline.entities",
      inputs: { text: textValue(input) }, params: { format: "hayabusa-jsonl", timezoneOffsetMinutes: 0, sourceLabel: "hayabusa" } });
    expect(operation.outputs.text).toMatchObject({ type: "text", text: JSON.stringify(drafted) });
    const invalid = JSON.parse(input.split("\n")[0]) as Record<string, unknown>;
    invalid.UserID = "not-a-sid";
    invalid.AccountName = "SYSTEM\\admin";
    expect((await timelineEntityEvents(JSON.stringify(invalid), "hayabusa-jsonl", 0))[0].entities)
      .toEqual([{ kind: "file", value: "C:\\windows\\System32\\svchost.exe" }]);
  });
});
