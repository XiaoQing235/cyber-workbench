import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { importWindowsTimeline } from "./windowsTimeline";
import { inspectCloudTrail, observedRoleGraph } from "./cloudTrail";

const caller = "arn:aws:iam::123456789012:user/analyst";
const role = "arn:aws:iam::123456789012:role/ReadOnly";
const records = [
  {
    eventVersion: "1.09", eventID: "d84df6de-dc2c-430f-8d89-5c2451166840", eventTime: "2026-10-11T09:48:55Z",
    eventSource: "sts.amazonaws.com", eventName: "AssumeRole", awsRegion: "ap-southeast-2", recipientAccountId: "123456789012",
    userIdentity: { type: "IAMUser", accountId: "123456789012", arn: caller }, sourceIPAddress: "198.51.100.10",
    requestParameters: { roleArn: role }, resources: [{ ARN: role, type: "AWS::IAM::Role" }], readOnly: false,
  },
  {
    eventVersion: "1.09", eventID: "751dc3ef-3208-4213-987d-f94d3fc98233", eventTime: "2026-10-11T09:49:01.123456Z",
    eventSource: "s3.amazonaws.com", eventName: "GetObject", recipientAccountId: "123456789012",
    userIdentity: { arn: role }, sourceIPAddress: "AWS Internal", resources: [{ ARN: "arn:aws:s3:::bucket/data.txt" }],
    readOnly: true, errorCode: "AccessDenied",
  },
];

describe("CloudTrail record normalization", () => {
  it("imports a licensed metadata-only JSONL excerpt of the OTRF AWS incident", async () => {
    const input = readFileSync(new URL("./testing/otrf-cloud-breach-excerpt.jsonl", import.meta.url), "utf8");
    const report = inspectCloudTrail(input);
    expect(report).toMatchObject({ total: 3, duplicateEventIds: 0, services: [
      { name: "s3.amazonaws.com", count: 2 }, { name: "sts.amazonaws.com", count: 1 },
    ] });
    const roleArn = "arn:aws:iam::123456789123:role/MordorNginxStack-BankingWAFRole-9S3E0UAE1MM0";
    expect(report.events[0]).toMatchObject({ eventId: "a3a3dded-7c27-42c0-a42d-891cdd436278",
      utc: "2020-09-14T00:48:30.000000Z", targetRoleArn: roleArn, principal: null });
    expect(report.events.slice(1)).toMatchObject([
      { eventId: "771299cb-e200-4926-9604-c85358b30499", eventName: "GetObject", utc: "2020-09-14T01:02:34.000000Z" },
      { eventId: "edc2222c-5063-47fb-9fc0-c2ffb86b9d15", eventName: "GetObject", utc: "2020-09-14T01:13:20.000000Z" },
    ]);
    expect(report.events[1].principal).toBe("arn:aws:sts::123456789123:assumed-role/MordorNginxStack-BankingWAFRole-9S3E0UAE1MM0/i-0317f6c6b66ae9c40");
    expect(report.events[1].resources).toContain("arn:aws:s3:::mordors3stack-s3bucket-llp2yingx64a/ring.txt");
    expect(input).not.toMatch(/responseElements|sessionToken|SecretAccessKey|accessKeyId/);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.cloudtrail.inspect",
      inputs: { text: textValue(input) }, params: {} });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: report });
    const timelineRun = await executeOperation(createDefaultRegistry(), { operationId: "forensics.cloudtrail.timeline-export",
      inputs: { text: textValue(input) }, params: { hostname: "incident-excerpt" } });
    if (timelineRun.outputs.text?.type !== "text") throw new Error("Expected incident timeline");
    const timeline = await importWindowsTimeline(timelineRun.outputs.text.text, "plaso-jsonl", 0, 10);
    expect(timeline.total).toBe(3);
    expect(timeline.events.map((event) => event.artifact)).toContain("arn:aws:s3:::mordors3stack-s3bucket-llp2yingx64a/ring.txt");
    expect(observedRoleGraph(report)).toMatchObject({ edges: [], skippedMissingIdentity: 1 });
  });
  it("keeps IAM target and failed API provenance with six-digit UTC", async () => {
    const report = inspectCloudTrail(JSON.stringify({ Records: records }));
    expect(report).toMatchObject({ total: 2, duplicateEventIds: 0, services: [{ name: "s3.amazonaws.com", count: 1 }, { name: "sts.amazonaws.com", count: 1 }] });
    expect(report.events[0]).toMatchObject({ utc: "2026-10-11T09:48:55.000000Z", principal: caller, targetRoleArn: role, accountId: "123456789012" });
    expect(report.events[1]).toMatchObject({ utc: "2026-10-11T09:49:01.123456Z", sourceAddress: "AWS Internal", errorCode: "AccessDenied" });
    const lines = report.events.map((event) => JSON.stringify({ timestamp: event.utc, parser: "cloudtrail", hostname: event.accountId ?? "", filename: event.targetRoleArn ?? event.resources[0] ?? "", message: event.eventName }));
    const timeline = await importWindowsTimeline(lines.join("\n"), "plaso-jsonl", 0, 60);
    expect(timeline.total).toBe(2);
    expect(timeline.events[0].utc).toBe("2026-10-11T09:48:55.000000Z");
  });

  it("rejects invalid calendar dates, malformed identities, and oversized record sets", () => {
    expect(() => inspectCloudTrail(JSON.stringify({ ...records[0], eventTime: "2026-02-30T09:48:55Z" }))).toThrow(/invalid calendar date/);
    expect(() => inspectCloudTrail(JSON.stringify({ ...records[0], userIdentity: [] }))).toThrow(/userIdentity must be an object/);
    expect(() => inspectCloudTrail(JSON.stringify({ Records: Array.from({ length: 5_001 }, () => ({
      eventID: "event", eventTime: "2026-10-11T09:48:55Z", eventSource: "aws.example", eventName: "Call",
    })) }))).toThrow(/5,000/);
    expect(() => inspectCloudTrail(`${JSON.stringify(records[0])}\n{"eventID":`)).toThrow(/valid JSON or JSONL/);
    expect(() => inspectCloudTrail(`${JSON.stringify({ ...records[0], eventTime: undefined, "@timestamp": "2020-09-14T01:02:34.000Z" })}\n${JSON.stringify({ ...records[1], eventTime: undefined, "@timestamp": "2020-09-14T01:13:20.000Z" })}`))
      .not.toThrow();
  });

  it("keeps duplicate IDs visible and exports account-aware timeline JSONL through the registry", async () => {
    const text = textValue(JSON.stringify({ Records: [...records, records[0]] }));
    const registry = createDefaultRegistry();
    const inspected = await executeOperation(registry, { operationId: "forensics.cloudtrail.inspect", inputs: { text }, params: {} });
    expect(inspected.run.status).toBe("success");
    expect(inspected.outputs.report).toMatchObject({ type: "structured", data: { total: 3, duplicateEventIds: 1 } });
    const exported = await executeOperation(registry, {
      operationId: "forensics.cloudtrail.timeline-export", inputs: { text }, params: { hostname: "fixture-cloud" },
    });
    expect(exported.run.status).toBe("success");
    if (exported.outputs.text?.type !== "text") throw new Error("Expected CloudTrail JSONL");
    expect(exported.outputs.text.text.split("\n")).toHaveLength(3);
    const timeline = await importWindowsTimeline(exported.outputs.text.text, "plaso-jsonl", 0, 60);
    expect(timeline.total).toBe(2);
    expect(timeline.duplicates).toBe(1);
    expect(timeline.events[0]).toMatchObject({ host: "fixture-cloud", artifact: role, source: "plaso:cloudtrail" });
    expect(timeline.events.some((event) => event.message.includes("AccessDenied"))).toBe(true);
  });

  it("graphs observed role calls without treating errors or duplicate logs as permissions", () => {
    const failure = { ...records[0], eventID: "failed-attempt", eventTime: "2026-10-11T09:49:02Z", errorCode: "AccessDenied" };
    const missingCaller = { ...records[0], eventID: "unknown-caller", userIdentity: undefined };
    const report = inspectCloudTrail(JSON.stringify({ Records: [records[0], records[0], failure, missingCaller] }));
    const graph = observedRoleGraph(report);
    expect(graph).toMatchObject({ skippedDuplicateIds: 1, skippedMissingIdentity: 1 });
    expect(graph.nodes).toHaveLength(2);
    expect(graph.edges).toHaveLength(2);
    expect(graph.edges.find((edge) => edge.outcome === "no-reported-error")).toMatchObject({ caller, role, count: 1, eventIds: [records[0].eventID] });
    expect(graph.edges.find((edge) => edge.outcome === "reported-error")).toMatchObject({ caller, role, count: 1, eventIds: ["failed-attempt"] });
  });

  it("exposes the observed graph through the Forensics operation", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.cloudtrail.role-graph", inputs: { text: textValue(JSON.stringify({ Records: records })) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.run.diagnostics.join(" ")).toMatch(/not an authorization graph/);
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { edges: [{ caller, role, outcome: "no-reported-error" }] } });
  });
});
