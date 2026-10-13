import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { diffHar, diffHarHeaders } from "./harDiff";

const SECRET = "FAKE-HIDDEN-QUERY-TOKEN";
const document = {
  log: {
    version: "1.2", pages: [{ id: "baseline" }, { id: "candidate" }],
    entries: [
      { pageref: "baseline", request: { method: "GET", url: `https://api.example.org/v1/users?id=42&cb=100&token=${SECRET}`, headers: [{ name: "Authorization", value: SECRET }] },
        response: { status: 200, content: { size: 100, text: SECRET } } },
      { pageref: "candidate", request: { method: "GET", url: `https://api.example.org/v1/users?id=42&cb=200&token=${SECRET}` },
        response: { status: 500, content: { size: 20 } } },
      { pageref: "candidate", request: { method: "POST", url: "https://api.example.org/v1/ship?utm_source=fixture", postData: { text: SECRET } },
        response: { status: 201, content: { size: 5 } } },
    ],
  },
};

describe("offline HAR request differential", () => {
  it("groups noise-only query changes and reports status/size differences without leaking values", () => {
    const report = diffHar(JSON.stringify(document));
    expect(report).toMatchObject({ baselinePage: "baseline", candidatePage: "candidate", matched: 1,
      queryValuesIgnored: true, headersCookiesAndBodiesReturned: false,
      changed: [{ request: "GET https://api.example.org/v1/users?id&token", baselineStatus: 200, candidateStatus: 500, baselineBodyBytes: 100, candidateBodyBytes: 20 }],
      added: [{ request: "POST https://api.example.org/v1/ship" }], missing: [] });
    expect(JSON.stringify(report)).not.toContain(SECRET);
  });

  it("rejects duplicate page IDs and non-HTTP request URLs", () => {
    expect(() => diffHar(JSON.stringify({ log: { ...document.log, pages: [{ id: "same" }, { id: "same" }] } }))).toThrow(/must be unique/);
    const invalid = structuredClone(document);
    invalid.log.entries[0].request.url = "file:///private.txt";
    expect(() => diffHar(JSON.stringify(invalid))).toThrow(/HTTP or HTTPS/);
  });

  it("allows unchanged matched requests after the difference budget is full", () => {
    const extra = structuredClone(document);
    extra.log.entries.splice(2, 1);
    extra.log.entries.push({ pageref: "baseline", request: { method: "GET", url: "https://api.example.org/v1/users?id=42&cb=300&token=second" }, response: { status: 200, content: { size: 100 } } });
    extra.log.entries.push({ pageref: "candidate", request: { method: "GET", url: "https://api.example.org/v1/users?id=42&cb=400&token=second" }, response: { status: 200, content: { size: 100 } } });
    const report = diffHar(JSON.stringify(extra), "", "", "cb,utm_source", 1);
    expect(report).toMatchObject({ matched: 2, changed: [expect.any(Object)], added: [] });
  });

  it("registers an offline HAR diff that omits request tokens and bodies", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "network.har.diff", inputs: { data: bytesFrom(new TextEncoder().encode(JSON.stringify(document))) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { matched: 1, queryValuesIgnored: true } });
    expect(JSON.stringify(result.outputs)).not.toContain(SECRET);
  });

  it("compares duplicate header counts without returning private values", async () => {
    const input = structuredClone(document);
    input.log.entries[0].request.headers = [
      { name: "X-Trace", value: SECRET }, { name: "x-trace", value: SECRET },
      { name: "Authorization", value: SECRET },
    ];
    input.log.entries[1].request.headers = [{ name: "X-Trace", value: SECRET }];
    input.log.entries.splice(2);
    const report = diffHarHeaders(JSON.stringify(input));
    expect(report).toMatchObject({ matched: 1, changed: [{ request: "GET https://api.example.org/v1/users", header: "x-trace", baselineValues: 2, candidateValues: 1 }], headerValuesReturned: false });
    expect(JSON.stringify(report)).not.toContain(SECRET);
    const registry = await executeOperation(createDefaultRegistry(), { operationId: "network.har.header-diff",
      inputs: { data: bytesFrom(new TextEncoder().encode(JSON.stringify(input))) }, params: {} });
    expect(registry.run.status).toBe("success");
    const invalid = structuredClone(input);
    invalid.log.entries[0].request.url = "not-a-url";
    expect(() => diffHarHeaders(JSON.stringify(invalid))).toThrow(/URL is invalid/);
    expect(() => diffHarHeaders(JSON.stringify({ log: { ...input.log, pages: [{ id: "same" }, { id: "same" }] } }))).toThrow(/unique/);
  });

  it("compares response header multiplicity without exposing values or response bodies", async () => {
    const input = { log: { ...document.log, entries: [
      { ...document.log.entries[0], response: { ...document.log.entries[0].response, headers: [
        { name: "Set-Cookie", value: SECRET }, { name: "X-Result", value: SECRET }, { name: "X-Result", value: SECRET },
      ] } },
      { ...document.log.entries[1], response: { ...document.log.entries[1].response, headers: [
        { name: "Set-Cookie", value: SECRET }, { name: "x-result", value: "changed-secret" },
      ] } },
    ] } };
    const report = diffHarHeaders(JSON.stringify(input), "", "", "set-cookie", 10, "response");
    expect(report).toMatchObject({ matched: 1, changed: [{ header: "x-result", baselineValues: 2, candidateValues: 1 }], headerValuesReturned: false });
    expect(JSON.stringify(report)).not.toMatch(/FAKE-HIDDEN|changed-secret/);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "network.har.header-diff",
      inputs: { data: bytesFrom(new TextEncoder().encode(JSON.stringify(input))) }, params: { side: "response", ignoredHeaders: "set-cookie" } });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: { changed: report.changed } });
  });
});
