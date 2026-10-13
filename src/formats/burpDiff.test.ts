import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { diffBurp, diffBurpHeaders } from "./burpDiff";

const secret = "FAKE-PRIVATE-BURP-PAYLOAD";
const item = (method: string, url: string, status: number) => `<item>
<time>Sun Oct 12 19:20:00 UTC 2026</time><url>${url}</url><host>api.example.org</host>
<method>${method}</method><status>${status}</status><responselength>9999</responselength>
<request base64="true">${btoa(secret)}</request><response base64="true">${btoa(secret)}</response>
</item>`;
const xml = (body: string) => `<?xml version="1.0"?><items burpVersion="2025.1" exportTime="Mon Oct 12 2026">${body}</items>`;

describe("offline Burp XML request differential", () => {
  it("compares ordered groups, ignores noise and omits decoded payloads and response lengths", async () => {
    const input = xml(item("GET", "https://api.example.org/v1/users?id=42&amp;cb=1", 200)
      + item("POST", "https://api.example.org/v1/ship", 201)
      + item("GET", "https://api.example.org/v1/users?id=99&amp;cb=2", 500)
      + item("DELETE", "https://api.example.org/v1/session", 204));
    const report = await diffBurp(input, 2, "cb", 10);
    expect(report).toMatchObject({ matched: 1, compared: 4, changed: [{ baselineStatus: 200, candidateStatus: 500,
      baselineBodyBytes: null, candidateBodyBytes: null, request: "GET https://api.example.org/v1/users?id" }],
      missing: [{ request: "POST https://api.example.org/v1/ship" }], added: [{ request: "DELETE https://api.example.org/v1/session" }] });
    expect(JSON.stringify(report)).not.toContain(secret);
    expect(JSON.stringify(report)).not.toContain("9999");
  });

  it("rejects malformed XML, entities, invalid groups and non-HTTP URLs", async () => {
    const pair = item("GET", "https://api.example.org/a", 200) + item("GET", "https://api.example.org/a", 200);
    await expect(diffBurp(xml(pair).replace("<items", '<!DOCTYPE items [<!ENTITY x "secret">]><items'), 1, "", 10)).rejects.toThrow(/declaration/);
    await expect(diffBurp(xml(pair).replace("</items>", ""), 1, "", 10)).rejects.toThrow(/malformed/);
    await expect(diffBurp(xml(pair), 2, "", 10)).rejects.toThrow(/baseline count/);
    await expect(diffBurp(xml(pair).replace("https://api.example.org/a", "file:///secret"), 1, "", 10)).rejects.toThrow(/HTTP or HTTPS/);
    await expect(diffBurp(xml(pair).replace("<status>200</status>", "<status>oops</status>"), 1, "", 10)).rejects.toThrow(/status/);
  });

  it("registers the same bounded offline operation", async () => {
    const result = await executeOperation(createDefaultRegistry(), { operationId: "network.burp.diff",
      inputs: { data: bytesFrom(new TextEncoder().encode(xml(item("GET", "https://api.example.org/a", 200) + item("GET", "https://api.example.org/a", 403)))) },
      params: {} });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { matched: 1, changed: [{ baselineStatus: 200, candidateStatus: 403 }] } });
    expect(JSON.stringify(result.outputs)).not.toContain(secret);
  });

  it("compares only header names and counts from base64 requests, with noise removal", async () => {
    const request = (headers: string) => btoa(`GET /a HTTP/1.1\r\nHost: api.example.org\r\nAuthorization: ${secret}\r\n${headers}\r\n`);
    const pair = xml(item("GET", "https://api.example.org/a?cb=1", 200).replace(btoa(secret), request("X-Mode: one\r\nX-Mode: two\r\n"))
      + item("GET", "https://api.example.org/a?cb=2", 200).replace(btoa(secret), request("X-Mode: altered-secret-value\r\nX-Other: present\r\n")));
    const report = await diffBurpHeaders(pair, 1, "authorization", 10);
    expect(report).toMatchObject({ matched: 1, headerValuesReturned: false,
      changed: [{ header: "x-mode", baselineValues: 2, candidateValues: 1 }, { header: "x-other", baselineValues: 0, candidateValues: 1 }] });
    expect(JSON.stringify(report)).not.toContain(secret);
    expect(JSON.stringify(report)).not.toContain("altered-secret-value");
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "network.burp.header-diff",
      inputs: { data: bytesFrom(new TextEncoder().encode(pair)) }, params: { baselineCount: 1, ignoredHeaders: "authorization", maxChanges: 10 } });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: { changed: report.changed } });
    await expect(diffBurpHeaders(pair.replace(/<request base64="true">[^<]+/, '<request base64="true">bad!'), 1, "", 10)).rejects.toThrow(/base64/);
    const noDelimiter = xml(item("GET", "https://api.example.org/a", 200).replace(btoa(secret), btoa("GET /a HTTP/1.1\r\nHost: api.example.org"))
      + item("GET", "https://api.example.org/a", 200));
    await expect(diffBurpHeaders(noDelimiter, 1, "", 10)).rejects.toThrow(/header block/);
  });

  it("compares Burp response headers without returning cookie values, status lines or bodies", async () => {
    const response = (headers: string) => btoa(`HTTP/1.1 200 OK\r\nSet-Cookie: ${secret}\r\n${headers}\r\nPRIVATE BODY`);
    const pair = xml(item("GET", "https://api.example.org/a", 200).replace(`<response base64="true">${btoa(secret)}`, `<response base64="true">${response("X-Trace: first\r\nX-Trace: second\r\n")}`)
      + item("GET", "https://api.example.org/a", 200).replace(`<response base64="true">${btoa(secret)}`, `<response base64="true">${response("X-Trace: changed-secret-value\r\nX-Other: present\r\n")}`));
    const report = await diffBurpHeaders(pair, 1, "set-cookie", 10, "response");
    expect(report).toMatchObject({ matched: 1, changed: [
      { header: "x-trace", baselineValues: 2, candidateValues: 1 },
      { header: "x-other", baselineValues: 0, candidateValues: 1 },
    ], headerValuesReturned: false });
    expect(JSON.stringify(report)).not.toMatch(/PRIVATE|changed-secret-value|200 OK/);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "network.burp.header-diff",
      inputs: { data: bytesFrom(new TextEncoder().encode(pair)) }, params: { baselineCount: 1, side: "response", ignoredHeaders: "set-cookie", maxChanges: 10 } });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: { changed: report.changed } });
    await expect(diffBurpHeaders(pair.replace(/<response base64="true">[^<]+/, '<response base64="true">bad!'), 1, "", 10, "response"))
      .rejects.toThrow(/base64/);
  });
});
