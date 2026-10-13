import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { analyzeOracleTranscript, type OracleCondition } from "./oracleTranscript";

const condition: OracleCondition = { mode: "status", statusValue: 200, minimumBytes: 3, contains: "ok", minimumMs: 20 };
const transcript = JSON.stringify([
  { request: "aa", status: 200, body: "ok", durationMs: 10 },
  { request: "AA", status: 403, body: "error", durationMs: 30 },
  { request: "bb", status: 200, body: "ok!", durationMs: 20 },
]);

describe("offline oracle transcripts", () => {
  it("classifies status and reports disagreement between repeated requests", () => {
    expect(analyzeOracleTranscript(transcript, condition)).toEqual({
      total: 3, matched: 2, repeatedRequests: 1, noisyRequests: 1, minorityResponses: 1,
      medianMs: 20, p95Ms: 30,
      observations: [
        { index: 0, matched: true, status: 200, bodyBytes: 2, durationMs: 10 },
        { index: 1, matched: false, status: 403, bodyBytes: 5, durationMs: 30 },
        { index: 2, matched: true, status: 200, bodyBytes: 3, durationMs: 20 },
      ],
    });
  });

  it("evaluates byte length, content, and timing conditions independently", () => {
    expect(analyzeOracleTranscript(transcript, { ...condition, mode: "length" }).matched).toBe(2);
    expect(analyzeOracleTranscript(transcript, { ...condition, mode: "contains" }).matched).toBe(2);
    expect(analyzeOracleTranscript(transcript, { ...condition, mode: "timing" }).matched).toBe(2);
  });

  it("rejects malformed requests and unbounded response data", () => {
    expect(() => analyzeOracleTranscript('[{"request":"xyz","status":200,"body":"ok","durationMs":1}]', condition)).toThrow(/bounded hex/);
    expect(() => analyzeOracleTranscript(JSON.stringify([{ request: "aa", status: 200, body: "x".repeat(4_097), durationMs: 1 }]), condition)).toThrow(/body exceeds/);
    expect(() => analyzeOracleTranscript(transcript, { ...condition, mode: "contains", contains: "" })).toThrow(/cannot be empty/);
  });

  it("returns a noise report without storing request or response bodies", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "crypto.oracle.transcript-analyze", inputs: { transcript: textValue(transcript) }, params: condition,
    });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: object }).data).toMatchObject({ total: 3, matched: 2, noisyRequests: 1, minorityResponses: 1 });
    expect(result.run.diagnostics).toEqual(["Classified 3 stored response(s); 1 repeated request(s) had inconsistent outcomes."]);
    expect(JSON.stringify((result.outputs.report as { data: object }).data)).not.toMatch(/"aa"|"bb"|"error"/);
  });
});