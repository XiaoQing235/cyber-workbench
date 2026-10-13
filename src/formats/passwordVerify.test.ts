import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { verifyPasswordCandidates } from "./passwordVerify";

describe("bounded password candidate verification", () => {
  it("matches explicit raw hashes against independently computed Node digests", async () => {
    for (const algorithm of ["md5", "sha256"] as const) {
      const digest = createHash(algorithm).update("hunter2").digest("hex");
      const report = await verifyPasswordCandidates("wrong\nhunter2\nother", digest, algorithm, 2);
      expect(report).toEqual({ algorithm, tried: 2, truncated: true, matches: [{ line: 2, candidate: "hunter2" }], digestVerified: true });
    }
    const digest = createHash("sha256").update("hunter2").digest("hex");
    const result = await executeOperation(createDefaultRegistry(), { operationId: "credential.candidates.verify",
      inputs: { words: textValue("wrong\nhunter2") }, params: { algorithm: "sha256", digest, maxAttempts: 2 } });
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { digestVerified: true, matches: [{ candidate: "hunter2" }] } });
  });

  it("rejects malformed digests and respects a strict attempt budget", async () => {
    await expect(verifyPasswordCandidates("a", "not hex", "sha256", 1)).rejects.toThrow(/bounded raw-digest/);
    const digest = createHash("sha256").update("b").digest("hex");
    expect(await verifyPasswordCandidates("a\nb", digest, "sha256", 1)).toMatchObject({ tried: 1, truncated: true, matches: [], digestVerified: false });
  });
});
