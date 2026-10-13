import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { generatePasswordCandidates, type CandidateOptions } from "./passwordCandidates";

const options: CandidateOptions = {
  source: "dictionary", words: "Alpha\nBeta", rules: ":\nu\n$!", mask: "", customCharset: "", combineWith: "",
  maxCandidates: 100, maxWork: 100, maxOutputBytes: 1024, unique: true,
};

describe("bounded password candidates", () => {
  it("applies ordered dictionary rules and preserves UTF-8 output", async () => {
    const result = await generatePasswordCandidates(options);
    expect(result).toEqual({
      source: "dictionary", text: "Alpha\nALPHA\nAlpha!\nBeta\nBETA\nBeta!", generated: 6, work: 6, truncated: false,
    });
  });

  it("shares ZIP's mask semantics while respecting the candidate cap", async () => {
    const result = await generatePasswordCandidates({ ...options, source: "mask", mask: "?1?d", customCharset: "ab", maxCandidates: 3 });
    expect(result).toEqual({ source: "mask", text: "a0\na1\na2", generated: 3, work: 3, truncated: true });
  });

  it("combines ordered word lists without materializing the full Cartesian product", async () => {
    const result = await generatePasswordCandidates({ ...options, source: "combine", words: "a\nb", combineWith: "1\n2" });
    expect(result).toEqual({ source: "combine", text: "a1\na2\nb1\nb2", generated: 4, work: 4, truncated: false });
  });

  it("bounds duplicate work and UTF-8 output bytes independently", async () => {
    const workLimited = await generatePasswordCandidates({ ...options, words: "a\na\na\nb", rules: ":", maxWork: 2 });
    expect(workLimited).toMatchObject({ text: "a", generated: 1, work: 2, truncated: true });
    const outputLimited = await generatePasswordCandidates({ ...options, words: "é\néé", rules: ":", maxOutputBytes: 3 });
    expect(outputLimited).toMatchObject({ text: "é", generated: 1, work: 2, truncated: true });
  });

  it("yields for cancellation and rejects unsupported rules", async () => {
    let yields = 0;
    const manyWords = Array.from({ length: 300 }, (_, index) => String(index)).join("\n");
    await expect(generatePasswordCandidates({ ...options, words: manyWords, maxCandidates: 1_000, maxWork: 1_000, maxOutputBytes: 10_000 }, async () => { yields++; throw new DOMException("cancelled", "AbortError"); })).rejects.toMatchObject({ name: "AbortError" });
    expect(yields).toBe(1);
    await expect(generatePasswordCandidates({ ...options, rules: "p1" })).rejects.toMatchObject({ code: "INVALID_PARAMS" });
  });

  it("exposes both a bounded wordlist and a truncation report through the registry", async () => {
    const { words: _words, ...params } = options;
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "credential.candidates.generate", inputs: { words: textValue("a\nb") },
      params: { ...params, source: "combine", combineWith: "1\n2", maxCandidates: 3 },
    });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.candidates as { text: string }).text).toBe("a1\na2\nb1");
    expect((result.outputs.report as { data: object }).data).toEqual({ generated: 3, work: 4, truncated: true, source: "combine" });
    expect(result.run.diagnostics).toEqual(["Generated 3 candidate(s) from 4 attempt(s). A configured limit was reached."]);
  });
});