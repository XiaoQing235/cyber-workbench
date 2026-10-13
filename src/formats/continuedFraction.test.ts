import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { continuedFraction } from "./continuedFraction";
import challenge from "./testing/google-ctf-2023-primes-chal.sage?raw";

describe("bounded exact continued fractions", () => {
  it("matches independently derived convergents from Google CTF 2023 published constants", async () => {
    const published = Object.fromEntries(Array.from(challenge.matchAll(/^# (q|x) = 0x([0-9a-f]+)$/gim), ([, name, hex]) => [name, BigInt(`0x${hex}`).toString()]));
    expect(Object.keys(published).sort()).toEqual(["q", "x"]);
    const input = JSON.stringify({ numerator: published.x, denominator: published.q });
    const report = continuedFraction(input, 12);
    expect(report.terms).toEqual([
      [0, 0, 1], [1, 1, 1], [2, 2, 3], [2, 5, 7], [1, 7, 10], [2, 19, 27],
      [12, 235, 334], [1, 254, 361], [30, 7855, 11164], [1, 8109, 11525],
      [1, 15964, 22689], [80, 1285229, 1826645],
    ].map(([quotient, numerator, denominator], index) => ({ index, quotient: String(quotient), numerator: String(numerator), denominator: String(denominator) })));
    expect(report).toMatchObject({ complete: false, truncated: true });
    const result = await executeOperation(createDefaultRegistry(), { operationId: "crypto.rational.continued-fraction",
      inputs: { fraction: textValue(input) }, params: { maxTerms: 12 } });
    expect(result.run.error).toBeUndefined();
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { terms: report.terms, truncated: true } });
  });

  it("enforces exact input and reports a completed expansion", () => {
    expect(continuedFraction('{"numerator":"355","denominator":"113"}', 10)).toMatchObject({ complete: true, truncated: false,
      terms: [{ quotient: "3", numerator: "3", denominator: "1" }, { quotient: "7", numerator: "22", denominator: "7" },
        { quotient: "16", numerator: "355", denominator: "113" }] });
    expect(continuedFraction('{"numerator":"355","denominator":"113"}', 2)).toMatchObject({ complete: false, truncated: true });
    expect(() => continuedFraction('{"numerator":355,"denominator":"113"}', 10)).toThrow(/exact unsigned decimal/);
    expect(() => continuedFraction('{"numerator":"1","denominator":"0"}', 10)).toThrow(/nonzero/);
  });
});