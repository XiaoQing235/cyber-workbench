export interface ContinuedFractionReport {
  numerator: string;
  denominator: string;
  terms: { index: number; quotient: string; numerator: string; denominator: string }[];
  complete: boolean;
  truncated: boolean;
}

function exact(value: unknown, name: string): bigint {
  if (typeof value !== "string" || value.length > 617 || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${name} must be an exact unsigned decimal string of at most 617 digits`);
  }
  return BigInt(value);
}

export function continuedFraction(text: string, maxTerms: number): ContinuedFractionReport {
  if (text.length > 4_096 || !Number.isSafeInteger(maxTerms) || maxTerms < 1 || maxTerms > 128) throw new Error("Continued-fraction input or term budget is invalid");
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { throw new Error("Continued-fraction input is not valid JSON"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Continued-fraction input must be an object");
  const data = parsed as Record<string, unknown>;
  if (Object.keys(data).length !== 2 || !Object.hasOwn(data, "numerator") || !Object.hasOwn(data, "denominator")) {
    throw new Error("Continued-fraction input needs only numerator and denominator");
  }
  const numerator = exact(data.numerator, "Numerator");
  const denominator = exact(data.denominator, "Denominator");
  if (denominator === 0n) throw new Error("Continued-fraction denominator must be nonzero");
  let remainder = numerator;
  let divisor = denominator;
  let previousNumerator = 1n;
  let beforeNumerator = 0n;
  let previousDenominator = 0n;
  let beforeDenominator = 1n;
  const terms: ContinuedFractionReport["terms"] = [];
  while (divisor !== 0n && terms.length < maxTerms) {
    const quotient = remainder / divisor;
    const nextNumerator = quotient * previousNumerator + beforeNumerator;
    const nextDenominator = quotient * previousDenominator + beforeDenominator;
    terms.push({ index: terms.length, quotient: quotient.toString(), numerator: nextNumerator.toString(), denominator: nextDenominator.toString() });
    [remainder, divisor] = [divisor, remainder % divisor];
    [beforeNumerator, previousNumerator] = [previousNumerator, nextNumerator];
    [beforeDenominator, previousDenominator] = [previousDenominator, nextDenominator];
  }
  return { numerator: numerator.toString(), denominator: denominator.toString(), terms, complete: divisor === 0n, truncated: divisor !== 0n };
}