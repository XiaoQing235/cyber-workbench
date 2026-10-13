const MAX_MODULUS = 1n << 64n;

export interface LcgRecovery {
  modulus: string;
  multiplier: string;
  increment: string;
  observed: number;
  next: string[];
  verified: boolean;
}

function residue(value: bigint, modulus: bigint): bigint {
  const remainder = value % modulus;
  return remainder < 0n ? remainder + modulus : remainder;
}

function inverse(value: bigint, modulus: bigint): bigint | null {
  let remainder = modulus;
  let nextRemainder = residue(value, modulus);
  let coefficient = 0n;
  let nextCoefficient = 1n;
  while (nextRemainder !== 0n) {
    const quotient = remainder / nextRemainder;
    [remainder, nextRemainder] = [nextRemainder, remainder - quotient * nextRemainder];
    [coefficient, nextCoefficient] = [nextCoefficient, coefficient - quotient * nextCoefficient];
  }
  return remainder === 1n ? residue(coefficient, modulus) : null;
}

function decimal(value: unknown, label: string, maxDigits = 20): bigint {
  if (typeof value !== "string" || value.length > maxDigits || !/^(?:0|[1-9][0-9]*)$/.test(value)) throw new Error(`${label} must be an unsigned decimal integer of at most ${maxDigits} digits`);
  return BigInt(value);
}

function parseObservations(text: string, minimum: number, maximum: number, maxDigits: number): bigint[] {
  let values: unknown;
  if (text.trimStart().startsWith("[")) {
    try { values = JSON.parse(text); }
    catch { throw new Error("LCG observations are not valid JSON"); }
  } else values = text.replace(/\r/g, "").split("\n").filter(Boolean);
  if (!Array.isArray(values) || values.length < minimum || values.length > maximum) throw new Error(`LCG recovery requires ${minimum} to ${maximum.toLocaleString("en-US")} observed outputs`);
  return values.map((value, index) => decimal(value, `LCG output ${index}`, maxDigits));
}

function gcd(left: bigint, right: bigint): bigint {
  let first = left < 0n ? -left : left;
  let second = right < 0n ? -right : right;
  while (second !== 0n) [first, second] = [second, first % second];
  return first;
}

export function recoverLcg(text: string, modulusText: string, predictCount: number): LcgRecovery {
  const modulus = decimal(modulusText, "LCG modulus");
  if (modulus < 2n || modulus > MAX_MODULUS) throw new Error("LCG modulus must be between 2 and 2^64");
  if (!Number.isSafeInteger(predictCount) || predictCount < 1 || predictCount > 64) throw new Error("LCG prediction count must be between 1 and 64");
  const outputs = parseObservations(text, 3, 1_024, 20);
  if (outputs.some((value) => value >= modulus)) throw new Error("LCG output exceeds the declared modulus");
  const firstDifference = residue(outputs[1] - outputs[0], modulus);
  const multiplierInverse = inverse(firstDifference, modulus);
  if (multiplierInverse === null) throw new Error("LCG differences are not invertible; multiple generators fit these observations");
  const multiplier = residue((outputs[2] - outputs[1]) * multiplierInverse, modulus);
  const increment = residue(outputs[1] - multiplier * outputs[0], modulus);
  for (let index = 1; index < outputs.length; index++) {
    if (residue(multiplier * outputs[index - 1] + increment, modulus) !== outputs[index]) throw new Error(`LCG parameters do not reproduce observed output ${index}`);
  }
  const next: string[] = [];
  let value = outputs[outputs.length - 1];
  for (let index = 0; index < predictCount; index++) {
    value = residue(multiplier * value + increment, modulus);
    next.push(value.toString());
  }
  return { modulus: modulus.toString(), multiplier: multiplier.toString(), increment: increment.toString(), observed: outputs.length, next, verified: outputs.length > 3 };
}

export function recoverUnknownModulusLcg(text: string, predictCount: number): LcgRecovery & { modulusCandidate: true; determinantsUsed: number } {
  if (!Number.isSafeInteger(predictCount) || predictCount < 1 || predictCount > 16) throw new Error("Unknown-modulus LCG prediction count must be between 1 and 16");
  const outputs = parseObservations(text, 6, 64, 155);
  if (outputs.some((value) => value >= (1n << 512n))) throw new Error("LCG outputs must be under 2^512");
  const differences = outputs.slice(1).map((value, index) => value - outputs[index]);
  let modulus = 0n;
  for (let index = 0; index + 2 < differences.length; index++) {
    const first = differences[index];
    const second = differences[index + 1];
    const third = differences[index + 2];
    modulus = gcd(modulus, second * second - first * third);
  }
  if (modulus <= 1n || modulus >= (1n << 512n) || outputs.some((value) => value >= modulus)) throw new Error("LCG modulus candidate is zero, out of range or inconsistent with the observations");
  const firstDifference = residue(outputs[1] - outputs[0], modulus);
  const multiplierInverse = inverse(firstDifference, modulus);
  if (multiplierInverse === null) throw new Error("LCG modulus candidate has non-invertible differences; multiple generators fit these observations");
  const multiplier = residue((outputs[2] - outputs[1]) * multiplierInverse, modulus);
  const increment = residue(outputs[1] - multiplier * outputs[0], modulus);
  for (let index = 1; index < outputs.length; index++) {
    if (residue(multiplier * outputs[index - 1] + increment, modulus) !== outputs[index]) throw new Error(`LCG candidate does not reproduce observed output ${index}`);
  }
  const next: string[] = [];
  let value = outputs[outputs.length - 1];
  for (let index = 0; index < predictCount; index++) {
    value = residue(multiplier * value + increment, modulus);
    next.push(value.toString());
  }
  return { modulus: modulus.toString(), multiplier: multiplier.toString(), increment: increment.toString(), observed: outputs.length,
    next, verified: true, modulusCandidate: true, determinantsUsed: differences.length - 2 };
}
