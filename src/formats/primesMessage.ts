/** Bounded version of the indexed-small-prime and convergent recovery in Google CTF's Primes solver. */
export function recoverPrimeMessage(text: string, maxTerms: number): {
  candidate: string | null; correctedBits: number; convergentIndex: number | null; testedConvergents: number; verifiedEncoding: boolean;
} {
  if (text.length > 5_000 || !Number.isSafeInteger(maxTerms) || maxTerms < 1 || maxTerms > 2048) throw new Error("Primes input or convergent budget is invalid");
  let input: unknown;
  try { input = JSON.parse(text); } catch { throw new Error("Primes input must be JSON"); }
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("Primes input must be an object");
  const data = input as Record<string, unknown>;
  if (Object.keys(data).sort().join(",") !== "message,q,x" || typeof data.message !== "string" ||
    data.message.length < 1 || data.message.length > 128 || /[^\x00-\x7f]/.test(data.message) ||
    typeof data.q !== "string" || typeof data.x !== "string" || !/^0x[0-9a-f]{1,512}$/i.test(data.q) ||
    !/^0x[0-9a-f]{1,512}$/i.test(data.x)) throw new Error("Primes requires an ASCII message and at most 2048-bit hex q and x");
  const q = BigInt(data.q);
  const x = BigInt(data.x);
  if (q < 3n || x < 1n || x >= q) throw new Error("Primes q and x are outside modular bounds");
  const count = data.message.length * 7;
  const sieve = new Uint8Array(10_000);
  const primes: bigint[] = [];
  for (let n = 2; n < sieve.length && primes.length < count; n++) {
    if (sieve[n]) continue;
    primes.push(BigInt(n));
    for (let composite = n * n; composite < sieve.length; composite += n) sieve[composite] = 1;
  }
  if (primes.length !== count) throw new Error("Primes sieve cannot cover the message");
  let encoded = 1n;
  for (let i = 0; i < count; i++) if (data.message.charCodeAt(Math.floor(i / 7)) & (1 << (i % 7))) encoded = encoded * primes[i] % q;
  if (encoded === x) return { candidate: data.message, correctedBits: 0, convergentIndex: null, testedConvergents: 0, verifiedEncoding: true };
  let oldR = q;
  let r = encoded;
  let oldT = 0n;
  let t = 1n;
  while (r !== 0n) {
    const quotient = oldR / r;
    [oldR, r] = [r, oldR - quotient * r];
    [oldT, t] = [t, oldT - quotient * t];
  }
  if (oldR !== 1n) throw new Error("Primes message encoding is not invertible modulo q");
  const error = x * ((oldT % q + q) % q) % q;
  let a = error;
  let b = q;
  let denominatorPrevious = 0n;
  let denominatorBefore = 1n;
  const factor = (value: bigint): number[] | null => {
    if (value < 1n) return null;
    const indices: number[] = [];
    for (let index = 0; index < primes.length && value > 1n; index++) {
      if (value % primes[index] !== 0n) continue;
      value /= primes[index];
      if (value % primes[index] === 0n) return null;
      indices.push(index);
    }
    return value === 1n ? indices : null;
  };
  let testedConvergents = 0;
  while (b !== 0n && testedConvergents < maxTerms) {
    const quotient = a / b;
    const denominator = quotient * denominatorPrevious + denominatorBefore;
    [denominatorBefore, denominatorPrevious] = [denominatorPrevious, denominator];
    [a, b] = [b, a % b];
    const index = testedConvergents++;
    if (denominator === 0n) continue;
    const residue = denominator * error % q;
    const numeratorFactors = factor(denominator);
    const residueFactors = factor(residue);
    if (!numeratorFactors || !residueFactors || numeratorFactors.some((part) => residueFactors.includes(part))) continue;
    const output = Array.from(data.message, (character) => character.charCodeAt(0));
    for (const position of [...numeratorFactors, ...residueFactors]) output[Math.floor(position / 7)] ^= 1 << (position % 7);
    if (output.some((character) => character > 127 || character < 32)) continue;
    let check = 1n;
    for (let position = 0; position < count; position++) if (output[Math.floor(position / 7)] & (1 << (position % 7))) check = check * primes[position] % q;
    if (check !== x) continue;
    return { candidate: String.fromCharCode(...output), correctedBits: numeratorFactors.length + residueFactors.length,
      convergentIndex: index, testedConvergents, verifiedEncoding: true };
  }
  return { candidate: null, correctedBits: 0, convergentIndex: null, testedConvergents, verifiedEncoding: false };
}
