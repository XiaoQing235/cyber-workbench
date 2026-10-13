export interface LcgRsaReport {
  seed: string;
  primes: string[];
  primeConfidence: "probable";
  iterations: number;
  rsaModulus: string;
  publicExponent: "65537";
  decrypted: { hex: string; utf8: string | null }[];
}

function decimal(value: unknown, label: string): bigint {
  if (typeof value !== "string" || value.length > 155 || !/^(?:0|[1-9][0-9]*)$/.test(value)) throw new Error(`${label} must be an exact unsigned decimal string of at most 155 digits`);
  return BigInt(value);
}

export async function reconstructLcgRsa(text: string, primeBits: number, primeCount: number, maxIterations: number, signal?: AbortSignal): Promise<LcgRsaReport> {
  if (text.length > 16_000 || !Number.isSafeInteger(primeBits) || primeBits < 8 || primeBits > 512 ||
    !Number.isSafeInteger(primeCount) || primeCount < 2 || primeCount > 8 ||
    !Number.isSafeInteger(maxIterations) || maxIterations < 1 || maxIterations > 20_000) throw new Error("LCG-RSA input or computation budget is invalid");
  let parsed: unknown;
  try { parsed = JSON.parse(text); }
  catch { throw new Error("LCG-RSA input is not valid JSON"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("LCG-RSA input must be an object");
  const input = parsed as Record<string, unknown>;
  if (Object.keys(input).some((key) => !["modulus", "multiplier", "increment", "firstObserved", "ciphertexts"].includes(key)) ||
    !Array.isArray(input.ciphertexts) || input.ciphertexts.length < 1 || input.ciphertexts.length > 4 ||
    input.ciphertexts.some((cipher) => typeof cipher !== "string" || cipher.length < 2 || cipher.length > 8_192 || cipher.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(cipher))) {
    throw new Error("LCG-RSA input needs 1-4 little-endian hex ciphertexts and only the generator fields");
  }
  const modulus = decimal(input.modulus, "LCG modulus");
  const multiplier = decimal(input.multiplier, "LCG multiplier");
  const increment = decimal(input.increment, "LCG increment");
  const firstObserved = decimal(input.firstObserved, "First LCG output");
  if (modulus < 2n || modulus >= (1n << 512n) || multiplier >= modulus || increment >= modulus || firstObserved >= modulus) throw new Error("LCG-RSA generator parameters exceed the 512-bit modulus budget");
  const [{ default: isProbablyPrime }, { modInv, modPow }] = await Promise.all([import("crypto-miller-rabin"), import("bigint-mod-arith")]);
  let seed: bigint;
  try { seed = ((firstObserved - increment) * modInv(multiplier, modulus) % modulus + modulus) % modulus; }
  catch { throw new Error("LCG multiplier is not invertible, so the initial state cannot be recovered"); }
  let state = seed;
  const primes: bigint[] = [];
  let iterations = 0;
  while (primes.length < primeCount && iterations < maxIterations) {
    if (signal?.aborted) throw signal.reason;
    state = (multiplier * state + increment) % modulus;
    iterations++;
    if (state.toString(2).length === primeBits && !primes.includes(state) && isProbablyPrime(state, 16)) primes.push(state);
    if (iterations % 32 === 0) await new Promise((resolve) => setTimeout(resolve, 0));
  }
  if (primes.length !== primeCount) throw new Error(`LCG-RSA search found ${primes.length} of ${primeCount} probable primes within ${maxIterations} iterations`);
  const rsaModulus = primes.reduce((product, prime) => product * prime, 1n);
  const totient = primes.reduce((product, prime) => product * (prime - 1n), 1n);
  const publicExponent = 65537n;
  let privateExponent: bigint;
  try { privateExponent = modInv(publicExponent, totient); }
  catch { throw new Error("RSA public exponent has no inverse for the recovered prime candidates"); }
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const decrypted = (input.ciphertexts as string[]).map((ciphertext) => {
    const bytes = Uint8Array.from(ciphertext.match(/../g)!, (pair) => Number.parseInt(pair, 16));
    let value = 0n;
    for (let index = bytes.length - 1; index >= 0; index--) value = (value << 8n) | BigInt(bytes[index]);
    if (value >= rsaModulus) throw new Error("LCG-RSA ciphertext exceeds the reconstructed RSA modulus");
    const plain = modPow(value, privateExponent, rsaModulus);
    const hex = plain.toString(16).padStart(Math.ceil(plain.toString(16).length / 2) * 2, "0");
    let utf8: string | null;
    try { utf8 = decoder.decode(Uint8Array.from(hex.match(/../g)!, (pair) => Number.parseInt(pair, 16))); }
    catch { utf8 = null; }
    return { hex, utf8 };
  });
  return { seed: seed.toString(), primes: primes.map(String), primeConfidence: "probable", iterations, rsaModulus: rsaModulus.toString(),
    publicExponent: "65537", decrypted };
}
