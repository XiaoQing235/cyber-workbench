export const MAX_QR1_BYTES = 48;

export interface QuarterRoundRecovery {
  counter: number;
  plaintext: Uint8Array<ArrayBuffer>;
  assumedPrefixBytes: 4;
  nonceIndependentBytes: number;
  verified: false;
}

const rotateLeft = (word: number, bits: number) => ((word << bits) | (word >>> (32 - bits))) >>> 0;
const rotateRight = (word: number, bits: number) => ((word >>> bits) | (word << (32 - bits))) >>> 0;

export function recoverOneQuarterRound(key: Uint8Array, ciphertext: Uint8Array, prefix: Uint8Array): QuarterRoundRecovery {
  if (key.length !== 32 || prefix.length !== 4 || ciphertext.length < 4 || ciphertext.length > MAX_QR1_BYTES) {
    throw new Error("One-quarter-round recovery requires a 32-byte key, a four-byte prefix and 4-48 ciphertext bytes");
  }
  const keyWords = new DataView(key.buffer, key.byteOffset, key.byteLength);
  const cipherWords = new DataView(ciphertext.buffer, ciphertext.byteOffset, ciphertext.byteLength);
  const prefixWord = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength).getUint32(0, true);
  const key0 = keyWords.getUint32(0, true);
  const key4 = keyWords.getUint32(16, true);
  const output0 = cipherWords.getUint32(0, true) ^ prefixWord;
  const counter = (rotateRight(((rotateRight((output0 - key0) >>> 0, 12) ^ key0) - key4) >>> 0, 16) ^ key0) >>> 0;

  const state = new Uint32Array(16);
  for (let index = 0; index < 8; index++) state[4 + index] = keyWords.getUint32(index * 4, true);
  state[12] = counter;
  const mixed = state.slice();
  let a = (mixed[0] + mixed[4]) >>> 0;
  let d = rotateLeft(mixed[12] ^ a, 16);
  let c = (mixed[8] + d) >>> 0;
  let b = rotateLeft(mixed[4] ^ c, 12);
  a = (a + b) >>> 0;
  d = rotateLeft(d ^ a, 8);
  c = (c + d) >>> 0;
  b = rotateLeft(b ^ c, 7);
  mixed[0] = a;
  mixed[4] = b;
  mixed[8] = c;

  const plaintext = new Uint8Array(ciphertext.length);
  for (let index = 0; index < ciphertext.length; index++) {
    const word = index >>> 2;
    const keystreamWord = (mixed[word] + state[word]) >>> 0;
    plaintext[index] = ciphertext[index] ^ ((keystreamWord >>> ((index & 3) * 8)) & 0xff);
  }
  return { counter, plaintext, assumedPrefixBytes: 4, nonceIndependentBytes: ciphertext.length, verified: false };
}