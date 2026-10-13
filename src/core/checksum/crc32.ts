export const CRC32_TABLE = Uint32Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});

export const CRC32_INITIAL = 0xffffffff;

/** Feeds bytes into a running CRC-32 register (start from CRC32_INITIAL). */
export function crc32Update(register: number, bytes: Uint8Array): number {
  let crc = register;
  for (let i = 0; i < bytes.length; i++) crc = CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return crc;
}

export function crc32Finish(register: number): number {
  return (register ^ 0xffffffff) >>> 0;
}

/** CRC-32 (IEEE 802.3) as used by PNG, ZIP and gzip. */
export function crc32(bytes: Uint8Array): number {
  return crc32Finish(crc32Update(CRC32_INITIAL, bytes));
}

export function crc32FourBytePreimage(checksum: number): Uint8Array<ArrayBuffer> {
  if (!Number.isInteger(checksum) || checksum < 0 || checksum > 0xffffffff) throw new Error("CRC-32 must be an unsigned 32-bit integer");
  const zeroChecksum = crc32(new Uint8Array(4));
  const columns = Array.from({ length: 32 }, (_, bit) => {
    const bytes = new Uint8Array(4);
    bytes[bit >>> 3] = 1 << (bit & 7);
    return crc32(bytes) ^ zeroChecksum;
  });
  const rows = new Uint32Array(32);
  const answers = new Uint8Array(32);
  for (let outputBit = 0; outputBit < 32; outputBit++) {
    for (let inputBit = 0; inputBit < 32; inputBit++) {
      if ((columns[inputBit] >>> outputBit) & 1) rows[outputBit] |= (1 << inputBit) >>> 0;
    }
    answers[outputBit] = ((checksum ^ zeroChecksum) >>> outputBit) & 1;
  }
  for (let bit = 0; bit < 32; bit++) {
    const pivot = rows.findIndex((row, index) => index >= bit && ((row >>> bit) & 1) !== 0);
    if (pivot < 0) throw new Error("CRC-32 four-byte mapping is not invertible");
    [rows[bit], rows[pivot]] = [rows[pivot], rows[bit]];
    [answers[bit], answers[pivot]] = [answers[pivot], answers[bit]];
    for (let index = 0; index < 32; index++) {
      if (index !== bit && ((rows[index] >>> bit) & 1)) {
        rows[index] ^= rows[bit];
        answers[index] ^= answers[bit];
      }
    }
  }
  const bytes = new Uint8Array(4);
  for (let bit = 0; bit < 32; bit++) bytes[bit >>> 3] |= answers[bit] << (bit & 7);
  return bytes;
}
