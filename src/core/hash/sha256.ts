import type { ByteSource } from "../bytes/ByteSource";

const K = Uint32Array.of(
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
);

const HASH_CHUNK = 4 * 1024 * 1024;

/** Incremental SHA-256 (WebCrypto can only digest a complete buffer). */
export class Sha256 {
  private readonly state = Uint32Array.of(
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  );
  private readonly block = new Uint8Array(64);
  private readonly words = new Uint32Array(64);
  private blockLength = 0;
  private totalBytes = 0;
  private finished = false;

  update(data: Uint8Array): this {
    if (this.finished) throw new Error("SHA-256 already finished");
    this.totalBytes += data.length;
    let offset = 0;
    if (this.blockLength > 0) {
      offset = Math.min(64 - this.blockLength, data.length);
      this.block.set(data.subarray(0, offset), this.blockLength);
      this.blockLength += offset;
      if (this.blockLength < 64) return this;
      this.compress(this.block, 0);
      this.blockLength = 0;
    }
    for (; offset + 64 <= data.length; offset += 64) this.compress(data, offset);
    if (offset < data.length) {
      this.block.set(data.subarray(offset));
      this.blockLength = data.length - offset;
    }
    return this;
  }

  digest(): Uint8Array<ArrayBuffer> {
    const bits = this.totalBytes * 8;
    const padding = new Uint8Array((this.blockLength < 56 ? 64 : 128) - this.blockLength);
    padding[0] = 0x80;
    const view = new DataView(padding.buffer);
    view.setUint32(padding.length - 8, Math.floor(bits / 2 ** 32));
    view.setUint32(padding.length - 4, bits >>> 0);
    this.update(padding);
    this.finished = true;
    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) outView.setUint32(i * 4, this.state[i]);
    return out;
  }

  private compress(data: Uint8Array, offset: number): void {
    const w = this.words;
    for (let i = 0; i < 16; i++) {
      const j = offset + i * 4;
      w[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
    }
    for (let i = 16; i < 64; i++) {
      const x = w[i - 15];
      const y = w[i - 2];
      const s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
      const s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    const s = this.state;
    let a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
    for (let i = 0; i < 64; i++) {
      const sum1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const t1 = (h + sum1 + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
      const sum0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const t2 = (sum0 + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      h = g;
      g = f;
      f = e;
      e = (d + t1) | 0;
      d = c;
      c = b;
      b = a;
      a = (t1 + t2) | 0;
    }
    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
  }
}

export function toHexString(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const cache = new WeakMap<ByteSource, Promise<string>>();

/**
 * Hex SHA-256 of a source, read in chunks. Sources are immutable, so the result is memoised.
 * Each chunk yields to the event loop so hashing a large file on the main thread stays responsive.
 */
export function sha256Source(source: ByteSource): Promise<string> {
  let pending = cache.get(source);
  if (!pending) {
    pending = (async () => {
      const hash = new Sha256();
      for (let offset = 0; offset < source.size; offset += HASH_CHUNK) {
        hash.update(await source.read(offset, HASH_CHUNK));
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
      return toHexString(hash.digest());
    })();
    pending.catch(() => cache.delete(source));
    cache.set(source, pending);
  }
  return pending;
}

/** Records a hash that is already known (e.g. content-addressed storage), avoiding a re-read. */
export function rememberSha256(source: ByteSource, hash: string): void {
  cache.set(source, Promise.resolve(hash));
}
