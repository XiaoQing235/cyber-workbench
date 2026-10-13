import { readAll } from "../../core/bytes/sources";
import { CRC32_INITIAL, crc32Finish, crc32Update } from "../../core/checksum/crc32";
import { defineOperation } from "../../core/operation/types";
import { numberValue, textValue } from "../../core/value";
import { bytesInput, forEachChunk, MiB, toHex } from "../util";

type DigestAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

export const hashDigest = defineOperation<{ algorithm: DigestAlgorithm }>({
  spec: {
    id: "hash.digest",
    version: "1.0.0",
    title: "Hash (SHA family)",
    category: "Hashing",
    description: "Compute a SHA-1 / SHA-2 digest with Web Crypto. Output is lowercase hex.",
    keywords: ["sha1", "sha256", "sha512", "digest", "checksum"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "digest", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: {
        algorithm: {
          type: "string",
          title: "Algorithm",
          enum: ["SHA-1", "SHA-256", "SHA-384", "SHA-512"],
          default: "SHA-256",
        },
      },
      required: ["algorithm"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "low",
    limits: { maxInputBytes: 256 * MiB },
  },
  async run(_ctx, inputs, params) {
    const data = await readAll(bytesInput(inputs));
    const digest = await crypto.subtle.digest(params.algorithm, data);
    return { digest: textValue(toHex(new Uint8Array(digest))) };
  },
});

export const crc32 = defineOperation<Record<string, never>>({
  spec: {
    id: "checksum.crc32",
    version: "1.0.0",
    title: "CRC-32",
    category: "Hashing",
    description: "CRC-32 (IEEE 802.3, as used by ZIP, PNG and gzip).",
    keywords: ["crc", "checksum", "png", "zip"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "crc", type: "number" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "low",
    limits: { maxInputBytes: 4096 * MiB },
  },
  async run(ctx, inputs) {
    let register = CRC32_INITIAL;
    await forEachChunk(ctx, bytesInput(inputs), (chunk) => {
      register = crc32Update(register, chunk);
    });
    return { crc: numberValue(crc32Finish(register)) };
  },
});
