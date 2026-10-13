import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { recoverOneQuarterRound } from "./oneQuarterRound";

const hexBytes = (value: string) => {
  if (!/^(?:[0-9a-f]{2})+$/i.test(value)) throw new Error("Fixture hex must contain complete bytes");
  return Uint8Array.from(value.match(/../g)!, (part) => Number.parseInt(part, 16));
};

describe("one-quarter-round prefix recovery", () => {
  it("inverts a nonzero-key official cipher vector independently of the nonce", () => {
    const key = hexBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const plaintext = Uint8Array.from({ length: 48 }, (_, index) => index);
    const ciphertext = hexBytes("309eaf3f0405060708090a0b0c0d0e0f9ddc45f21c1f1a19080b0e0d0407020199670b160c0f0a09181b1e1d14171211");
    const result = recoverOneQuarterRound(key, ciphertext, plaintext.subarray(0, 4));
    expect(result.counter).toBe(0x89abcdef);
    expect(result.plaintext).toEqual(plaintext);
  });

  it("derives counter 1 and reproduces a published Numerology learning pair", () => {
    const key = hexBytes("000000005c5470020000000031f4727bf7d4923400000000e7bbb1c900000000");
    const plaintext = hexBytes("9de16236ae1521cffe67ab68fd1325951b2a1b11b75bec946325faca2a8db02a013b9c18ddd31f168e6dd472ebccdfc7");
    const ciphertext = hexBytes("d4922d0bae1521cffe67ab68fd132595c4942d350ff30c906325faca486555dc2ac805afddd31f16401ab7e1ebccdfc7");
    const result = recoverOneQuarterRound(key, ciphertext, plaintext.subarray(0, 4));
    expect(result).toMatchObject({ counter: 1, assumedPrefixBytes: 4, nonceIndependentBytes: 48, verified: false });
    expect(result.plaintext).toEqual(plaintext);
  });

  it("rejects bytes whose nonce independence is not established", () => {
    const key = new Uint8Array(32);
    const prefix = new Uint8Array(4);
    expect(() => recoverOneQuarterRound(key, new Uint8Array(49), prefix)).toThrow(/4-48/);
    expect(() => recoverOneQuarterRound(key, new Uint8Array(3), prefix)).toThrow(/4-48/);
    expect(() => recoverOneQuarterRound(new Uint8Array(31), new Uint8Array(4), prefix)).toThrow(/32-byte/);
  });

  it("recovers the archived Google CTF 2025 flag from the byte-identical challenge package", async () => {
    const original = readFileSync(new URL("./testing/google-ctf-2025-numerology.json", import.meta.url));
    expect(createHash("sha256").update(original).digest("hex")).toBe("c088a9227cff73fa9f41d5e010fc691ee796d45113546f885665312d71197ed7");
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "crypto.chacha.qr1-prefix-recover", inputs: { data: bytesValue(new MemorySource(new Uint8Array(original))) },
      params: { knownPrefixHex: "4354467b" },
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { counter: 32279, verified: false, nonceIndependentBytes: 42 } });
    if (result.outputs.candidate?.type !== "bytes") throw new Error("Expected candidate bytes");
    expect(new TextDecoder().decode(await readAll(result.outputs.candidate.source))).toBe("CTF{w3_aRe_g0Nn@_ge7_MY_FuncKee_monkey_!!}");
  });

  it("rejects malformed packages and ciphertext extending into nonce-dependent words", async () => {
    const registry = createDefaultRegistry();
    for (const document of [
      { cipher_parameters: { key: "00".repeat(32) }, flag_ciphertext: "00".repeat(49) },
      { cipher_parameters: { key: "00".repeat(31) }, flag_ciphertext: "00".repeat(4) },
      { cipher_parameters: { key: "00".repeat(32) }, flag_ciphertext: "f" },
    ]) {
      const result = await executeOperation(registry, {
        operationId: "crypto.chacha.qr1-prefix-recover",
        inputs: { data: bytesValue(new MemorySource(new TextEncoder().encode(JSON.stringify(document)))) },
        params: { knownPrefixHex: "4354467b" },
      });
      expect(result.run.status).toBe("failed");
      expect(result.outputs.candidate).toBeUndefined();
    }
  });
});