import { describe, expect, it } from "vitest";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { parsePaddingOracleInput, simulatePaddingOracle } from "./paddingOracle";

const hex = (bytes: Uint8Array): string => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

describe("local AES-CBC padding oracle", () => {
  it("distinguishes valid ciphertext from broken PKCS#7 padding with a real AES key", async () => {
    const keyBytes = new Uint8Array(16).fill(7);
    const iv = new Uint8Array(16).fill(4);
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-CBC", false, ["encrypt"]);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, new TextEncoder().encode("local oracle fixture")));
    const damaged = ciphertext.slice();
    damaged[damaged.length - 1] ^= 1;
    const input = parsePaddingOracleInput(JSON.stringify({ key: hex(keyBytes), iv: hex(iv), ciphertexts: [hex(ciphertext), hex(damaged)] }));
    expect(await simulatePaddingOracle(input, 2)).toEqual({
      probed: 2, available: 2, valid: 1, truncated: false,
      outcomes: [{ index: 0, status: "valid", plaintextBytes: 20 }, { index: 1, status: "invalid" }],
    });
    expect(await simulatePaddingOracle(input, 1)).toMatchObject({ probed: 1, truncated: true, valid: 1 });
  });

  it("rejects incomplete blocks, unsupported fields, and invalid key lengths", () => {
    const sample = { key: "00".repeat(16), iv: "00".repeat(16), ciphertexts: ["00".repeat(16)] };
    expect(() => parsePaddingOracleInput(JSON.stringify({ ...sample, ciphertexts: ["00".repeat(15)] }))).toThrow(/complete 16-byte blocks/);
    expect(() => parsePaddingOracleInput(JSON.stringify({ ...sample, key: "00".repeat(15) }))).toThrow(/AES key/);
    expect(() => parsePaddingOracleInput(JSON.stringify({ ...sample, secret: "extra" }))).toThrow(/unsupported field/);
  });

  it("returns a bounded report without key or ciphertext material", async () => {
    const keyBytes = new Uint8Array(16).fill(7);
    const iv = new Uint8Array(16).fill(4);
    const key = await crypto.subtle.importKey("raw", keyBytes, "AES-CBC", false, ["encrypt"]);
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, new TextEncoder().encode("valid")));
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "crypto.oracle.padding-simulate",
      inputs: { probes: textValue(JSON.stringify({ key: hex(keyBytes), iv: hex(iv), ciphertexts: [hex(ciphertext), hex(ciphertext)] })) },
      params: { maxProbes: 1 },
    });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: object }).data).toEqual({
      probed: 1, available: 2, valid: 1, truncated: true, outcomes: [{ index: 0, status: "valid", plaintextBytes: 5 }],
    });
    expect(result.run.diagnostics).toEqual(["Tested 1 local probe(s); 1 had valid PKCS#7 padding. Probe budget reached."]);
    expect(JSON.stringify((result.outputs.report as { data: object }).data)).not.toContain(hex(keyBytes));
  });
});