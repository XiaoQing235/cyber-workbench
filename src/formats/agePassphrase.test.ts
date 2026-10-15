import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { decryptAgePassphrase } from "./agePassphrase";

const original = new Uint8Array(readFileSync(new URL("./testing/google-ctf-2023-npc-secret.age", import.meta.url)));
const publishedPassphrase = "standardwatersigngivenchosen";

describe("age scrypt passphrase decryption", () => {
  it("decrypts the original Google CTF 2023 NPC ciphertext to the archived flag", async () => {
    expect(createHash("sha256").update(original).digest("hex")).toBe("6d816411e3b738f8bc2cc508fdde3a4fc50dca5dc778cec7f2bc6b209c9b7512");
    const result = await decryptAgePassphrase(new MemorySource(original), publishedPassphrase);
    expect(result.workFactor).toBe(19);
    expect(new TextDecoder("utf-8", { fatal: true }).decode(result.plaintext)).toBe("CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}");
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "crypto.age.passphrase-decrypt",
      inputs: { data: bytesValue(new MemorySource(original)) }, params: { passphrase: publishedPassphrase } });
    expect(operation.run.status).toBe("success");
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: { authenticated: true, workFactor: 19,
      utf8Candidate: "CTF{S3vEn_bR1dg35_0f_K0eN1g5BeRg}", flagVerified: false } });
    expect(operation.run.diagnostics.join(" ")).not.toContain(publishedPassphrase);
  }, 30_000);

  it("rejects unsupported or excessive work before key derivation", async () => {
    const tooCostly = original.slice();
    const factorOffset = new TextDecoder().decode(tooCostly.subarray(0, 90)).indexOf(" 19\n") + 1;
    expect(factorOffset).toBeGreaterThan(0);
    tooCostly[factorOffset] = 0x32;
    await expect(decryptAgePassphrase(new MemorySource(tooCostly), publishedPassphrase)).rejects.toThrow(/work factor exceeds 19/);
    await expect(decryptAgePassphrase(new MemorySource(original.subarray(0, 90)), publishedPassphrase)).rejects.toThrow();
    await expect(decryptAgePassphrase(new MemorySource(new Uint8Array(64 * 1024 + 1)), publishedPassphrase)).rejects.toThrow(/64 KiB/);
  });

  it("does not return plaintext for a wrong passphrase", async () => {
    await expect(decryptAgePassphrase(new MemorySource(original), "incorrect-passphrase")).rejects.toThrow();
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "crypto.age.passphrase-decrypt",
      inputs: { data: bytesValue(new MemorySource(original)) }, params: { passphrase: "incorrect-passphrase" } });
    expect(operation.run.status).toBe("failed");
    expect(operation.outputs.plaintext).toBeUndefined();
  }, 30_000);
});
