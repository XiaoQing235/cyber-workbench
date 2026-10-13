import { describe, expect, it } from "vitest";
import { readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { textValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { analyzeNonceReuse, parseNonceCsv, parseNonceRecords, recoverWithCrib } from "./nonceReuse";

const encoder = new TextEncoder();
const hex = (value: Uint8Array): string => Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");

describe("nonce reuse analysis", () => {
  it("recovers known plaintext from WebCrypto AES-CTR ciphertexts sharing a key and counter", async () => {
    const key = await crypto.subtle.importKey("raw", new Uint8Array(16), "AES-CTR", false, ["encrypt"]);
    const counter = new Uint8Array(16).fill(7);
    const firstPlain = encoder.encode("Known prefix with secret");
    const secondPlain = encoder.encode("Other text and password");
    const encrypt = async (plain: Uint8Array<ArrayBuffer>) => new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CTR", counter, length: 64 }, key, plain));
    const records = parseNonceRecords(JSON.stringify([
      { algorithm: "AES-CTR", keyId: "fixture-key", nonce: hex(counter), ciphertext: hex(await encrypt(firstPlain)), knownPlaintext: { offset: 6, hex: hex(firstPlain.subarray(6, 17)) } },
      { algorithm: "AES-CTR", keyId: "fixture-key", nonce: hex(counter), ciphertext: hex(await encrypt(secondPlain)) },
    ]));
    const groups = analyzeNonceReuse(records);
    expect(groups).toMatchObject([{ indexes: [0, 1], risk: "confirmed", overlapBytes: 23 }]);
    const result = recoverWithCrib(records, 0, 1);
    expect(hex(result.xor)).toBe(hex(Uint8Array.from(firstPlain.subarray(0, secondPlain.length), (byte, index) => byte ^ secondPlain[index])));
    expect(new TextDecoder().decode(result.recovered ?? undefined)).toBe("text and pa");
    expect(result.offset).toBe(6);
  });

  it("marks unknown key IDs as possible rather than proven keystream reuse", () => {
    const records = parseNonceRecords(JSON.stringify([
      { algorithm: "AES-GCM", nonce: "aa".repeat(12), ciphertext: "01", tag: "00".repeat(16) },
      { algorithm: "AES-GCM", nonce: "aa".repeat(12), ciphertext: "02" },
    ]));
    expect(analyzeNonceReuse(records)).toMatchObject([{ risk: "possible", xorPreview: "03" }]);
    expect(recoverWithCrib(records, 0, 1)).toMatchObject({ recovered: null, offset: null, risk: "possible" });
  });

  it("XORs only ciphertext, not WebCrypto AES-GCM authentication tags", async () => {
    const key = await crypto.subtle.importKey("raw", new Uint8Array(16).fill(5), "AES-GCM", false, ["encrypt"]);
    const nonce = new Uint8Array(12).fill(9);
    const firstPlain = encoder.encode("known message");
    const secondPlain = encoder.encode("other message");
    const seal = async (plain: Uint8Array<ArrayBuffer>) => {
      const encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plain));
      return { ciphertext: hex(encrypted.subarray(0, -16)), tag: hex(encrypted.subarray(-16)) };
    };
    const records = parseNonceRecords(JSON.stringify([
      { algorithm: "AES-GCM", keyId: "fixture", nonce: hex(nonce), ...await seal(firstPlain), knownPlaintext: { offset: 0, hex: hex(firstPlain) } },
      { algorithm: "AES-GCM", keyId: "fixture", nonce: hex(nonce), ...await seal(secondPlain) },
    ]));
    const result = recoverWithCrib(records, 0, 1);
    expect(hex(result.xor)).toBe(hex(Uint8Array.from(firstPlain, (byte, index) => byte ^ secondPlain[index])));
    expect(new TextDecoder().decode(result.recovered ?? undefined)).toBe("other message");
    expect(result.xor.length).toBe(firstPlain.length);
  });

  it("rejects ambiguous fields, malformed lengths, and mismatched keys", () => {
    const base = { algorithm: "AES-GCM", keyId: "one", nonce: "aa".repeat(12), ciphertext: "00" };
    expect(() => parseNonceRecords(JSON.stringify([{ ...base, extra: "ignored" }, base]))).toThrow(/unsupported field/);
    expect(() => parseNonceRecords(JSON.stringify([{ ...base, nonce: "aa".repeat(13) }, base]))).toThrow(/invalid size/);
    expect(() => parseNonceRecords(JSON.stringify([{ ...base, knownPlaintext: { offset: 1, hex: "01" } }, base]))).toThrow(/exceeds the ciphertext/);
    const distinctKeys = parseNonceRecords(JSON.stringify([base, { ...base, keyId: "two" }]));
    expect(analyzeNonceReuse(distinctKeys)).toEqual([]);
    expect(() => recoverWithCrib(distinctKeys, 0, 1)).toThrow(/do not share/);
  });

  it("exposes group, XOR, and unverified crib candidate outputs through the registry", async () => {
    const input = textValue(JSON.stringify([
      { algorithm: "AES-CTR", keyId: "key-1", nonce: "00".repeat(16), ciphertext: "010203", knownPlaintext: { offset: 1, hex: "6162" } },
      { algorithm: "AES-CTR", keyId: "key-1", nonce: "00".repeat(16), ciphertext: "040506" },
    ]));
    const registry = createDefaultRegistry();
    const inspectResult = await executeOperation(registry, { operationId: "crypto.nonce-reuse.inspect", inputs: { records: input }, params: {} });
    expect(inspectResult.run.error).toBeUndefined();
    expect((inspectResult.outputs.report as { data: object }).data).toMatchObject({ recordCount: 2, groups: [{ risk: "confirmed", indexes: [0, 1] }] });
    const params = { firstIndex: 0, secondIndex: 1 };
    const xorResult = await executeOperation(registry, { operationId: "crypto.nonce-reuse.xor", inputs: { records: input }, params });
    expect(xorResult.run.error).toBeUndefined();
    expect(hex(await readAll((xorResult.outputs.xor as { source: Parameters<typeof readAll>[0] }).source))).toBe("050705");
    const cribResult = await executeOperation(registry, { operationId: "crypto.nonce-reuse.crib", inputs: { records: input }, params });
    expect(cribResult.run.error).toBeUndefined();
    expect(hex(await readAll((cribResult.outputs.candidate as { source: Parameters<typeof readAll>[0] }).source))).toBe("6667");
    expect((cribResult.outputs.report as { data: object }).data).toMatchObject({ offset: 1, candidateBytes: 2, verified: false });
  });

  it("parses quoted CSV fields and rejects malformed or duplicate columns", async () => {
    const csv = 'algorithm,keyId,nonce,ciphertext,knownPlaintextOffset,knownPlaintextHex\nAES-CTR,"fixture,key",00000000000000000000000000000000,0102,0,6162\nAES-CTR,"fixture,key",00000000000000000000000000000000,0304,,\n';
    const records = await parseNonceCsv(csv);
    expect(records).toHaveLength(2);
    expect(records[0]).toMatchObject({ keyId: "fixture,key", knownPlaintext: { offset: 0 } });
    expect(analyzeNonceReuse(records)).toMatchObject([{ risk: "confirmed", xorPreview: "0206" }]);
    const registryResult = await executeOperation(createDefaultRegistry(), { operationId: "crypto.nonce-reuse.inspect", inputs: { records: textValue(csv) }, params: { format: "csv" } });
    expect(registryResult.run.error).toBeUndefined();
    expect((registryResult.outputs.report as { data: object }).data).toMatchObject({ groups: [{ indexes: [0, 1] }] });
    await expect(parseNonceCsv(csv.replace(",keyId,", ",keyId,keyId,"))).rejects.toThrow(/malformed|unsupported or duplicate/);
    await expect(parseNonceCsv(csv.replace(",0,6162", ",,6162"))).rejects.toThrow(/both crib offset and hex/);
  });
});