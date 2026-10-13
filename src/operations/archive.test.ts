import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { readFileSync } from "node:fs";
import { readZip, writeZip, zipEntryData } from "../core/archive/zip";
import type { Finding } from "../core/analysis/finding";
import { readAll } from "../core/bytes/sources";
import { crc32, crc32FourBytePreimage } from "../core/checksum/crc32";
import { Sha256 } from "../core/hash/sha256";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom, textValue } from "../core/value";
import type { ZipForensicReport } from "../formats/zip";
import { buildPolyglotZip } from "../formats/zipPolyglot";
import { inspectZipEndChain } from "../formats/zipEndChain";
import { extractRar4Stored, extractRar5Stored } from "../formats/rar7z";
import { MemorySource } from "../core/bytes/sources";
import { encryptZipCryptoForTest, testZipCryptoPassword } from "../formats/zipCrypto";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();

async function inspect(bytes: Uint8Array<ArrayBuffer>): Promise<ZipForensicReport> {
  const result = await executeOperation(registry, { operationId: "archive.zip.inspect", inputs: { data: bytesFrom(bytes) }, params: {} });
  expect(result.run.error).toBeUndefined();
  return (result.outputs.report as { data: ZipForensicReport }).data;
}

async function exportHash(bytes: Uint8Array<ArrayBuffer>, entryIndex = 0): Promise<{ hash: string; diagnostics: string[] }> {
  const result = await executeOperation(registry, { operationId: "archive.zip.hash-export", inputs: { data: bytesFrom(bytes) }, params: { entryIndex } });
  if (result.run.error) throw new Error(result.run.error.message);
  return { hash: (result.outputs.hash as { text: string }).text, diagnostics: result.run.diagnostics };
}

const rules = (findings: Finding[]) => findings.map((finding) => finding.ruleId);

describe("ZIP archive recovery", () => {
  it("recovers the original 2022 AppNote flag from CRC-valid EOF-anchored ZIP records", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("../formats/testing/google-ctf-2022-appnote.zip", import.meta.url)));
    expect(createHash("sha256").update(bytes).digest("hex")).toBe("d6f941e8633906b8e6299ee5756ad4579c55078ac34a1ab55651c8794cf0b902");
    const report = inspectZipEndChain(bytes);
    expect(report.records).toHaveLength(21);
    expect(report.records.filter((record) => record.name.startsWith("flag"))).toHaveLength(19);
    expect(report.records[0]).toMatchObject({ name: "hi.txt", eocdOffset: 61_132 });
    expect(report.records.at(-1)).toMatchObject({ name: "hello.txt", eocdOffset: 61_572 });
    expect(report.contiguous).toBe(true);
    expect(report.candidateText).toBe("CTF{p0s7m0d3rn_z1p}");
    const result = await executeOperation(registry, { operationId: "archive.zip.eocd-chain",
      inputs: { data: bytesFrom(bytes) }, params: { prefix: "flag" } });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { candidateText: "CTF{p0s7m0d3rn_z1p}", candidateBytes: 19, verified: false } });
    if (result.outputs.candidate?.type !== "bytes") throw new Error("Expected CRC-verified ZIP candidate bytes");
    expect(new TextDecoder().decode(await readAll(result.outputs.candidate.source))).toBe("CTF{p0s7m0d3rn_z1p}");
    const tampered = bytes.slice();
    tampered[report.records.find((record) => record.name === "flag00")!.dataOffset] ^= 1;
    const incomplete = inspectZipEndChain(tampered);
    expect(incomplete.contiguous).toBe(false);
    expect(incomplete.candidate).toBeNull();
    const rejected = await executeOperation(registry, { operationId: "archive.zip.eocd-chain",
      inputs: { data: bytesFrom(tampered) }, params: { prefix: "flag" } });
    expect(rejected.run.error?.code).toBe("INVALID_INPUT");
    const appended = new Uint8Array(bytes.length + 1);
    appended.set(bytes);
    expect(() => inspectZipEndChain(appended)).toThrow(/No EOF-anchored/);
    const oversized = await executeOperation(registry, { operationId: "archive.zip.eocd-chain",
      inputs: { data: bytesFrom(new Uint8Array(1024 * 1024 + 1)) }, params: { prefix: "flag" } });
    expect(oversized.run.error?.code).toBe("INPUT_TOO_LARGE");
  });

  it("extracts both original 2018 Polyglot input sets with verified payload hashes", async () => {
    const fixtures = [
      { name: "first", digest: "ab2905a5bc5253f6c43c255b0510e887c8f3c318e25b7e2aa1f007927f10f40e",
        entries: [
          ["header.txt", "c67d29fea817ed3ffba0ae99275a18d6cb058dbabfabcebcb1f4c904033ac536"],
          ["pao_de_queijo.txt", "6e6463d212a22ecdd1b539c1a3be62e8cea40f951521766db9e6b1f005a5c51d"],
          ["picanha.txt", "c72ad7261e8c32a5aee49af0721e94486a7bf04051a980cad790bb857c2aeb36"],
        ] },
      { name: "second", digest: "f74f5d732678a488f9e8110f44eea4e7da0dbb4a0057758baf4a338b0daa2481",
        entries: [
          ["arepa.txt", "6dbb8dd2f8221cbaa9d023c893b7f1b6a603afc1d9cd740872bccaa7a6922f92"],
          ["cachapa.txt", "41860cc6ac5244df28842e834a8c9b55aba88534a5533284688b73404f747db7"],
          ["header.txt", "c67d29fea817ed3ffba0ae99275a18d6cb058dbabfabcebcb1f4c904033ac536"],
        ] },
    ];
    for (const fixture of fixtures) {
      const bytes = new Uint8Array(readFileSync(new URL(`../formats/testing/google-ctf-2018-polyglot-${fixture.name}.zip`, import.meta.url)));
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(fixture.digest);
      const report = await inspect(bytes);
      expect(report.entries.map((entry) => entry.name)).toEqual(fixture.entries.map(([name]) => name));
      for (const [entryIndex, [name, digest]] of fixture.entries.entries()) {
        const result = await executeOperation(registry, { operationId: "archive.zip.extract-plain",
          inputs: { data: bytesFrom(bytes) }, params: { entryIndex, maxOutputBytes: 65_536 } });
        expect(result.run.status).toBe("success");
        expect(result.outputs.report).toMatchObject({ type: "structured", data: { name, verified: true } });
        if (result.outputs.data?.type !== "bytes") throw new Error("Expected extracted ZIP entry bytes");
        expect(createHash("sha256").update(await readAll(result.outputs.data.source)).digest("hex")).toBe(digest);
      }
    }
  });

  it("rebuilds the original Polyglot challenge reference from both licensed input ZIPs", () => {
    const first = new Uint8Array(readFileSync(new URL("../formats/testing/google-ctf-2018-polyglot-first.zip", import.meta.url)));
    const second = new Uint8Array(readFileSync(new URL("../formats/testing/google-ctf-2018-polyglot-second.zip", import.meta.url)));
    const output = buildPolyglotZip(first, second);
    expect(output).toHaveLength(131_881);
    expect(createHash("sha256").update(output).digest("hex")).toBe("4f5ba114e256b371bf3d0ed252d12f7151365bccdfac9f80ca0df2b7a388ebb9");
    const altered = first.slice();
    altered[68] ^= 1;
    expect(() => buildPolyglotZip(altered, second)).toThrow(/CRC/);
    expect(() => buildPolyglotZip(first.subarray(0, first.length - 1), second)).toThrow(/end record/);
    expect(() => buildPolyglotZip(second, first)).toThrow(/share identical/);
  });

  it("exports the identical Polyglot ZIP from a CRC-checked two-archive wrapper", async () => {
    const input = new Uint8Array(readFileSync(new URL("../formats/testing/google-ctf-2018-polyglot-pair.zip", import.meta.url)));
    expect(createHash("sha256").update(input).digest("hex")).toBe("66ddda229b3b8eef0b6425b2aef9e82b0ddd5a158bdf3b0358d4e516dc97e4b4");
    const result = await executeOperation(registry, { operationId: "archive.zip.polyglot-compose",
      inputs: { data: bytesFrom(input) }, params: {} });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: {
      bytes: 131_881, independentExtractorValidationRequired: true, flagRecovered: false } });
    if (result.outputs.archive?.type !== "bytes") throw new Error("Expected constructed ZIP bytes");
    expect(createHash("sha256").update(await readAll(result.outputs.archive.source)).digest("hex"))
      .toBe("4f5ba114e256b371bf3d0ed252d12f7151365bccdfac9f80ca0df2b7a388ebb9");
  });

  it("refuses encrypted entries and an unencrypted entry over the selected output budget", async () => {
    const encrypted = new Uint8Array(readFileSync(new URL("../formats/testing/google-ctf-2023-ziphard.zip", import.meta.url)));
    const rejected = await executeOperation(registry, { operationId: "archive.zip.extract-plain",
      inputs: { data: bytesFrom(encrypted) }, params: { entryIndex: 0, maxOutputBytes: 65_536 } });
    expect(rejected.run.error?.code).toBe("INVALID_INPUT");
    expect(rejected.outputs.data).toBeUndefined();
    const plain = new Uint8Array(readFileSync(new URL("../formats/testing/google-ctf-2018-polyglot-first.zip", import.meta.url)));
    const limited = await executeOperation(registry, { operationId: "archive.zip.extract-plain",
      inputs: { data: bytesFrom(plain) }, params: { entryIndex: 1, maxOutputBytes: 1 } });
    expect(limited.run.error?.code).toBe("INPUT_TOO_LARGE");
  });

  it("rejects plaintext extending beyond a stored ZipCrypto entry before loading bkcrack", async () => {
    const archive = new Uint8Array(readFileSync(new URL("../formats/testing/offline-pack.zip", import.meta.url)));
    const result = await executeOperation(registry, { operationId: "archive.zip.known-plaintext",
      inputs: { data: bytesFrom(archive) }, params: { entryIndex: 0, knownPlaintext: "offline-known-plaintext-fixture\n", encoding: "utf8",
        plaintextOffset: 0, maxCandidates: 1, maxEncryptedBytes: 1024 } });
    expect(result.run.error).toMatchObject({ code: "INVALID_PARAMS", message: expect.stringMatching(/extends past the 31-byte compressed stream/) });
  });

  it("extracts the original Google CTF 2023 flag with independently published internal keys", async () => {
    const archive = new Uint8Array(readFileSync(new URL("../formats/testing/google-ctf-2023-ziphard.zip", import.meta.url)));
    const keys = "7796d1ea 96defd9f d7043705";
    const result = await executeOperation(registry, { operationId: "archive.zip.extract-keys",
      inputs: { data: bytesFrom(archive) }, params: { entryIndex: 1, keys, maxEncryptedBytes: 1_024, maxOutputBytes: 1_024 } });
    expect(result.run.error).toBeUndefined();
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { name: "flag.txt", bytes: 50, verified: true, keySource: "supplied" } });
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected CRC-verified flag.txt bytes");
    const plain = await readAll(result.outputs.data.source);
    expect([...plain.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
    expect(new TextDecoder("utf-8", { ignoreBOM: false }).decode(plain)).toBe("CTF{y0u_u5ed_3xtr@_pl@1nt3xt_t0_d3t3rm1n3_k3ys}");
    const wrong = await executeOperation(registry, { operationId: "archive.zip.extract-keys",
      inputs: { data: bytesFrom(archive) }, params: { entryIndex: 1, keys: "7796d1ea 96defd9f d7043704", maxEncryptedBytes: 1_024, maxOutputBytes: 1_024 } });
    expect(wrong.run.error?.code).toBe("INVALID_INPUT");
  });

  it("recovers the published Google CTF 2023 junk.dat bytes from the original encrypted ZIP", async () => {
    const archive = new Uint8Array(readFileSync(new URL("../formats/testing/google-ctf-2023-ziphard.zip", import.meta.url)));
    const report = await inspect(archive);
    expect(report.entries[0]).toMatchObject({ name: "junk.dat", encryption: "ZipCrypto", crc32: "0x3b3953bc",
      compressedSize: 16, uncompressedSize: 4, dataOffset: 38, consistent: true });
    expect(report.entries[1]).toMatchObject({ name: "flag.txt", encryption: "ZipCrypto", crc32: "0x4712d99a",
      compressedSize: 62, uncompressedSize: 50, consistent: true });
    const recovered = await executeOperation(registry, { operationId: "archive.zip.crc32-preimage4",
      inputs: { data: bytesFrom(archive) }, params: { entryIndex: 0 } });
    expect(recovered.run.error).toBeUndefined();
    expect(recovered.outputs.report).toMatchObject({ type: "structured", data: {
      name: "junk.dat", crc32: "0x3b3953bc", length: 4, encryption: "ZipCrypto",
    } });
    if (recovered.outputs.data?.type !== "bytes") throw new Error("Expected recovered ZIP entry bytes");
    expect(await readAll(recovered.outputs.data.source)).toEqual(Uint8Array.of(0xe2, 0xf2, 0xba, 0x77));
    const unsupported = await executeOperation(registry, { operationId: "archive.zip.crc32-preimage4",
      inputs: { data: bytesFrom(archive) }, params: { entryIndex: 1 } });
    expect(unsupported.run.error?.code).toBe("UNAVAILABLE");
  });

  it("inverts CRC-32 for arbitrary four-byte values without brute force", () => {
    for (const bytes of [Uint8Array.of(0, 0, 0, 0), Uint8Array.of(0xff, 0x04, 0xa7, 0x80), Uint8Array.of(0, 0, 0, 1)]) {
      expect(crc32FourBytePreimage(crc32(bytes))).toEqual(bytes);
    }
    fc.assert(fc.property(fc.uint8Array({ minLength: 4, maxLength: 4 }), (bytes) => {
      expect(crc32FourBytePreimage(crc32(bytes))).toEqual(bytes);
    }), { seed: 20261012, numRuns: 256 });
    expect(() => crc32FourBytePreimage(-1)).toThrow(/unsigned 32-bit/);
  });
  it("restores an inline PKZIP2 encrypted entry and verifies its password", async () => {
    const plaintext = new TextEncoder().encode("local ZIP hash fixture");
    const crc = crc32(plaintext);
    const modifiedTime = 0x3718;
    const encrypted = encryptZipCryptoForTest(plaintext, new TextEncoder().encode("fixturepass"), modifiedTime >>> 8);
    const length = encrypted.length.toString(16);
    const crcHex = crc.toString(16).padStart(8, "0");
    const hash = `sample:$pkzip2$1*2*2*0*${length}*${plaintext.length.toString(16)}*${crcHex}*0*0*0*${length}*${crcHex.slice(0, 4)}*${modifiedTime.toString(16)}*${[...encrypted].map((byte) => byte.toString(16).padStart(2, "0")).join("")}*$/pkzip2$:plain.txt`;
    const result = await executeOperation(registry, { operationId: "archive.zip.hash-restore",
      inputs: { text: textValue(hash) }, params: { entryName: "plain.txt" } });
    expect(result.run.error).toBeUndefined();
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { entryName: "plain.txt", encryptedBytes: encrypted.length, uncompressedBytes: plaintext.length } });
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected restored archive bytes");
    const archive = await readAll(result.outputs.data.source);
    expect((await inspect(archive)).entries[0]).toMatchObject({ name: "plain.txt", encryption: "ZipCrypto", compressedSize: encrypted.length, uncompressedSize: plaintext.length, consistent: true });
    const password = await executeOperation(registry, { operationId: "archive.zip.password-test", inputs: { data: bytesFrom(archive) },
      params: { entryIndex: 0, source: "dictionary", candidates: "fixturepass", mask: "", customCharset: "", maxAttempts: 1, maxEncryptedBytes: 1024, maxOutputBytes: 1024 } });
    expect(password.outputs.report).toMatchObject({ type: "structured", data: { matches: [{ password: "fixturepass", status: "verified" }] } });
    const extracted = await executeOperation(registry, { operationId: "archive.zip.extract", inputs: { data: bytesFrom(archive) },
      params: { entryIndex: 0, password: "fixturepass", maxEncryptedBytes: 1024, maxOutputBytes: 1024 } });
    expect(extracted.run.error).toBeUndefined();
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected extracted plaintext bytes");
    expect(await readAll(extracted.outputs.data.source)).toEqual(plaintext);
    const wrong = await executeOperation(registry, { operationId: "archive.zip.extract", inputs: { data: bytesFrom(archive) },
      params: { entryIndex: 0, password: "wrong", maxEncryptedBytes: 1024, maxOutputBytes: 1024 } });
    expect(wrong.run.error?.code).toBe("INVALID_INPUT");
    const malformed = await executeOperation(registry, { operationId: "archive.zip.hash-restore",
      inputs: { text: textValue(hash.replace(`*${length}*${plaintext.length.toString(16)}*`, `*${length}junk*${plaintext.length.toString(16)}*`)) }, params: { entryName: "plain.txt" } });
    expect(malformed.run.error).toMatchObject({ code: "UNAVAILABLE" });
  });

  it("restores a native zip2john deflated entry whose CRC has leading zeros", async () => {
    const native = "$pkzip2$1*2*2*0*18*203*cc01e3*0*48*8*18*00cc*4cb0*9fe32434d088b64cd9d8213b7a91f44922f961cb0eefd25b*$/pkzip2$";
    const restored = await executeOperation(registry, { operationId: "archive.zip.hash-restore",
      inputs: { text: textValue(native) }, params: { entryName: "repetitive.txt" } });
    expect(restored.run.error).toBeUndefined();
    if (restored.outputs.data?.type !== "bytes") throw new Error("Expected restored deflated ZIP bytes");
    const archive = await readAll(restored.outputs.data.source);
    expect((await inspect(archive)).entries[0]).toMatchObject({ methodName: "deflate", crc32: "0x00cc01e3", compressedSize: 24, uncompressedSize: 515, consistent: true });
    const password = await executeOperation(registry, { operationId: "archive.zip.password-test", inputs: { data: bytesFrom(archive) },
      params: { entryIndex: 0, source: "dictionary", candidates: "fixturepass", mask: "", customCharset: "", maxAttempts: 1, maxEncryptedBytes: 1024, maxOutputBytes: 1024 } });
    expect(password.outputs.report).toMatchObject({ type: "structured", data: { matches: [{ password: "fixturepass", status: "verified" }] } });
    const extracted = await executeOperation(registry, { operationId: "archive.zip.extract", inputs: { data: bytesFrom(archive) },
      params: { entryIndex: 0, password: "fixturepass", maxEncryptedBytes: 1024, maxOutputBytes: 1024 } });
    expect(extracted.run.error).toBeUndefined();
    if (extracted.outputs.data?.type !== "bytes") throw new Error("Expected extracted deflated plaintext bytes");
    expect(new TextDecoder().decode(await readAll(extracted.outputs.data.source))).toBe(Array(4).fill("A".repeat(128)).join("\n"));
  });
  it("inventories a consistent archive without findings", async () => {
    const bytes = new Uint8Array(await (await writeZip([
      { name: "flag.txt", data: new Blob(["flag{zip}"]) },
      { name: "folder/note.txt", data: new Blob(["note"]) },
    ])).arrayBuffer());
    const report = await inspect(bytes);
    expect(report.entries).toMatchObject([
      { name: "flag.txt", methodName: "stored", encryption: "none", consistent: true, compressedSize: 9 },
      { name: "folder/note.txt", methodName: "stored", encryption: "none", consistent: true, compressedSize: 4 },
    ]);
    expect(report.eocd).toMatchObject({ entriesTotal: 2 });
    expect(report.findings).toEqual([]);
  });

  it("keeps parsing while reporting a local/central mismatch and trailing payload", async () => {
    const original = new Uint8Array(await (await writeZip([{ name: "flag.txt", data: new Blob(["secret"]) }])).arrayBuffer());
    const eocd = original.length - 22;
    const centralOffset = new DataView(original.buffer).getUint32(eocd + 16, true);
    const damaged = new Uint8Array(original.length + 4);
    damaged.set(original);
    damaged.set([0xde, 0xad, 0xbe, 0xef], original.length);
    new DataView(damaged.buffer).setUint16(centralOffset + 10, 8, true);

    const report = await inspect(damaged);
    expect(report.entries[0]).toMatchObject({ name: "flag.txt", method: 8, consistent: false, issues: ["method: central 8, local 0"] });
    expect(rules(report.findings)).toEqual(expect.arrayContaining(["zip.local-central-consistency", "zip.extent"]));
    expect(report.findings.find((finding) => finding.ruleId === "zip.extent")).toMatchObject({
      span: { offset: original.length, length: 4 },
      suggestion: { operationId: "bytes.slice", params: { offset: original.length, length: -1 } },
    });
  });

  it("identifies ZipCrypto flags and duplicate names", async () => {
    const bytes = new Uint8Array(await (await writeZip([
      { name: "same.txt", data: new Blob(["one"]) },
      { name: "same.txt", data: new Blob(["two"]) },
    ])).arrayBuffer());
    const eocd = bytes.length - 22;
    const centralOffset = new DataView(bytes.buffer).getUint32(eocd + 16, true);
    new DataView(bytes.buffer).setUint16(6, 0x0801, true);
    new DataView(bytes.buffer).setUint16(centralOffset + 8, 0x0801, true);

    const report = await inspect(bytes);
    expect(report.entries[0].encryption).toBe("ZipCrypto");
    expect(rules(report.findings)).toEqual(expect.arrayContaining(["zip.encryption", "zip.duplicate-name"]));
  });

  it("discovers local records and rebuilds a missing central directory", async () => {
    const original = new Uint8Array(await (await writeZip([
      { name: "one.txt", data: new Blob(["one"]) },
      { name: "two.txt", data: new Blob(["second"]) },
    ])).arrayBuffer());
    const eocd = original.length - 22;
    const centralOffset = new DataView(original.buffer).getUint32(eocd + 16, true);
    const damaged = original.slice(0, centralOffset);

    const report = await inspect(damaged);
    expect(report.eocd).toBeNull();
    expect(report.localRecords).toMatchObject([{ name: "one.txt" }, { name: "two.txt" }]);
    expect(report.findings[0].suggestion).toMatchObject({ operationId: "archive.zip.rebuild" });

    const result = await executeOperation(registry, { operationId: "archive.zip.rebuild", inputs: { data: bytesFrom(damaged) }, params: {} });
    expect(result.run.error).toBeUndefined();
    expect(result.run.diagnostics).toEqual(["Recovered 2 local record(s) into a new ZIP central directory."]);
    const rebuilt = await readAll((result.outputs.data as Extract<typeof result.outputs.data, { type: "bytes" }>).source);
    const entries = await readZip(new Blob([rebuilt]));
    expect(entries.map((entry) => entry.name)).toEqual(["one.txt", "two.txt"]);
    expect(await (await zipEntryData(entries[1], 1024)).text()).toBe("second");
  });

  it("tests a bounded dictionary and fully verifies a traditional ZipCrypto entry", async () => {
    const plainZip = new Uint8Array(await (await writeZip([{ name: "flag.txt", data: new Blob(["flag{password}"]) }])).arrayBuffer());
    const plainSize = 14;
    const localNameLength = new DataView(plainZip.buffer).getUint16(26, true);
    const dataOffset = 30 + localNameLength;
    const eocdOffset = plainZip.length - 22;
    const centralOffset = new DataView(plainZip.buffer).getUint32(eocdOffset + 16, true);
    const crc = new DataView(plainZip.buffer).getUint32(14, true);
    const encrypted = encryptZipCryptoForTest(plainZip.slice(dataOffset, dataOffset + plainSize), new TextEncoder().encode("hunter2"), crc >>> 24);
    expect(await testZipCryptoPassword(encrypted, new TextEncoder().encode("hunter2"), {
      checkByte: crc >>> 24, method: 0, crc32: crc, uncompressedSize: plainSize, maxOutputBytes: 1024, exposePlaintext: true,
    })).toMatchObject({ status: "verified", plaintext: plainZip.slice(dataOffset, dataOffset + plainSize) });
    const archive = new Uint8Array(plainZip.length + 12);
    archive.set(plainZip.slice(0, dataOffset), 0);
    archive.set(encrypted, dataOffset);
    archive.set(plainZip.slice(dataOffset + plainSize), dataOffset + encrypted.length);
    const data = new DataView(archive.buffer);
    data.setUint16(6, 0x0801, true);
    data.setUint32(18, encrypted.length, true);
    const shiftedCentral = centralOffset + 12;
    data.setUint16(shiftedCentral + 8, 0x0801, true);
    data.setUint32(shiftedCentral + 20, encrypted.length, true);
    data.setUint32(eocdOffset + 12 + 16, shiftedCentral, true);

    const result = await executeOperation(registry, {
      operationId: "archive.zip.password-test",
      inputs: { data: bytesFrom(archive) },
      params: { entryIndex: 0, source: "dictionary", candidates: "wrong\nhunter2\nalso-wrong", mask: "", customCharset: "", maxAttempts: 2, maxEncryptedBytes: 1024, maxOutputBytes: 1024 },
    });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.report as { data: unknown }).data).toMatchObject({
      name: "flag.txt",
      source: "dictionary",
      attempted: 2,
      truncated: true,
      matches: [{ password: "hunter2", status: "verified" }],
    });

    const exported = await exportHash(archive);
    const checksum = (crc >>> 16).toString(16).padStart(4, "0");
    expect(exported.hash).toBe(`$pkzip$1*1*2*0*1a*e*${crc.toString(16).padStart(8, "0")}*0*26*0*1a*${checksum}*${[...encrypted].map((byte) => byte.toString(16).padStart(2, "0")).join("")}*$/pkzip$`);
    expect(exported.diagnostics).toEqual(["Exported flag.txt for Hashcat mode 17210 and John the Ripper."]);

    const maskResult = await executeOperation(registry, {
      operationId: "archive.zip.password-test",
      inputs: { data: bytesFrom(archive) },
      params: { entryIndex: 0, source: "mask", candidates: "", mask: "hunter?d", customCharset: "", maxAttempts: 3, maxEncryptedBytes: 1024, maxOutputBytes: 1024 },
    });
    expect(maskResult.run.error).toBeUndefined();
    expect((maskResult.outputs.report as { data: unknown }).data).toMatchObject({
      source: "mask",
      attempted: 3,
      truncated: true,
      matches: [{ password: "hunter2", status: "verified" }],
    });
  });

  it("parses WinZip AES metadata and exports the canonical $zip2$ fields", async () => {
    const name = new TextEncoder().encode("aes.txt");
    const salt = Uint8Array.from({ length: 8 }, (_, index) => index + 1);
    const verifier = Uint8Array.of(0xaa, 0xbb);
    const cipher = Uint8Array.of(0x10, 0x20, 0x30, 0x40);
    const auth = Uint8Array.from({ length: 10 }, (_, index) => 0xf0 + index);
    const payload = Uint8Array.from([...salt, ...verifier, ...cipher, ...auth]);
    const aesExtra = Uint8Array.of(0x01, 0x99, 0x07, 0x00, 0x02, 0x00, 0x41, 0x45, 0x01, 0x08, 0x00);
    const localLength = 30 + name.length + aesExtra.length;
    const centralOffset = localLength + payload.length;
    const archive = new Uint8Array(centralOffset + 46 + name.length + aesExtra.length + 22);
    const data = new DataView(archive.buffer);
    data.setUint32(0, 0x04034b50, true);
    data.setUint16(4, 51, true);
    data.setUint16(6, 1, true);
    data.setUint16(8, 99, true);
    data.setUint32(18, payload.length, true);
    data.setUint32(22, 4, true);
    data.setUint16(26, name.length, true);
    data.setUint16(28, aesExtra.length, true);
    archive.set(name, 30);
    archive.set(aesExtra, 30 + name.length);
    archive.set(payload, localLength);
    data.setUint32(centralOffset, 0x02014b50, true);
    data.setUint16(centralOffset + 4, 51, true);
    data.setUint16(centralOffset + 6, 51, true);
    data.setUint16(centralOffset + 8, 1, true);
    data.setUint16(centralOffset + 10, 99, true);
    data.setUint32(centralOffset + 20, payload.length, true);
    data.setUint32(centralOffset + 24, 4, true);
    data.setUint16(centralOffset + 28, name.length, true);
    data.setUint16(centralOffset + 30, aesExtra.length, true);
    archive.set(name, centralOffset + 46);
    archive.set(aesExtra, centralOffset + 46 + name.length);
    const eocd = centralOffset + 46 + name.length + aesExtra.length;
    data.setUint32(eocd, 0x06054b50, true);
    data.setUint16(eocd + 8, 1, true);
    data.setUint16(eocd + 10, 1, true);
    data.setUint32(eocd + 12, eocd - centralOffset, true);
    data.setUint32(eocd + 16, centralOffset, true);

    const report = await inspect(archive);
    expect(report.entries[0]).toMatchObject({ encryption: "AES", aes: { vendorVersion: 2, vendorId: "AE", strength: 1, keyBits: 128, actualMethod: 8, saltLength: 8 } });
    const exported = await exportHash(archive);
    expect(exported.hash).toBe("$zip2$*0*1*0*0102030405060708*aabb*4*10203040*f0f1f2f3f4f5f6f7f8f9*$/zip2$");
    expect(exported.diagnostics).toEqual(["Exported aes.txt (WinZip AES-128) for Hashcat mode 13600 and John the Ripper."]);

    const recovery = await executeOperation(registry, {
      operationId: "archive.zip.known-plaintext",
      inputs: { data: bytesFrom(archive) },
      params: { entryIndex: 0, knownPlaintext: "000000000000000000000000", encoding: "hex", plaintextOffset: 0, maxCandidates: 1, maxEncryptedBytes: 1024 },
    });
    expect(recovery.run.error).toMatchObject({ code: "INVALID_INPUT", message: "aes.txt uses AES encryption, which is not vulnerable to this attack" });
  });
});

describe("RAR and 7z inspection", () => {
  const inspectArchive = async (archive: Uint8Array<ArrayBuffer>): Promise<Record<string, unknown>> => {
    const result = await executeOperation(registry, { operationId: "archive.rar7z.inspect", inputs: { data: bytesFrom(archive) }, params: {} });
    if (result.run.error) throw new Error(result.run.error.message);
    return (result.outputs.report as { data: Record<string, unknown> }).data;
  };

  it("walks RAR4 blocks and identifies encrypted file data", async () => {
    const sealHeader = (header: Uint8Array<ArrayBuffer>): void => new DataView(header.buffer).setUint16(0, crc32(header.subarray(2)) & 0xffff, true);
    const signature = Uint8Array.of(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x00);
    const main = new Uint8Array(7);
    main[2] = 0x73;
    new DataView(main.buffer).setUint16(5, main.length, true);
    sealHeader(main);
    const name = new TextEncoder().encode("secret.txt");
    const file = new Uint8Array(32 + name.length);
    const fileView = new DataView(file.buffer);
    file[2] = 0x74;
    fileView.setUint16(3, 0x8004, true);
    fileView.setUint16(5, file.length, true);
    fileView.setUint32(7, 3, true);
    fileView.setUint32(11, 3, true);
    fileView.setUint16(26, name.length, true);
    file.set(name, 32);
    sealHeader(file);
    const end = new Uint8Array(7);
    end[2] = 0x7b;
    new DataView(end.buffer).setUint16(5, end.length, true);
    sealHeader(end);
    const archive = Uint8Array.from([...signature, ...main, ...file, 1, 2, 3, ...end]);

    await expect(inspectArchive(archive)).resolves.toMatchObject({
      format: "RAR4",
      encryption: "file-data",
      headers: 3,
      entries: [{ name: "secret.txt", packedSize: 3, encrypted: true }],
      issues: [],
    });
  });

  it("inspects the independently published libarchive RAR4 stored-file fixture", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("../formats/testing/libarchive-rar4-store.rar", import.meta.url)));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("a0e135fcf1d896265481f60ecef58776775ff300");
    const report = await inspectArchive(bytes);
    expect(report).toMatchObject({ format: "RAR4", encryption: "none", issues: [], entries: [
      { name: "test.txt", packedSize: 20, encrypted: false },
      { name: "testlink", packedSize: 8, encrypted: false },
      { name: "testdir\\test.txt", packedSize: 20, encrypted: false },
      { name: "testdir", packedSize: 0, encrypted: false },
      { name: "testemptydir", packedSize: 0, encrypted: false },
    ] });
    for (const index of [0, 2]) {
      const selected = await readAll(await extractRar4Stored(new MemorySource(bytes), index));
      expect(new TextDecoder().decode(selected)).toBe("test text document\r\n");
    }
    const operation = await executeOperation(registry, { operationId: "archive.rar4.stored-extract",
      inputs: { data: bytesFrom(bytes) }, params: { entryIndex: 2 } });
    expect(operation.run.status).toBe("success");
    if (operation.outputs.data?.type !== "bytes") throw new Error("Missing RAR4 member bytes");
    expect(new TextDecoder().decode(await readAll(operation.outputs.data.source))).toBe("test text document\r\n");
    await expect(extractRar4Stored(new MemorySource(bytes), 1)).rejects.toThrow(/regular file/);
    await expect(extractRar4Stored(new MemorySource(bytes), 3)).rejects.toThrow(/regular file/);
    const corrupt = bytes.slice(); corrupt[70] ^= 1;
    await expect(extractRar4Stored(new MemorySource(corrupt), 0)).rejects.toThrow(/CRC/);
    const unsupportedHeader = bytes.slice();
    // Clear the long-block bit but keep the file's claimed packed size; a valid header CRC must not make it extractable.
    const headerOffset = 20;
    const headerSize = new DataView(unsupportedHeader.buffer).getUint16(headerOffset + 5, true);
    new DataView(unsupportedHeader.buffer).setUint16(headerOffset + 3, 0x1020, true);
    new DataView(unsupportedHeader.buffer).setUint16(headerOffset, crc32(unsupportedHeader.subarray(headerOffset + 2, headerOffset + headerSize)) & 0xffff, true);
    await expect(extractRar4Stored(new MemorySource(unsupportedHeader), 0)).rejects.toThrow(/regular file/);
  });

  it("identifies the RAR5 archive-encryption header", async () => {
    const archive = Uint8Array.of(0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, 0, 0, 0, 0, 2, 4, 0);
    new DataView(archive.buffer).setUint32(8, crc32(archive.subarray(12)), true);
    await expect(inspectArchive(archive)).resolves.toMatchObject({ format: "RAR5", encryption: "headers", headers: 1, issues: [] });
  });

  it("extracts the original libarchive RAR5 stored member with CRC validation", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("../formats/testing/libarchive-rar5-store.rar", import.meta.url)));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("a9a34301f571216a294baa590b6b092309f46dc3");
    const expected = new TextEncoder().encode("hello libarchive test suite!\n");
    expect(await readAll(await extractRar5Stored(new MemorySource(bytes), 0))).toEqual(expected);
    expect(await inspectArchive(bytes)).toMatchObject({ format: "RAR5", encryption: "none", issues: [], limited: false, entries: [
      { name: "helloworld.txt", packedSize: 29, encrypted: false },
    ] });
    const flagged = bytes.slice();
    // Existing mtime extra: size=10, id=3. Reinterpret it as a crypt extra (id=1) with a valid header CRC.
    flagged[62] = 1;
    const fileAt = 23;
    const fileSize = flagged[fileAt + 4];
    new DataView(flagged.buffer).setUint32(fileAt, crc32(flagged.subarray(fileAt + 4, fileAt + 5 + fileSize)), true);
    expect(await inspectArchive(flagged)).toMatchObject({ format: "RAR5", encryption: "file-data", limited: true, entries: [{ encrypted: true }] });
    await expect(extractRar5Stored(new MemorySource(flagged), 0)).rejects.toThrow(/regular file/);
    const unsupportedExtra = bytes.slice(); unsupportedExtra[62] = 5; // RAR5 redirection extra, not a verified regular file
    new DataView(unsupportedExtra.buffer).setUint32(fileAt, crc32(unsupportedExtra.subarray(fileAt + 4, fileAt + 5 + fileSize)), true);
    await expect(extractRar5Stored(new MemorySource(unsupportedExtra), 0)).rejects.toThrow(/regular file/);
    const operation = await executeOperation(registry, { operationId: "archive.rar5.stored-extract",
      inputs: { data: bytesFrom(bytes) }, params: { entryIndex: 0 } });
    expect(operation.run.status).toBe("success");
    if (operation.outputs.data?.type !== "bytes") throw new Error("Missing selected RAR5 bytes");
    expect(await readAll(operation.outputs.data.source)).toEqual(expected);
    await expect(extractRar5Stored(new MemorySource(bytes), 1)).rejects.toThrow(/outside the archive/);
    const damaged = bytes.slice(); damaged[75] ^= 1;
    await expect(extractRar5Stored(new MemorySource(damaged), 0)).rejects.toThrow(/CRC/);
    const compressed = new Uint8Array(readFileSync(new URL("../formats/testing/libarchive-rar5-compressed.rar", import.meta.url)));
    expect(await inspectArchive(compressed)).toMatchObject({ limited: true, entries: [
      { name: "test1.bin", packedSize: 356 }, { name: "test2.bin", packedSize: 356 },
      { name: "test3.bin", packedSize: 368 }, { name: "test4.bin", packedSize: 368 },
    ] });
    await expect(extractRar5Stored(new MemorySource(compressed), 0)).rejects.toThrow(/regular file/);
  });

  it("selects all three libarchive RAR5 stored members without reading unrelated payloads", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("../formats/testing/libarchive-rar5-many-stored.rar", import.meta.url)));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("5de3ea99946bcb46a65f9a3d5639d23c4329b1bf");
    const report = await inspectArchive(bytes);
    expect(report.entries).toMatchObject([
      { name: "make_uue.tcl", packedSize: 405 }, { name: "cebula.txt", packedSize: 814 }, { name: "test.bin", packedSize: 1200 },
    ]);
    const referenceHashes = [
      "41f7ec23f892c8d4f18f72b01c8748572514475a902d818b92af048c3cb87422",
      "1e98540238b2b13d1a22f4f4fa8e2eb6c66e24d46115ffdfafd3f3f981b212e7",
      "588870a2dade35c2650fbb7898c9a9c7f21fce7c281198604e8d0c9737f2c375",
    ];
    for (const [index, entry] of (report.entries as { name: string; packedSize: number }[]).entries()) {
      const data = await readAll(await extractRar5Stored(new MemorySource(bytes), index));
      expect(data.length).toBe(entry.packedSize);
      expect(createHash("sha256").update(data).digest("hex")).toBe(referenceHashes[index]);
    }
  });

  it("exports a checksum-validated RAR5 encrypted header", async () => {
    const fromHex = (value: string): Uint8Array<ArrayBuffer> => Uint8Array.from(value.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
    const salt = fromHex("37526a0922b4adcc32f8fed5d51bb6c8");
    const iv = fromHex("8955617d9b801def51d734095bb8ecdb");
    const passwordCheck = fromHex("9f0b23c98ebb3653");
    const passwordCheckChecksum = new Sha256().update(passwordCheck).digest().slice(0, 4);
    const body = Uint8Array.from([4, 0, 0, 1, 15, ...salt, ...passwordCheck, ...passwordCheckChecksum]);
    const header = new Uint8Array(5 + body.length);
    header[4] = body.length;
    header.set(body, 5);
    new DataView(header.buffer).setUint32(0, crc32(header.subarray(4)), true);
    const archive = Uint8Array.from([0x52, 0x61, 0x72, 0x21, 0x1a, 0x07, 0x01, 0x00, ...header, ...iv, ...new Uint8Array(16)]);

    const result = await executeOperation(registry, { operationId: "archive.rar5.hash-export", inputs: { data: bytesFrom(archive) }, params: {} });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.hash as { text: string }).text).toBe("$rar5$16$37526a0922b4adcc32f8fed5d51bb6c8$15$8955617d9b801def51d734095bb8ecdb$8$9f0b23c98ebb3653");
    expect(result.run.diagnostics).toEqual(["Exported a RAR5 encrypted header for Hashcat mode 13000 and John the Ripper."]);

    const resealHeader = (bytes: Uint8Array<ArrayBuffer>): void => new DataView(bytes.buffer).setUint32(8, crc32(bytes.subarray(12, 8 + header.length)), true);
    const malformed: { name: string; bytes: Uint8Array<ArrayBuffer>; message: string }[] = [
      { name: "signature", bytes: Uint8Array.from([0, ...archive.subarray(1)]), message: "Input is not a RAR5 archive" },
      { name: "truncated prefix", bytes: archive.slice(0, 14), message: "RAR5 archive-encryption header is truncated" },
      { name: "truncated header", bytes: archive.slice(0, 8 + header.length - 1), message: "RAR5 archive-encryption header exceeds the archive bounds" },
      { name: "truncated IV", bytes: archive.slice(0, 8 + header.length + 15), message: "RAR5 encrypted-header IV is truncated" },
    ];
    for (const [name, offset, value, message] of [
      ["header type", 13, 1, "RAR5 archive does not begin with an archive-encryption header"],
      ["common flags", 14, 1, "RAR5 archive-encryption header uses unsupported common flags"],
      ["encryption version", 15, 1, "RAR5 archive uses an unsupported encryption version"],
      ["password-check flag", 16, 0, "RAR5 archive-encryption header has no supported password check"],
      ["KDF exponent zero", 17, 0, "RAR5 KDF iteration exponent is unsupported"],
      ["KDF exponent", 17, 25, "RAR5 KDF iteration exponent is unsupported"],
    ] as const) {
      const bytes = archive.slice();
      bytes[offset] = value;
      resealHeader(bytes);
      malformed.push({ name, bytes, message });
    }
    const trailingHeader = new Uint8Array(archive.length + 1);
    trailingHeader.set(archive.subarray(0, 8 + header.length));
    trailingHeader[12]++;
    trailingHeader.set(archive.subarray(8 + header.length), 8 + header.length + 1);
    new DataView(trailingHeader.buffer).setUint32(8, crc32(trailingHeader.subarray(12, 8 + header.length + 1)), true);
    malformed.push({ name: "trailing header data", bytes: trailingHeader, message: "RAR5 archive-encryption header has unsupported trailing data" });
    for (const fixture of malformed) {
      const rejected = await executeOperation(registry, { operationId: "archive.rar5.hash-export", inputs: { data: bytesFrom(fixture.bytes) }, params: {} });
      expect(rejected.run.error, fixture.name).toMatchObject({ code: "INVALID_INPUT", message: fixture.message });
    }

    const maximumKdf = archive.slice();
    maximumKdf[17] = 24;
    resealHeader(maximumKdf);
    const acceptedMaximum = await executeOperation(registry, { operationId: "archive.rar5.hash-export", inputs: { data: bytesFrom(maximumKdf) }, params: {} });
    expect(acceptedMaximum.run.error).toBeUndefined();
    expect((acceptedMaximum.outputs.hash as { text: string }).text).toContain("$24$");

    const invalidHeaderCrc = archive.slice();
    invalidHeaderCrc[13] ^= 0xff;
    const corruptHeader = await executeOperation(registry, { operationId: "archive.rar5.hash-export", inputs: { data: bytesFrom(invalidHeaderCrc) }, params: {} });
    expect(corruptHeader.run.error).toMatchObject({ code: "INVALID_INPUT", message: "RAR5 archive-encryption header CRC is invalid" });

    archive[archive.length - 16 - iv.length - 1] ^= 0xff;
    new DataView(archive.buffer).setUint32(8, crc32(archive.subarray(12, 8 + header.length)), true);
    const corrupted = await executeOperation(registry, { operationId: "archive.rar5.hash-export", inputs: { data: bytesFrom(archive) }, params: {} });
    expect(corrupted.run.error).toMatchObject({ code: "INVALID_INPUT", message: "RAR5 password-check checksum is invalid" });
  });

  it("validates 7z header CRCs and locates the AES coder", async () => {
    const next = Uint8Array.of(0x01, 0x06, 0xf1, 0x07, 0x01);
    const archive = new Uint8Array(32 + next.length);
    archive.set([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4]);
    const view = new DataView(archive.buffer);
    view.setBigUint64(12, 0n, true);
    view.setBigUint64(20, BigInt(next.length), true);
    view.setUint32(28, crc32(next), true);
    view.setUint32(8, crc32(archive.subarray(12, 32)), true);
    archive.set(next, 32);

    await expect(inspectArchive(archive)).resolves.toMatchObject({
      format: "7z",
      encryption: "AES-256",
      sevenZip: { version: "0.4", startHeaderCrcValid: true, nextHeaderCrcValid: true, nextHeaderOffset: 32, nextHeaderSize: 5, aesCoderOffset: 33 },
    });
  });

  it("inspects an independent 7-Zip 26 Copy-method archive and flags damaged header CRCs", async () => {
    const original = new Uint8Array(readFileSync(new URL("../formats/testing/7zip-26-copy.7z", import.meta.url)));
    const report = await inspectArchive(original);
    expect(report).toMatchObject({ format: "7z", encryption: "none", issues: [],
      sevenZip: { version: "0.4", startHeaderCrcValid: true, nextHeaderCrcValid: true } });
    const damaged = original.slice();
    damaged[8] ^= 1;
    expect(await inspectArchive(damaged)).toMatchObject({ format: "7z", issues: ["7z start-header CRC mismatch"],
      sevenZip: { startHeaderCrcValid: false } });
  });

  it("exports a bounded single-stream encrypted 7z header", async () => {
    const encrypted = Uint8Array.from({ length: 16 }, (_, index) => index);
    const iv = Uint8Array.from({ length: 16 }, (_, index) => 0x80 + index);
    const digest = 0x12345678;
    const next = Uint8Array.from([
      0x17,
      0x06, 0x00, 0x01, 0x09, encrypted.length, 0x0a, 0x01,
      crc32(encrypted) & 0xff, (crc32(encrypted) >>> 8) & 0xff, (crc32(encrypted) >>> 16) & 0xff, crc32(encrypted) >>> 24,
      0x00,
      0x07, 0x0b, 0x01, 0x00,
      0x01, 0x24, 0x06, 0xf1, 0x07, 0x01, 0x12, 0x53, 0x0f, ...iv,
      0x0c, 0x0e, 0x0a, 0x01,
      digest & 0xff, (digest >>> 8) & 0xff, (digest >>> 16) & 0xff, digest >>> 24,
      0x00, 0x00,
    ]);
    const archive = new Uint8Array(32 + encrypted.length + next.length);
    archive.set([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4]);
    archive.set(encrypted, 32);
    archive.set(next, 32 + encrypted.length);
    const view = new DataView(archive.buffer);
    view.setBigUint64(12, BigInt(encrypted.length), true);
    view.setBigUint64(20, BigInt(next.length), true);
    view.setUint32(28, crc32(next), true);
    view.setUint32(8, crc32(archive.subarray(12, 32)), true);

    const result = await executeOperation(registry, { operationId: "archive.sevenzip.hash-export", inputs: { data: bytesFrom(archive) }, params: {} });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.hash as { text: string }).text).toBe(`$7z$0$19$0$$16$${[...iv].map((byte) => byte.toString(16).padStart(2, "0")).join("")}$${digest}$16$14$000102030405060708090a0b0c0d0e0f`);
    expect(result.run.diagnostics).toEqual(["Exported an AES-256 encrypted 7z header for Hashcat mode 11600 and John the Ripper."]);

    archive[32] ^= 0xff;
    const corrupted = await executeOperation(registry, { operationId: "archive.sevenzip.hash-export", inputs: { data: bytesFrom(archive) }, params: {} });
    expect(corrupted.run.error).toMatchObject({ code: "INVALID_INPUT", message: "7z encrypted-header packed-stream CRC is invalid" });
  });

  it("uses the canonical zero-padded IV for implicit 7z AES properties", async () => {
    const encrypted = new Uint8Array(16);
    const next = Uint8Array.from([
      0x17, 0x06, 0x00, 0x01, 0x09, 0x10, 0x00,
      0x07, 0x0b, 0x01, 0x00, 0x01, 0x24, 0x06, 0xf1, 0x07, 0x01, 0x01, 0x13,
      0x0c, 0x0f, 0x0a, 0x01, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00,
    ]);
    const archive = new Uint8Array(32 + encrypted.length + next.length);
    archive.set([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4]);
    archive.set(encrypted, 32);
    archive.set(next, 48);
    const view = new DataView(archive.buffer);
    view.setBigUint64(12, 16n, true);
    view.setBigUint64(20, BigInt(next.length), true);
    view.setUint32(28, crc32(next), true);
    view.setUint32(8, crc32(archive.subarray(12, 32)), true);

    const result = await executeOperation(registry, { operationId: "archive.sevenzip.hash-export", inputs: { data: bytesFrom(archive) }, params: {} });
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.hash as { text: string }).text).toBe(`$7z$0$19$0$$16$${"00".repeat(16)}$305419896$16$15$${"00".repeat(16)}`);
  });

  it("matches a 7-Zip 26.04 encrypted-header golden vector", async () => {
    const archiveHex = "377abcaf271c0004475cb63fa0000000000000002f00000000000000ee1df7b3" +
      "0fd51cd1b65a71d0a146b1bf23bb2d9260b21ba2dab9172d37e2c0924477b433a84d93d05d872fef0cafa91fd4b76f03f6bd536f3edeb55b6b78962ec8b4023df5bb509dd39ed30c3f6c9349f5e4718648ed66740ebf517721150479b7c8dbb5f8b2540902fadd4e280115749a7b58c238a598790fcb03465a760db38d8223b91e41c62c7c09771904e0b26c8c4059f38d723eca9c7b5e619171a5bbe8f2d891" +
      "1706200109808000070b0100012406f1070112530fe7342585a66089c2a76710f87cd4f47b0c720a017925d9fc0000";
    const archive = Uint8Array.from(archiveHex.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
    const result = await executeOperation(registry, { operationId: "archive.sevenzip.hash-export", inputs: { data: bytesFrom(archive) }, params: {} });

    expect(result.run.error).toBeUndefined();
    expect((result.outputs.hash as { text: string }).text).toBe(
      "$7z$0$19$0$$16$e7342585a66089c2a76710f87cd4f47b$4242089337$128$114$" +
      "a84d93d05d872fef0cafa91fd4b76f03f6bd536f3edeb55b6b78962ec8b4023df5bb509dd39ed30c3f6c9349f5e4718648ed66740ebf517721150479b7c8dbb5f8b2540902fadd4e280115749a7b58c238a598790fcb03465a760db38d8223b91e41c62c7c09771904e0b26c8c4059f38d723eca9c7b5e619171a5bbe8f2d891",
    );
  });

  it("exports an encrypted header from a complete 7-Zip 26.04 archive", async () => {
    const archive = new Uint8Array(readFileSync(new URL("../formats/testing/7zip-26-encrypted-header.7z", import.meta.url)));
    expect(createHash("sha1").update(`blob ${archive.length}\0`).update(archive).digest("hex"))
      .toBe("d2435498e84b55d454baabc48787096daba0f537");
    const result = await executeOperation(registry, { operationId: "archive.sevenzip.hash-export",
      inputs: { data: bytesFrom(archive) }, params: {} });
    expect(result.run.status).toBe("success");
    const hash = (result.outputs.hash as { text: string }).text;
    expect(hash).toMatch(/^\$7z\$0\$19\$0\$\$16\$[0-9a-f]{32}\$\d+\$\d+\$\d+\$[0-9a-f]+$/);
    const report = await inspectArchive(archive);
    expect(report).toMatchObject({ format: "7z", encryption: "AES-256", issues: [],
      sevenZip: { startHeaderCrcValid: true, nextHeaderCrcValid: true } });
    const damaged = archive.slice();
    damaged[28] ^= 1;
    const rejected = await executeOperation(registry, { operationId: "archive.sevenzip.hash-export",
      inputs: { data: bytesFrom(damaged) }, params: {} });
    expect(rejected.run.error?.message).toMatch(/CRC/);
  });
});
