import { describe, expect, it } from "vitest";
import { Sha256 } from "../core/hash/sha256";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();
const encoder = new TextEncoder();
const AES_ID = "31c1f2e6bf714350be5805216afc5aff";
const ARGON2D = "ef636ddf8c29444b91f7a9a403e30a0c";
const ARGON2ID = "9e298b1956db4773b23dfc3ec6f0a1e6";
const REAL_HEADER_PREFIX = [
  "A9mimmf7S7UAAAQAAhAAAAAxwfLmv3FDUL5YBSFq/Fr/AwQAAAABAAAABCAAAAACREEDUWkb8tw3LLcy",
  "c61sP/4HPj9B4S1I6kXAlI6SYwcQAAAA+ZYacCggtqO/EPfaw+aO9guLAAAAAAFCBQAAACRVVUlEEAAA",
  "AO9jbd+MKURLkfeppAPjCgwFAQAAAEkIAAAADgAAAAAAAAAFAQAAAE0IAAAAAAAABAAAAAAEAQAAAFAE",
  "AAAAAgAAAEIBAAAAUyAAAACpLzEf0CNpSjeyot5QHhVpoq+BKb+84zw2xucR0CMbWAQBAAAAVgQAAAAT",
  "AAAAAAAEAAAADQoNChl3JQXVscBQUGtsV8dt69OW72fsrx4eTV+j4E2updhC465hpEb5yreD9cV57wnX",
  "p6z3RknRgIr/fkfd7oSukTE66y0ve0cRpuG6cufTaAkKh0FVTQToONgnYBHqYfXBgXADAAA=",
].join("");
const REAL_HASH = "$keepass$*4*14*ef636ddf*67108864*19*2*0244410351691bf2dc372cb73273ad6c3ffe073e3f41e12d48ea45c0948e9263*a92f311fd023694a37b2a2de501e1569a2af8129bfbce33c36c6e711d0231b58*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff03040000000100000004200000000244410351691bf2dc372cb73273ad6c3ffe073e3f41e12d48ea45c0948e92630710000000f9961a702820b6a3bf10f7dac3e68ef60b8b00000000014205000000245555494410000000ef636ddf8c29444b91f7a9a403e30a0c050100000049080000000e0000000000000005010000004d080000000000000400000000040100000050040000000200000042010000005320000000a92f311fd023694a37b2a2de501e1569a2af8129bfbce33c36c6e711d0231b5804010000005604000000130000000000040000000d0a0d0a*e3ae61a446f9cab783f5c579ef09d7a7acf74649d1808aff7e47ddee84ae9131";
const REAL_V3_PREFIX = [
  "A9mimmf7S7UBAAMAAhAAMcHy5r9xQ1C+WAUhavxa/wMEAAEAAAAEIAACuDpott/MgK2DcWEpgmA1ffoB",
  "3Rz1P/LtiMjhbmNH/QUgAK6aEc3QHtc6DwPe+7I3PtwNOcuw1Gt+hs6f9fybR5nTBggAZAAAAAAAAAAH",
  "EACm1UemvfZPVqCxr4TP/BVeCCAAHf42HQfeZGLMBF4m0GhSxlPtmRafLEyDZF/9uP/bbV0JIADoZE1U",
  "szQEfFdvlLLsBOhVnM8HSFb7PHU8loN+cB45jAoEAAIAAAAABAANCg0KqsgREMj90ALQFhFj4/cW8gcX",
  "95sW1P2H+9bdw6Hl/4I=",
].join("");
const REAL_V3_HASH = `$keepass$*2*100*0*02b83a68b6dfcc80ad837161298260357dfa01dd1cf53ff2ed88c8e16e6347fd*ae9a11cdd01ed73a0f03defbb2373edc0d39cbb0d46b7e86ce9ff5fc9b4799d3*a6d547a6bdf64f56a0b1af84cffc155e*e8644d54b334047c576f94b2ec04e8559ccf074856fb3c753c96837e701e398c*aac81110c8fdd002d0161163e3f716f20717f79b16d4fd87fbd6ddc3a1e5ff82`;

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}

function binary(hex: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(hex.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

function uint32(value: number): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value, true);
  return result;
}

function uint16(value: number): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(2);
  new DataView(result.buffer).setUint16(0, value, true);
  return result;
}

function uint64(value: number): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(8);
  new DataView(result.buffer).setBigUint64(0, BigInt(value), true);
  return result;
}

function headerField(id: number, value: Uint8Array): Uint8Array<ArrayBuffer> {
  return concat(Uint8Array.of(id), uint32(value.length), value);
}

function legacyField(id: number, value: Uint8Array): Uint8Array<ArrayBuffer> {
  return concat(Uint8Array.of(id), uint16(value.length), value);
}

function legacyFixture(rounds = 16): { bytes: Uint8Array<ArrayBuffer>; headerLength: number } {
  const header = concat(
    uint32(0x9aa2d903), uint32(0xb54bfb67), Uint8Array.of(1, 0, 3, 0),
    legacyField(2, binary(AES_ID)),
    legacyField(4, new Uint8Array(32).fill(0x11)),
    legacyField(5, new Uint8Array(32).fill(0x22)),
    legacyField(6, uint64(rounds)),
    legacyField(7, new Uint8Array(16).fill(0x33)),
    legacyField(9, new Uint8Array(32).fill(0x44)),
    legacyField(0, Uint8Array.of(13, 10, 13, 10)),
  );
  return { bytes: concat(header, new Uint8Array(32).fill(0x55)), headerLength: header.length };
}

function kdfEntry(name: string, type: number, value: Uint8Array): Uint8Array<ArrayBuffer> {
  const key = encoder.encode(name);
  return concat(Uint8Array.of(type), uint32(key.length), key, uint32(value.length), value);
}

function fixture(kdf = ARGON2D, extra: Uint8Array = new Uint8Array(0)): { bytes: Uint8Array<ArrayBuffer>; header: Uint8Array<ArrayBuffer> } {
  const params = concat(
    Uint8Array.of(0, 1),
    kdfEntry("$UUID", 0x42, binary(kdf)),
    kdfEntry("I", 0x05, uint64(2)),
    kdfEntry("M", 0x05, uint64(8 * 1024 * 1024)),
    kdfEntry("P", 0x04, uint32(1)),
    kdfEntry("V", 0x04, uint32(19)),
    kdfEntry("S", 0x42, new Uint8Array(32).fill(0x33)),
    extra,
    Uint8Array.of(0),
  );
  const header = concat(
    uint32(0x9aa2d903), uint32(0xb54bfb67), Uint8Array.of(0, 0, 4, 0),
    headerField(2, binary(AES_ID)),
    headerField(4, new Uint8Array(32).fill(0x11)),
    headerField(7, new Uint8Array(16).fill(0x22)),
    headerField(11, params),
    headerField(0, Uint8Array.of(13, 10, 13, 10)),
  );
  const digest = new Sha256().update(header).digest();
  return { header, bytes: concat(header, digest, new Uint8Array(32).fill(0x44), new Uint8Array(36)) };
}

async function run(operationId: string, bytes: Uint8Array<ArrayBuffer>) {
  return executeOperation(registry, { operationId, inputs: { data: bytesFrom(bytes) }, params: {} });
}

describe("KeePass password material", () => {
  it("matches a real pykeepass KDBX3 hash cracked by Hashcat 13400", async () => {
    const bytes = Uint8Array.from(atob(REAL_V3_PREFIX), (character) => character.charCodeAt(0));
    const exported = await run("credential.keepass.hash-export", bytes);
    expect(exported.run.error).toBeUndefined();
    expect((exported.outputs.hash as { text: string }).text).toBe(REAL_V3_HASH);
  });

  it("exports KDBX3 AES-KDF fields in John and Hashcat 13400 order", async () => {
    const { bytes, headerLength } = legacyFixture();
    const inspection = await run("credential.keepass.inspect", bytes);
    expect(inspection.run.error).toBeUndefined();
    expect((inspection.outputs.report as { data: object }).data).toEqual({
      format: "KDBX3", version: "3.1", cipher: "AES-256", kdf: "AES-KDF", iterations: 16, headerBytes: headerLength,
    });
    const exported = await run("credential.keepass.hash-export", bytes);
    expect((exported.outputs.hash as { text: string }).text).toBe(`$keepass$*2*16*0*${"11".repeat(32)}*${"22".repeat(32)}*${"33".repeat(16)}*${"44".repeat(32)}*${"55".repeat(32)}`);
    expect(exported.run.diagnostics).toEqual(["Exported KDBX3 AES-KDF password material for Hashcat mode 13400 and John the Ripper."]);
  });

  it("rejects truncated KDBX3 ciphertext and unsupported AES-KDF rounds", async () => {
    const { bytes } = legacyFixture();
    const truncated = await run("credential.keepass.hash-export", bytes.slice(0, -1));
    expect(truncated.run.error?.message).toMatch(/encrypted prefix is truncated/);
    const excessive = await run("credential.keepass.hash-export", legacyFixture(0x100000000).bytes);
    expect(excessive.run.error?.message).toMatch(/rounds exceed the supported 32-bit range/);
  });

  it("matches the pykeepass header cracked by Hashcat 34300", async () => {
    const prefix = Uint8Array.from(atob(REAL_HEADER_PREFIX), (character) => character.charCodeAt(0));
    const result = await run("credential.keepass.hash-export", concat(prefix, new Uint8Array(880)));
    expect(result.run.error).toBeUndefined();
    expect((result.outputs.hash as { text: string }).text).toBe(REAL_HASH);
  });

  it.each([[ARGON2D, "Argon2d", "ef636ddf"], [ARGON2ID, "Argon2id", "9e298b19"]])("exports KDBX4 %s metadata and hash", async (uuid, name, prefix) => {
    const { bytes, header } = fixture(uuid);
    const inspection = await run("credential.keepass.inspect", bytes);
    expect(inspection.run.error).toBeUndefined();
    expect((inspection.outputs.report as { data: object }).data).toEqual({
      format: "KDBX4", version: "4.0", cipher: "AES-256", kdf: name,
      iterations: 2, memoryKiB: 8192, parallelism: 1, headerBytes: header.length,
    });

    const exportResult = await run("credential.keepass.hash-export", bytes);
    expect(exportResult.run.error).toBeUndefined();
    const hash = (exportResult.outputs.hash as { text: string }).text;
    expect(hash.startsWith(`$keepass$*4*2*${prefix}*8388608*19*1*${"11".repeat(32)}*${"33".repeat(32)}*`)).toBe(true);
    expect(hash.endsWith(`*${"44".repeat(32)}`)).toBe(true);
    expect(exportResult.run.diagnostics).toEqual([`Exported KDBX4 ${name} password material for Hashcat mode 34300 and John the Ripper.`]);
  });

  it("rejects a corrupted header before returning password material", async () => {
    const { bytes, header } = fixture();
    bytes[header.length] ^= 1;
    const result = await run("credential.keepass.hash-export", bytes);
    expect(result.run.error).toMatchObject({ code: "INVALID_INPUT", message: "KeePass KDBX4 header SHA-256 is invalid" });
  });

  it("rejects an unsupported KDF and duplicate KDF parameters", async () => {
    const aesKdf = await run("credential.keepass.hash-export", fixture("c9d9f39a628a4460bf740d08c18a4fea").bytes);
    expect(aesKdf.run.error?.message).toMatch(/only Argon2d and Argon2id/);
    const duplicate = await run("credential.keepass.hash-export", fixture(ARGON2D, kdfEntry("I", 0x05, uint64(2))).bytes);
    expect(duplicate.run.error?.message).toMatch(/parameter I is duplicated/);
  });

  it("rejects truncated or unsupported database versions", async () => {
    const { bytes } = fixture();
    const short = await run("credential.keepass.hash-export", bytes.slice(0, 40));
    expect(short.run.error?.code).toBe("INVALID_INPUT");
    const version5 = bytes.slice();
    version5[10] = 5;
    const unsupported = await run("credential.keepass.hash-export", version5);
    expect(unsupported.run.error?.message).toMatch(/version 5.0 is unsupported/);
  });

  it("rejects a first block that overruns the file", async () => {
    const prefix = Uint8Array.from(atob(REAL_HEADER_PREFIX), (character) => character.charCodeAt(0));
    const result = await run("credential.keepass.hash-export", concat(prefix, new Uint8Array(879)));
    expect(result.run.error).toMatchObject({ code: "INVALID_INPUT", message: "KeePass first encrypted block is truncated" });
  });
});