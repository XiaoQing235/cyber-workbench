import { describe, expect, it } from "vitest";
import { readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import type { OperationResult } from "../core/operation/run";
import type { Params } from "../core/operation/types";
import { bytesFrom, textValue, type Value } from "../core/value";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();
const encoder = new TextEncoder();

async function run(operationId: string, input: Value, params: Params = {}): Promise<OperationResult> {
  const spec = registry.get(operationId).spec;
  return executeOperation(registry, { operationId, inputs: { [spec.inputs[0].name]: input }, params });
}

async function outputBytes(result: OperationResult): Promise<number[]> {
  expect(result.run.error).toBeUndefined();
  const value = Object.values(result.outputs)[0];
  if (value.type !== "bytes") throw new Error(`expected bytes, got ${value.type}`);
  return [...(await readAll(value.source))];
}

function outputText(result: OperationResult): string {
  expect(result.run.error).toBeUndefined();
  const value = Object.values(result.outputs)[0];
  if (value.type !== "text") throw new Error(`expected text, got ${value.type}`);
  return value.text;
}

const ascii = (text: string) => bytesFrom(encoder.encode(text));
const asciiCodes = (text: string) => [...encoder.encode(text)];

describe("Base64 (RFC 4648 test vectors)", () => {
  const vectors: [string, string][] = [
    ["", ""],
    ["f", "Zg=="],
    ["fo", "Zm8="],
    ["foo", "Zm9v"],
    ["foob", "Zm9vYg=="],
    ["fooba", "Zm9vYmE="],
    ["foobar", "Zm9vYmFy"],
  ];

  it.each(vectors)("encodes %j", async (plain, encoded) => {
    expect(outputText(await run("base64.encode", ascii(plain)))).toBe(encoded);
  });

  it.each(vectors)("decodes %j", async (plain, encoded) => {
    expect(await outputBytes(await run("base64.decode", textValue(encoded)))).toEqual(asciiCodes(plain));
  });

  it("supports the URL-safe alphabet and unpadded output", async () => {
    const data = bytesFrom(Uint8Array.from([0xfb, 0xff, 0xbf]));
    expect(outputText(await run("base64.encode", data, { alphabet: "url" }))).toBe("-_-_");
    expect(outputText(await run("base64.encode", ascii("f"), { padding: false }))).toBe("Zg");
  });

  it("ignores whitespace and accepts missing padding unless required", async () => {
    expect(await outputBytes(await run("base64.decode", textValue("Zm9v\nYg")))).toEqual(asciiCodes("foob"));
    const strict = await run("base64.decode", textValue("Zm9vYg"), { requirePadding: true });
    expect(strict.run.error?.code).toBe("INVALID_INPUT");
  });

  it("rejects invalid characters, bad padding and truncation", async () => {
    for (const bad of ["Zm9v!", "Zm9vY", "Zm9v=", "Zg=a", "Zg==="]) {
      const result = await run("base64.decode", textValue(bad));
      expect(result.run.status, bad).toBe("failed");
    }
  });

  it("flags non-zero unused bits", async () => {
    const result = await run("base64.decode", textValue("Zh=="));
    expect(await outputBytes(result)).toEqual(asciiCodes("f"));
    expect(result.run.diagnostics.join(" ")).toMatch(/steganography/);
  });

  it("encodes large inputs identically across chunk boundaries", async () => {
    const data = Uint8Array.from({ length: 3 * 256 * 1024 * 2 + 5 }, (_, i) => (i * 31) & 255);
    let binary = "";
    for (let i = 0; i < data.length; i += 8192) binary += String.fromCharCode(...data.subarray(i, i + 8192));
    const encoded = outputText(await run("base64.encode", bytesFrom(data)));
    expect(encoded).toBe(btoa(binary));
  });
});

describe("Hex", () => {
  it("encodes with case and separator options", async () => {
    const data = bytesFrom(Uint8Array.from([0x00, 0xab, 0xff]));
    expect(outputText(await run("hex.encode", data))).toBe("00abff");
    expect(outputText(await run("hex.encode", data, { uppercase: true, separator: " " }))).toBe("00 AB FF");
  });

  it("decodes with prefixes and separators", async () => {
    expect(await outputBytes(await run("hex.decode", textValue("0x48:0x69 \\x21")))).toEqual([0x48, 0x69, 0x21]);
  });

  it("fails on odd length or invalid digits", async () => {
    expect((await run("hex.decode", textValue("abc"))).run.error?.code).toBe("INVALID_INPUT");
    expect((await run("hex.decode", textValue("zz"))).run.error?.code).toBe("INVALID_INPUT");
    expect((await run("hex.decode", textValue("aa:bb"), { ignoreSeparators: false })).run.status).toBe("failed");
  });
});

describe("Password hash material", () => {
  it("exposes conservative classifications through the operation registry", async () => {
    const input = textValue(`${"a".repeat(32)}\nunknown`);
    const result = await run("credential.hash-identify", input, { maxLines: 10 });
    expect(result.run.error).toBeUndefined();
    expect(result.run.diagnostics).toEqual(["Identified 1 of 2 hash line(s)."]);
    expect((result.outputs.report as { data: unknown }).data).toMatchObject({
      matches: [{ format: "Raw 128-bit hexadecimal digest", confidence: "ambiguous", hashcatModes: [0, 1000] }],
      unrecognised: [{ line: 2, length: 7 }],
      truncated: false,
    });
  });

  it("rejects oversized credential text before parsing", async () => {
    const result = await run("credential.hash-identify", textValue("x".repeat(1024 * 1024 + 1)), { maxLines: 10 });
    expect(result.run.error).toMatchObject({ code: "INPUT_TOO_LARGE" });
  });
});

describe("Text charsets", () => {
  it("round-trips every byte through Latin-1, including 0x80–0x9F", async () => {
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    const text = outputText(await run("text.decode", bytesFrom(all), { charset: "latin1" }));
    expect(text.length).toBe(256);
    expect(text.charCodeAt(0x80)).toBe(0x80);
    expect(await outputBytes(await run("text.encode", textValue(text), { charset: "latin1" }))).toEqual([...all]);
  });

  it("encodes UTF-16 in both byte orders", async () => {
    expect(await outputBytes(await run("text.encode", textValue("Aé"), { charset: "utf-16le" }))).toEqual([
      0x41, 0x00, 0xe9, 0x00,
    ]);
    expect(await outputBytes(await run("text.encode", textValue("Aé"), { charset: "utf-16be" }))).toEqual([
      0x00, 0x41, 0x00, 0xe9,
    ]);
  });

  it("is strict about invalid UTF-8 unless asked to replace", async () => {
    const invalid = bytesFrom(Uint8Array.from([0x66, 0xff, 0x6f]));
    expect((await run("text.decode", invalid)).run.error?.code).toBe("INVALID_INPUT");
    expect(outputText(await run("text.decode", invalid, { onInvalid: "replace" }))).toBe("f\ufffdo");
  });

  it("keeps a UTF-8 BOM instead of silently stripping it", async () => {
    const withBom = bytesFrom(Uint8Array.from([0xef, 0xbb, 0xbf, 0x41]));
    expect(outputText(await run("text.decode", withBom))).toBe("\ufeffA");
  });

  it("rejects unmappable characters by default", async () => {
    expect((await run("text.encode", textValue("€"), { charset: "latin1" })).run.error?.code).toBe("INVALID_INPUT");
    expect(await outputBytes(await run("text.encode", textValue("€"), { charset: "latin1", onUnmappable: "replace" }))).toEqual([
      0x3f,
    ]);
    expect((await run("text.encode", textValue("\ud800"))).run.error?.code).toBe("INVALID_INPUT");
  });
});

describe("Binary operations", () => {
  const data = bytesFrom(Uint8Array.from([1, 2, 3, 4, 5, 6, 7]));

  it("reverses whole input or groups", async () => {
    expect(await outputBytes(await run("bytes.reverse", data))).toEqual([7, 6, 5, 4, 3, 2, 1]);
    const grouped = await run("bytes.reverse", data, { groupSize: 2 });
    expect(await outputBytes(grouped)).toEqual([2, 1, 4, 3, 6, 5, 7]);
    expect(grouped.run.diagnostics).toHaveLength(1);
    expect(await outputBytes(await run("bytes.reverse", data, { groupSize: 4, remainder: "reverse" }))).toEqual([
      4, 3, 2, 1, 7, 6, 5,
    ]);
    expect((await run("bytes.reverse", data, { groupSize: 4, remainder: "error" })).run.status).toBe("failed");
  });

  it("does not modify its input artifact", async () => {
    const source = Uint8Array.from([1, 2, 3]);
    const input = bytesFrom(source);
    await run("bytes.reverse", input);
    expect([...source]).toEqual([1, 2, 3]);
  });

  it("reverses bits and inverts bytes", async () => {
    const value = bytesFrom(Uint8Array.from([0b00000001, 0b11010000]));
    expect(await outputBytes(await run("bits.reverse", value))).toEqual([0b10000000, 0b00001011]);
    expect(await outputBytes(await run("bytes.not", value))).toEqual([0b11111110, 0b00101111]);
  });

  it("XORs with a repeating key aligned to absolute offsets across chunks", async () => {
    const size = 2 * 1024 * 1024 + 7;
    const plain = Uint8Array.from({ length: size }, (_, i) => (i * 7) & 255);
    const key = [0x13, 0x37, 0x42];
    const result = await outputBytes(await run("bytes.xor", bytesFrom(plain), { key: "13 37 42" }));
    expect(result.length).toBe(size);
    for (const i of [0, 1, 2, 3, 1024 * 1024 - 1, 1024 * 1024, 1024 * 1024 + 1, size - 1]) {
      expect(result[i]).toBe(plain[i] ^ key[i % 3]);
    }
  });

  it("XOR rejects an empty key and accepts UTF-8 keys", async () => {
    expect((await run("bytes.xor", data, { key: "" })).run.error?.code).toBe("INVALID_PARAMS");
    expect(await outputBytes(await run("bytes.xor", ascii("AB"), { key: "\u0001", keyFormat: "utf-8" }))).toEqual([
      0x40, 0x43,
    ]);
  });

  it("finds the independently enumerated bad-byte-free XOR keys", async () => {
    const original = Uint8Array.of(0, 1, 10, 65);
    const result = await run("binary.badbytes.xor-keys", bytesFrom(original), { forbidden: "00 0a", maxKeys: 16 });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: {
      scannedBytes: 4, forbidden: ["00", "0a"], originalBadCount: 2, firstBadOffsets: [0, 2],
      validKeyCount: 250, keys: ["02", "03", "04", "05", "06", "07", "08", "09", "0c", "0d", "0e", "0f", "10", "11", "12", "13"], truncated: true,
      keyByteChecked: false,
    } });
    for (const key of ["02", "03", "0c", "13"]) {
      const encoded = await outputBytes(await run("bytes.xor", bytesFrom(original), { key }));
      expect(encoded.some((byte) => byte === 0 || byte === 10)).toBe(false);
    }
    expect((await run("binary.badbytes.xor-keys", bytesFrom(original), { forbidden: "" })).run.error?.code).toBe("INVALID_PARAMS");
  });

  it("slices without copying and validates the range", async () => {
    expect(await outputBytes(await run("bytes.slice", data, { offset: 2, length: 3 }))).toEqual([3, 4, 5]);
    expect(await outputBytes(await run("bytes.slice", data, { offset: 5 }))).toEqual([6, 7]);
    expect((await run("bytes.slice", data, { offset: 5, length: 5 })).run.error?.code).toBe("INVALID_INPUT");
  });
});

describe("Hashing", () => {
  it("computes SHA-256 and SHA-1", async () => {
    expect(outputText(await run("hash.digest", ascii("abc")))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(outputText(await run("hash.digest", ascii("abc"), { algorithm: "SHA-1" }))).toBe(
      "a9993e364706816aba3e25717850c26c9cd0d89d",
    );
  });

  it("computes CRC-32 (check value)", async () => {
    const result = await run("checksum.crc32", ascii("123456789"));
    expect(result.outputs.crc).toEqual({ type: "number", value: 0xcbf43926 });
  });
});
