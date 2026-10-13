import { describe, expect, it } from "vitest";
import { ConcatSource, MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import type { OperationResult } from "../core/operation/run";
import type { Params } from "../core/operation/types";
import { bytesFrom, bytesValue, type Value } from "../core/value";
import { decodeImage } from "../formats/decode";
import { parsePng } from "../formats/png/parse";
import { compress, makeBmp24, makePng, tamperDimensions } from "../formats/testing/fixtures";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();
const pattern = (length: number, seed = 7) => Uint8Array.from({ length }, (_, i) => (i * seed + (i >> 2)) & 255);

async function run(operationId: string, input: Value, params: Params = {}): Promise<OperationResult> {
  return executeOperation(registry, { operationId, inputs: { data: input }, params });
}

function output(result: OperationResult): Value {
  expect(result.run.error).toBeUndefined();
  return Object.values(result.outputs)[0];
}

async function outputBytes(result: OperationResult): Promise<Uint8Array> {
  const value = output(result);
  if (value.type !== "bytes") throw new Error(`expected bytes, got ${value.type}`);
  return readAll(value.source);
}

function report(result: OperationResult): Record<string, unknown> & { findings: { id: string; suggestion?: { params?: Params } }[] } {
  const value = output(result);
  if (value.type !== "structured") throw new Error(`expected structured, got ${value.type}`);
  return value.data as never;
}

describe("PNG repair workflow", () => {
  const width = 6;
  const height = 5;

  it("finds the real dimensions from the CRC and restores the image", async () => {
    const pixels = pattern(width * height * 3);
    const original = await makePng({ width, height, colorType: 2, bitDepth: 8, pixels });
    const tampered = tamperDimensions(original, width, 2);

    const search = report(await run("png.find-dimensions", bytesFrom(tampered), { maxDimension: 64 }));
    expect(search.matches).toContainEqual({ width, height });
    const suggestion = search.findings[0].suggestion!;

    const repaired = await outputBytes(await run("png.set-ihdr", bytesFrom(tampered), suggestion.params));
    expect([...repaired]).toEqual([...original]);
    const structure = await parsePng(new MemorySource(new Uint8Array(repaired)));
    expect(structure.chunks.every((c) => c.storedCrc === c.computedCrc)).toBe(true);
  });

  it("spots a reduced height from the image data size even when the CRC was fixed", async () => {
    const original = await makePng({ width, height, colorType: 2, bitDepth: 8, pixels: pattern(width * height * 3) });
    const shrunk = await outputBytes(await run("png.set-ihdr", bytesFrom(original), { height: 2 }));
    const inspection = report(await run("png.inspect", bytesFrom(new Uint8Array(shrunk))));
    const finding = inspection.findings.find((f) => f.id === "png.idat.extra");
    expect(finding?.suggestion?.params).toEqual({ height });
    expect(inspection.findings.some((f) => f.id === "png.crc.IHDR")).toBe(false);
  });

  it("patches without copying the untouched bytes and leaves the input unchanged", async () => {
    const original = await makePng({ width, height, colorType: 0, bitDepth: 8, pixels: pattern(width * height) });
    const before = original.slice();
    const result = await run("png.set-ihdr", bytesFrom(original), { width: 7 });
    const value = output(result);
    expect(value.type === "bytes" && value.source instanceof ConcatSource).toBe(true);
    expect([...original]).toEqual([...before]);
    expect(result.run.diagnostics[0]).toMatch(/7×5/);
  });

  it("recomputes broken chunk CRCs", async () => {
    const png = await makePng({ width: 2, height: 2, colorType: 0, bitDepth: 8, pixels: pattern(4) });
    const broken = png.slice();
    broken[broken.length - 13] ^= 0xff; // last byte of the IDAT CRC
    expect((await parsePng(new MemorySource(broken))).findings.some((f) => f.id === "png.crc.IDAT")).toBe(true);
    const fixed = await outputBytes(await run("png.fix-crcs", bytesFrom(broken)));
    expect([...fixed]).toEqual([...png]);
  });

  it("rejects non-PNG input with a clear error", async () => {
    const result = await run("png.inspect", bytesFrom(new TextEncoder().encode("hello")));
    expect(result.run.error?.code).toBe("INVALID_INPUT");
  });
});

describe("image.lsb operation", () => {
  it("extracts a message from a PNG and reports dropped bits", async () => {
    const message = new TextEncoder().encode("CTF{ok}");
    const cover = pattern(4 * 4 * 4, 11);
    [...message]
      .flatMap((byte) => [7, 6, 5, 4, 3, 2, 1, 0].map((s) => (byte >> s) & 1))
      .forEach((bit, i) => (cover[i] = (cover[i] & 0xfe) | bit));
    const png = await makePng({ width: 4, height: 4, colorType: 6, bitDepth: 8, pixels: cover });
    const result = await run("image.lsb", bytesFrom(png), { channels: "RGBA" });
    const bytes = await outputBytes(result);
    expect(new TextDecoder().decode(bytes.subarray(0, message.length))).toBe("CTF{ok}");
    expect(result.run.diagnostics).toEqual([]);
  });

  it("works on BMP with named channels regardless of storage order", async () => {
    const rgb = Uint8Array.of(1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0);
    const bmp = makeBmp24(2, 2, rgb);
    const bytes = await outputBytes(await run("image.lsb", bytesFrom(bmp), { channels: "RGB" }));
    expect(bytes.length).toBe(1);
    expect(bytes[0]).toBe(0b10000111);
  });

  it("fails clearly for a missing channel", async () => {
    const png = await makePng({ width: 1, height: 1, colorType: 0, bitDepth: 8, pixels: Uint8Array.of(1) });
    const result = await run("image.lsb", bytesFrom(png), { channels: "R" });
    expect(result.run.error?.message).toMatch(/available: Y/);
  });
});

describe("BMP operations", () => {
  it("reveals rows hidden by a reduced height", async () => {
    const width = 4;
    const bmp = makeBmp24(width, 2, pattern(width * 5 * 3), 3);
    const inspection = report(await run("bmp.inspect", bytesFrom(bmp)));
    const finding = inspection.findings.find((f) => f.id === "bmp.extra-rows");
    const restored = await outputBytes(await run("bmp.set-dimensions", bytesFrom(bmp), finding!.suggestion!.params));
    const { image } = await decodeImage(new MemorySource(new Uint8Array(restored)));
    expect(image.height).toBe(5);
  });
});

describe("zlib.inflate operation", () => {
  const data = new TextEncoder().encode("flag{".repeat(1000) + "}");

  it.each(["zlib", "gzip", "deflate-raw"] as const)("round-trips %s", async (format) => {
    const compressed = await compress(data, format === "zlib" ? "deflate" : format);
    expect([...(await outputBytes(await run("zlib.inflate", bytesFrom(compressed), { format })))]).toEqual([...data]);
  });

  it("fails on a decompression bomb instead of exhausting memory", async () => {
    const bomb = await compress(new Uint8Array(8 * 1024 * 1024));
    const result = await run("zlib.inflate", bytesFrom(bomb), { maxOutputBytes: 1024 * 1024 });
    expect(result.run.error?.message).toMatch(/decompression bomb/);
  });

  it("fails on a damaged stream unless partial output is allowed", async () => {
    const big = pattern(200_000, 3);
    const damaged = (await compress(big)).slice(0, -8);
    const strict = await run("zlib.inflate", bytesFrom(damaged));
    expect(strict.run.status).toBe("failed");
    expect(strict.run.error?.message).toMatch(/truncated or corrupt/);
    const lenient = await run("zlib.inflate", bytesFrom(damaged), { allowPartial: true });
    expect(lenient.run.status).toBe("success");
    expect(lenient.run.diagnostics[0]).toMatch(/damaged/);
    expect([...(await outputBytes(lenient))]).toEqual([...big.subarray(0, (await outputBytes(lenient)).length)]);
  });
});

describe("file.detect operation", () => {
  it("identifies a PNG and an appended ZIP signature", async () => {
    const png = await makePng({ width: 1, height: 1, colorType: 0, bitDepth: 8, pixels: Uint8Array.of(0), trailing: Uint8Array.of(0x50, 0x4b, 3, 4, 1, 2) });
    const detection = report(await run("file.detect", bytesFrom(png)));
    expect(detection.candidates).toContainEqual({ type: "png", description: "PNG image" });
    expect(detection.embedded).toContainEqual({ type: "zip", description: "ZIP archive (local file header)", offset: png.length - 6 });
  });

  it("recognises Base64-shaped text and measures entropy", async () => {
    const text = new TextEncoder().encode("Q1RGe2RldGVjdH0=\n");
    const detection = report(await run("file.detect", bytesValue(new MemorySource(text))));
    expect(detection.findings.map((f) => f.id)).toContain("detect.text");
    expect(detection.entropyBitsPerByte).toBeGreaterThan(3);
    const random = report(await run("file.detect", bytesFrom(Uint8Array.from({ length: 65536 }, (_, i) => (i * 2654435761) >>> 24))));
    expect(random.entropyBitsPerByte).toBeGreaterThan(7.5);
  });
});
