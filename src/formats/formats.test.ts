import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { MemorySource } from "../core/bytes/sources";
import { inflate } from "../core/compression/inflate";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { decodeBmp, parseBmp } from "./bmp/bmp";
import { decodeImage } from "./decode";
import { bitPlaneRgba, toRgba } from "./image";
import { extractBits } from "./lsb";
import { decodePng } from "./png/decode";
import { parsePng } from "./png/parse";
import { compress, concat, makeBmp24, makePng, pngChunk, tamperDimensions } from "./testing/fixtures";

const source = (bytes: Uint8Array<ArrayBuffer>) => new MemorySource(bytes);
const pattern = (length: number, seed = 7) => Uint8Array.from({ length }, (_, i) => (i * seed + (i >> 3)) & 255);

describe("PNG parsing", () => {
  it("inspects and decodes two original Google CTF 2024 pixel-permutation inputs", async () => {
    const samples = [
      { file: "google-ctf-2024-otp-2nd00.png", first: [130, 115, 130, 255], middle: [125, 132, 137, 255], last: [122, 132, 143, 255] },
      { file: "google-ctf-2024-otp-2nd01.png", first: [164, 173, 180, 255], middle: [55, 58, 62, 255], last: [90, 104, 105, 255] },
    ];
    for (const sample of samples) {
      const bytes = new Uint8Array(readFileSync(new URL(`./testing/${sample.file}`, import.meta.url)));
      const result = await executeOperation(createDefaultRegistry(), { operationId: "png.inspect", inputs: { data: bytesFrom(bytes) }, params: {} });
      expect(result.run.error).toBeUndefined();
      const report = (result.outputs.report as { data: { signatureValid: boolean; ihdr: { width: number; height: number; bitDepth: number; colorType: number }; chunks: { crcOk: boolean }[]; endOffset: number; findings: unknown[] } }).data;
      expect(report).toMatchObject({ signatureValid: true, ihdr: { width: 64, height: 64, bitDepth: 8, colorType: 6 }, endOffset: bytes.length, findings: [] });
      expect(report.chunks.every((chunk) => chunk.crcOk)).toBe(true);
      const original = source(bytes);
      const { image, warnings } = await decodePng(original, await parsePng(original));
      expect(warnings).toEqual([]);
      const pixels = toRgba(image, false);
      expect([...pixels.subarray(0, 4)]).toEqual(sample.first);
      expect([...pixels.subarray((31 * 64 + 31) * 4, (31 * 64 + 31) * 4 + 4)]).toEqual(sample.middle);
      expect([...pixels.subarray(-4)]).toEqual(sample.last);
    }
  });

  it("lists chunks with valid CRCs and no strong findings for a clean file", async () => {
    const png = await makePng({ width: 4, height: 3, colorType: 2, bitDepth: 8, pixels: pattern(36) });
    const structure = await parsePng(source(png));
    expect(structure.signatureValid).toBe(true);
    expect(structure.chunks.map((c) => c.type)).toEqual(["IHDR", "IDAT", "IEND"]);
    expect(structure.chunks.every((c) => c.storedCrc === c.computedCrc)).toBe(true);
    expect(structure.ihdr).toMatchObject({ width: 4, height: 3, bitDepth: 8, colorType: 2 });
    expect(structure.findings.filter((f) => f.severity === "strong")).toEqual([]);
  });

  it("flags tampered IHDR dimensions via the CRC and suggests a search", async () => {
    const png = tamperDimensions(await makePng({ width: 4, height: 3, colorType: 2, bitDepth: 8, pixels: pattern(36) }), 4, 2);
    const finding = (await parsePng(source(png))).findings.find((f) => f.id === "png.crc.IHDR");
    expect(finding?.severity).toBe("strong");
    expect(finding?.suggestion?.operationId).toBe("png.find-dimensions");
  });

  it("reports trailing data after IEND with a carve suggestion", async () => {
    const png = await makePng({ width: 1, height: 1, colorType: 0, bitDepth: 8, pixels: Uint8Array.of(9), trailing: Uint8Array.of(0x50, 0x4b, 3, 4) });
    const finding = (await parsePng(source(png))).findings.find((f) => f.id === "png.trailing");
    expect(finding?.span).toEqual({ offset: png.length - 4, length: 4 });
    expect(finding?.suggestion).toMatchObject({ operationId: "bytes.slice", params: { offset: png.length - 4 } });
  });

  it("reads tEXt, zTXt and iTXt chunks", async () => {
    const zText = concat(Uint8Array.from("Secret\0\0", (c) => c.charCodeAt(0)), await compress(new TextEncoder().encode("flag{z}")));
    const iText = concat(new TextEncoder().encode("Note\0\0\0en\0\0"), new TextEncoder().encode("héllo"));
    const png = await makePng({
      width: 1,
      height: 1,
      colorType: 0,
      bitDepth: 8,
      pixels: Uint8Array.of(0),
      extraChunks: [
        ["tEXt", new TextEncoder().encode("Comment\0plain text")],
        ["zTXt", zText],
        ["iTXt", iText],
      ],
    });
    const texts = (await parsePng(source(png))).texts.map(({ chunk, keyword, text }) => ({ chunk, keyword, text }));
    expect(texts).toEqual([
      { chunk: "tEXt", keyword: "Comment", text: "plain text" },
      { chunk: "zTXt", keyword: "Secret", text: "flag{z}" },
      { chunk: "iTXt", keyword: "Note", text: "héllo" },
    ]);
  });

  it("keeps parsing after a damaged signature and stops cleanly on a truncated chunk", async () => {
    const png = await makePng({ width: 2, height: 2, colorType: 0, bitDepth: 8, pixels: pattern(4) });
    const damaged = new Uint8Array(png);
    damaged[4] = 0x0a; // \r\n → \n style damage
    const structure = await parsePng(source(damaged));
    expect(structure.signatureValid).toBe(false);
    expect(structure.chunks.length).toBeGreaterThan(0);

    const truncated = png.slice(0, png.length - 20);
    const findings = (await parsePng(source(truncated))).findings.map((f) => f.id);
    expect(findings).toContain("png.chunk.truncated");
  });
});

describe("PNG decoding", () => {
  it("reverses all five scanline filters exactly", async () => {
    const pixels = pattern(5 * 6 * 3, 13);
    const png = await makePng({ width: 6, height: 5, colorType: 2, bitDepth: 8, pixels, filters: [0, 1, 2, 3, 4] });
    const { image, warnings } = await decodePng(source(png), await parsePng(source(png)));
    expect(warnings).toEqual([]);
    expect(image.channels).toEqual(["R", "G", "B"]);
    expect([...image.samples]).toEqual([...pixels]);
  });

  it("unpacks sub-byte palette indices and keeps the palette", async () => {
    // 5 pixels per row at 2 bits: indices 0,1,2,3,1 → 00 01 10 11 | 01 000000
    const png = await makePng({
      width: 5,
      height: 1,
      colorType: 3,
      bitDepth: 2,
      pixels: Uint8Array.of(0b00011011, 0b01000000),
      palette: Uint8Array.of(255, 0, 0, 0, 255, 0, 0, 0, 255, 9, 9, 9),
    });
    const { image } = await decodePng(source(png), await parsePng(source(png)));
    expect(image.channels).toEqual(["I"]);
    expect([...image.samples]).toEqual([0, 1, 2, 3, 1]);
    expect([...toRgba(image, false).subarray(0, 8)]).toEqual([255, 0, 0, 255, 0, 255, 0, 255]);
  });

  it("decodes 16-bit samples big-endian", async () => {
    const png = await makePng({ width: 2, height: 1, colorType: 0, bitDepth: 16, pixels: Uint8Array.of(0x12, 0x34, 0xff, 0x01) });
    const { image } = await decodePng(source(png), await parsePng(source(png)));
    expect(image.samples).toBeInstanceOf(Uint16Array);
    expect([...image.samples]).toEqual([0x1234, 0xff01]);
  });

  it("de-interlaces Adam7 images", async () => {
    const width = 11;
    const height = 9;
    const pixels = pattern(width * height * 4, 5);
    const png = await makePng({ width, height, colorType: 6, bitDepth: 8, pixels, interlace: true, filters: [4, 1, 0, 2, 3] });
    const { image, warnings } = await decodePng(source(png), await parsePng(source(png)));
    expect(warnings).toEqual([]);
    expect([...image.samples]).toEqual([...pixels]);
  });

  it("decodes what it can when IDAT is short, with a warning", async () => {
    const png = tamperDimensions(await makePng({ width: 3, height: 2, colorType: 0, bitDepth: 8, pixels: pattern(6) }), 3, 4);
    const { image, warnings } = await decodePng(source(png), await parsePng(source(png)));
    expect(image.height).toBe(4);
    expect([...image.samples.subarray(0, 6)]).toEqual([...pattern(6)]);
    expect(warnings.join(" ")).toMatch(/short/);
  });
});

describe("BMP", () => {
  it("decodes 24-bit bottom-up rows with padding as top-down BGR samples", async () => {
    const rgb = Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18);
    const bmp = makeBmp24(3, 2, rgb);
    const structure = await parseBmp(source(bmp));
    expect(structure.rowStride).toBe(12);
    const { image } = await decodeBmp(source(bmp), structure);
    expect(image.channels).toEqual(["B", "G", "R"]);
    expect([...image.samples.subarray(0, 3)]).toEqual([3, 2, 1]);
    expect([...toRgba(image, true).subarray(0, 4)]).toEqual([1, 2, 3, 255]);
  });

  it("finds rows hidden by a reduced height", async () => {
    const bmp = makeBmp24(4, 2, pattern(4 * 5 * 3), 3);
    const finding = (await parseBmp(source(bmp))).findings.find((f) => f.id === "bmp.extra-rows");
    expect(finding?.severity).toBe("strong");
    expect(finding?.suggestion).toMatchObject({ operationId: "bmp.set-dimensions", params: { height: 5 } });
  });
});

describe("LSB extraction", () => {
  const message = new TextEncoder().encode("flag{lsb}");

  function embed(cover: Uint8Array, bits: number[]): Uint8Array<ArrayBuffer> {
    const out = new Uint8Array(cover);
    bits.forEach((bit, i) => (out[i] = (out[i] & 0xfe) | bit));
    return out;
  }
  const bitsOf = (bytes: Uint8Array) => [...bytes].flatMap((byte) => [7, 6, 5, 4, 3, 2, 1, 0].map((s) => (byte >> s) & 1));

  it("recovers a message hidden in RGB least significant bits", async () => {
    const width = 8;
    const height = 4;
    const pixels = embed(pattern(width * height * 3, 29), bitsOf(message));
    const png = await makePng({ width, height, colorType: 2, bitDepth: 8, pixels });
    const { image } = await decodeImage(source(png));
    const result = extractBits(image, { channels: "RGB", bit: 0, bitOrder: "msb-first", scan: "rows", startFrom: "top" });
    expect(new TextDecoder().decode(result.bytes.subarray(0, message.length))).toBe("flag{lsb}");
  });

  it("honours channel order, scan direction and packing", async () => {
    const image = {
      format: "png" as const,
      width: 2,
      height: 2,
      channels: ["R", "G", "B"] as const,
      bitDepth: 8,
      // pixel (x,y): R bit0 = 1 only at (1,0); B bit0 = 1 only at (0,1)
      samples: Uint8Array.of(0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0),
    };
    const rows = extractBits(image, { channels: "R", bit: 0, bitOrder: "msb-first", scan: "rows", startFrom: "top" });
    expect(rows.leftoverBits).toBe(4);
    const columnsBlue = extractBits(image, { channels: "BR", bit: 0, bitOrder: "lsb-first", scan: "columns", startFrom: "top" });
    // columns order: (0,0) (0,1) (1,0) (1,1); per pixel B then R → bits 0,0, 1,0, 0,1, 0,0
    expect([...columnsBlue.bytes]).toEqual([0b00100100]);
    expect(() => extractBits(image, { channels: "A", bit: 0, bitOrder: "msb-first", scan: "rows", startFrom: "top" })).toThrow(/available: RGB/);
  });
});

describe("bit planes", () => {
  it("renders one bit of one channel as black and white", () => {
    const image = {
      format: "png" as const,
      width: 2,
      height: 1,
      channels: ["R", "G"] as const,
      bitDepth: 8,
      samples: Uint8Array.of(0b01, 0b10, 0b10, 0b01),
    };
    expect([...bitPlaneRgba(image, 1, 1)]).toEqual([255, 255, 255, 255, 0, 0, 0, 255]);
  });
});

describe("inflate", () => {
  it("stops a decompression bomb at the output limit", async () => {
    const bomb = await compress(new Uint8Array(4 * 1024 * 1024));
    await expect(inflate(source(bomb), "zlib", { maxOutputBytes: 1024 * 1024 })).rejects.toThrow(/exceeds/);
  });

  it("keeps output produced before a stream error", async () => {
    const data = pattern(100_000, 3);
    const stream = await compress(data);
    const result = await inflate(source(stream.slice(0, stream.length - 10)), "zlib", { maxOutputBytes: 1 << 24 });
    expect(result.error).toBeTruthy();
    expect([...result.bytes]).toEqual([...data.subarray(0, result.bytes.length)]);
  });
});

describe("decodeImage", () => {
  it("rejects formats it does not handle", async () => {
    await expect(decodeImage(source(Uint8Array.of(0xff, 0xd8, 0xff, 0xe0, 0, 0, 0, 0)))).rejects.toThrow(/Unsupported/);
  });

  it("handles a hand-built single-pixel PNG made from raw chunks", async () => {
    const png = concat(
      Uint8Array.of(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a),
      pngChunk("IHDR", Uint8Array.of(0, 0, 0, 1, 0, 0, 0, 1, 8, 0, 0, 0, 0)),
      pngChunk("IDAT", await compress(Uint8Array.of(0, 200))),
      pngChunk("IEND", new Uint8Array(0)),
    );
    expect([...(await decodeImage(source(png))).image.samples]).toEqual([200]);
  });
});
