import modelData from "@tesseract.js-data/eng/4.0.0_best_int/eng.traineddata.gz?inline";
import ocrWasm from "tesseract.js-core/tesseract-core-simd-lstm.wasm?inline";
import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import type { Bytes } from "../core/bytes/ByteSource";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import type { Params } from "../core/operation/types";
import { bytesFrom } from "../core/value";
import { encodeBmp24 } from "../formats/bmp/encode";
import { decodeImage } from "../formats/decode";
import { toRgba } from "../formats/image";
import fixture from "../formats/testing/ocr-text.png?inline";
import { setPackFileReader } from "../runtimes/files";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();
const fromDataUrl = (url: string) => Uint8Array.from(atob(url.slice(url.indexOf(",") + 1)), (c) => c.charCodeAt(0));
setPackFileReader(async (url) => {
  if (url.includes("tesseract-core")) return fromDataUrl(ocrWasm);
  if (url.includes("traineddata")) return fromDataUrl(modelData);
  throw new Error(`No test file for ${url}`);
});

async function ocr(input: Bytes, params: Params = {}) {
  const result = await executeOperation(registry, { operationId: "ocr.recognize", inputs: { data: bytesFrom(input) }, params });
  const value = Object.values(result.outputs)[0];
  return { text: value?.type === "text" ? value.text : "", error: result.run.error, diagnostics: result.run.diagnostics };
}

const png = fromDataUrl(fixture);

describe("OCR pack", () => {
  it("reads printed text", { timeout: 60_000 }, async () => {
    const { text, diagnostics, error } = await ocr(png);
    expect(error).toBeUndefined();
    expect(text).toMatch(/^Hello CTF Workbench\nflag.ocr_in_browser. 2026$/);
    expect(diagnostics.at(-1)).toMatch(/^Mean confidence \d+% \(raw decoder\)/);
  });

  it("inverts light text on a dark background and honours a whitelist", { timeout: 60_000 }, async () => {
    const { image } = await decodeImage(new MemorySource(png), { maxPixels: 1e7 });
    const rgba = toRgba(image, true);
    const rgb = new Uint8Array(image.width * image.height * 3);
    for (let p = 0; p < image.width * image.height; p++) for (let c = 0; c < 3; c++) rgb[p * 3 + c] = 255 - rgba[p * 4 + c];
    const inverted = encodeBmp24(image.width, image.height, rgb);
    const { text, diagnostics } = await ocr(inverted, { layout: "block" });
    expect(diagnostics[0]).toBe("Mostly dark image: inverted so the text is dark on light.");
    expect(text).toContain("Hello CTF Workbench");
    expect((await ocr(png, { whitelist: "0123456789" })).text.replace(/\s+/g, "")).toMatch(/2026$/);
  });

  it("rejects what it cannot read", async () => {
    expect((await ocr(Uint8Array.of(1, 2, 3))).error?.code).toBe("INVALID_INPUT");
  });

  it("recovers document text from the independently decoded Google CTF PNG2 image", { timeout: 60_000 }, async () => {
    const { decodePng2 } = await import("../formats/png2");
    const input = new Uint8Array(readFileSync(new URL("../formats/testing/google-ctf-2023-reproduced.png2", import.meta.url)));
    const decoded = await decodePng2(new MemorySource(input));
    const result = await ocr(decoded.png, { layout: "sparse", whitelist: "CTF{}0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_" });
    expect(result.error).toBeUndefined();
    expect(result.text).toContain("Tableofcontents");
    expect(result.text).toContain("Hilbertcurveorder");
    expect(result.text).not.toContain("0cc4sion4lly_PNG2_is_actuAlly_5m4ll3r");
    const { colorContrastCrop } = await import("../formats/colorContrast");
    const crop = await colorContrastCrop(new MemorySource(decoded.png), 320, 215, 390, 180, 120);
    const prefix = await ocr(crop.image, { layout: "line", scale: 2 });
    expect(prefix.error).toBeUndefined();
    expect(prefix.text).toBe("CTF{");
  });

});
