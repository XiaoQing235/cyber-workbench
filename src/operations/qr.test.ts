import QRCode from "qrcode";
import { describe, expect, it } from "vitest";
import { readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import type { Params } from "../core/operation/types";
import { textValue, type Value } from "../core/value";
import { formatBits, gridToText, parseGrid, writeFormat, type Grid } from "../formats/qr";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();

/** A real QR code from an independent encoder. */
function encode(text: string, level: "L" | "M" | "Q" | "H", version?: number): Grid {
  const { modules } = QRCode.create(text, { errorCorrectionLevel: level, ...(version ? { version } : {}) });
  return Array.from({ length: modules.size }, (_, y) => Array.from({ length: modules.size }, (_, x) => modules.get(y, x) === 1));
}

async function run(operationId: string, input: Value, params: Params = {}) {
  const port = registry.get(operationId).spec.inputs[0].name;
  const result = await executeOperation(registry, { operationId, inputs: { [port]: input }, params });
  return { value: Object.values(result.outputs)[0], error: result.run.error, diagnostics: result.run.diagnostics };
}

describe("QR recovery lab", () => {
  it("decodes a grid, and an image drawn from it, then samples the image back to the same grid", async () => {
    const grid = encode("flag{qr_basics}", "M");
    const text = textValue(gridToText(grid));
    expect((await run("qr.from-grid", text, { restore: false, tryFormats: false })).value).toEqual(textValue("flag{qr_basics}"));
    const image = (await run("qr.draw-grid", text, { scale: 5 })).value;
    expect((await run("qr.decode", image)).value).toEqual(textValue("flag{qr_basics}"));
    expect((await run("qr.to-grid", image)).value).toEqual(text);
  });

  it("restores erased finder patterns and timing", async () => {
    const grid = encode("flag{finders_restored}", "H", 7);
    const damaged = grid.map((row) => [...row]);
    for (let y = 0; y < 9; y++) for (let x = 0; x < 9; x++) if (!(x === 8 || y === 8)) damaged[y][x] = false;
    for (let y = 0; y < 8; y++) for (let x = grid.length - 8; x < grid.length; x++) damaged[y][x] = !damaged[y][x];
    for (let i = 8; i < grid.length - 8; i++) damaged[6][i] = false;
    const text = textValue(gridToText(damaged));
    expect((await run("qr.from-grid", text, { restore: false, tryFormats: false })).error?.code).toBe("INVALID_INPUT");
    const { value, diagnostics } = await run("qr.from-grid", text, { restore: true, tryFormats: false });
    expect(value).toEqual(textValue("flag{finders_restored}"));
    expect(diagnostics[0]).toMatch(/module\(s\) changed/);
  });

  it("brute-forces damaged format information", async () => {
    const grid = encode("flag{format_bits}", "Q");
    const blanked = writeFormat(grid, 0);
    const result = await run("qr.from-grid", textValue(gridToText(blanked)), { tryFormats: true });
    expect(result.value).toEqual(textValue("flag{format_bits}"));
    expect(result.diagnostics.at(-1)).toMatch(/error correction Q with mask \d/);
    const level = "Q";
    const mask = Number(/mask (\d)/.exec(result.diagnostics.at(-1)!)![1]);
    expect(gridToText(writeFormat(grid, formatBits(level, mask)))).toBe(gridToText(grid));
  });

  it("accepts 1/0 grids, explains malformed ones, and renders images the viewer can show", async () => {
    const grid = encode("flag{ones}", "L");
    const ones = grid.map((row) => row.map((dark) => (dark ? "1" : "0")).join("")).join("\n");
    expect(parseGrid(ones)).toEqual(grid);
    expect((await run("qr.from-grid", textValue("##\n.."))).error?.message).toMatch(/21, 25, 29/);
    const image = (await run("qr.draw-grid", textValue(ones), { scale: 2 })).value;
    const bytes = image.type === "bytes" ? await readAll(image.source) : new Uint8Array();
    expect(String.fromCharCode(bytes[0], bytes[1])).toBe("BM");
  });
});
