import { describe, expect, it } from "vitest";
import type { Finding } from "./core/analysis/finding";
import { readAll } from "./core/bytes/sources";
import { executeOperation } from "./core/operation/execute";
import type { Params } from "./core/operation/types";
import { bytesFrom, type Value } from "./core/value";
import { compress, makeBmp24, makePng, tamperDimensions } from "./formats/testing/fixtures";
import { createDefaultRegistry } from "./operations";

// The M2 challenge flows, driven as in the UI: run an operation, follow a finding's suggestion, repeat.

const registry = createDefaultRegistry();
const ascii = (text: string) => new TextEncoder().encode(text);
const base64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));

async function step(operationId: string, input: Value, params: Params = {}): Promise<Value> {
  const port = registry.get(operationId).spec.inputs[0].name;
  const result = await executeOperation(registry, { operationId, inputs: { [port]: input }, params });
  expect(result.run.error).toBeUndefined();
  return Object.values(result.outputs)[0];
}

function findings(report: Value): Finding[] {
  if (report.type !== "structured") throw new Error(`expected a report, got ${report.type}`);
  return (report.data as { findings: Finding[] }).findings;
}

/** Runs the suggestion of the finding `findingId` (with any chained steps) on `input`. */
async function follow(report: Value, findingId: string, input: Value): Promise<Value> {
  const suggestion = findings(report).find((finding) => finding.id === findingId)?.suggestion;
  if (!suggestion) throw new Error(`no suggestion on ${findingId}`);
  let value = input;
  for (const next of [suggestion, ...(suggestion.then ?? [])]) value = await step(next.operationId, value, next.params);
  return value;
}

async function bytesOf(value: Value): Promise<Uint8Array> {
  if (value.type !== "bytes") throw new Error(`expected bytes, got ${value.type}`);
  return readAll(value.source);
}

/** Writes `message` MSB-first into the least significant bits, clearing all other LSBs. */
function embedLsb(cover: Uint8Array, message: Uint8Array): void {
  cover.forEach((sample, i) => (cover[i] = sample & 0xfe));
  [...message]
    .flatMap((byte) => [7, 6, 5, 4, 3, 2, 1, 0].map((shift) => (byte >> shift) & 1))
    .forEach((bit, i) => (cover[i] |= bit));
}

describe("M2 challenge flows", () => {
  it("PNG with a reduced height and a Base64 + zlib LSB payload", async () => {
    const [width, height] = [32, 24];
    const pixels = Uint8Array.from({ length: width * height * 3 }, (_, i) => (i * 37) & 255);
    embedLsb(pixels, ascii(base64(await compress(ascii("flag{vertical_slice}")))));
    const challenge = tamperDimensions(await makePng({ width, height, colorType: 2, bitDepth: 8, pixels }), width, 12);
    const original = challenge.slice();
    const input = bytesFrom(challenge);

    const search = await follow(await step("png.inspect", input), "png.crc.IHDR", input);
    const repaired = await follow(search, "png.dimensions.0", input);
    expect(findings(await step("png.inspect", repaired)).filter((f) => f.severity === "strong")).toEqual([]);

    const extracted = await step("image.lsb", repaired);
    const decoded = await step("decode.auto", extracted);
    const [best] = findings(decoded);
    expect(best.message).toContain("Base64 → zlib");
    expect(best.message).toContain("flag{vertical_slice}");
    expect(new TextDecoder().decode(await bytesOf(await follow(decoded, best.id, extracted)))).toBe("flag{vertical_slice}");
    expect(challenge).toEqual(original);
  });

  it("BMP whose height hides the rows carrying an LSB flag", async () => {
    const [width, height] = [16, 16];
    const rgb = Uint8Array.from({ length: width * height * 3 }, (_, i) => (i * 13) & 255);
    embedLsb(rgb, ascii("flag{hidden_rows}"));
    const full = makeBmp24(width, height, rgb);
    const challenge = bytesFrom(new Uint8Array(await bytesOf(await step("bmp.set-dimensions", bytesFrom(full), { height: 8 }))));

    const visibleBits = new TextDecoder().decode(await bytesOf(await step("image.lsb", challenge)));
    expect(visibleBits).not.toContain("flag{");

    const repaired = await follow(await step("bmp.inspect", challenge), "bmp.extra-rows", challenge);
    expect(await bytesOf(repaired)).toEqual(full);
    const [best] = findings(await step("decode.auto", await step("image.lsb", repaired)));
    expect(best.message).toContain("flag{hidden_rows}");
  });

  it("PNG with gzip-compressed, reversed Base64 appended after IEND", async () => {
    const hidden = await compress(ascii([...base64(ascii("flag{after_iend}"))].reverse().join("")), "gzip");
    const input = bytesFrom(await makePng({ width: 4, height: 4, colorType: 2, bitDepth: 8, pixels: new Uint8Array(48), trailing: hidden }));

    const carved = await follow(await step("png.inspect", input), "png.trailing", input);
    expect(await bytesOf(carved)).toEqual(hidden);
    expect(findings(await step("file.detect", carved))[0].message).toContain("gzip");

    const decoded = await step("decode.auto", carved);
    const [best] = findings(decoded);
    expect(best.message).toContain("gzip → Reverse → Base64");
    expect(new TextDecoder().decode(await bytesOf(await follow(decoded, best.id, carved)))).toBe("flag{after_iend}");
  });
});
