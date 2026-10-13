import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { readZip, zipEntryData } from "../core/archive/zip";
import { decodePng } from "./png/decode";
import { parsePng } from "./png/parse";
import { improveSharedPermutation, replayPixelPermutation } from "./pixelPermutation";

const original = new Uint8Array(readFileSync(new URL("./testing/google-ctf-2024-otp-pair.zip", import.meta.url)));

describe("Google CTF 2024 shared pixel permutation", () => {
  it("replays the source-published recovered map to reproduce every original challenge pixel", async () => {
    const encryptedBytes = new Uint8Array(readFileSync(new URL("./testing/google-ctf-2024-otp-2nd00.png", import.meta.url)));
    const referenceBytes = new Uint8Array(readFileSync(new URL("./testing/google-ctf-2024-otp-source-recovered-2nd00.png", import.meta.url)));
    const keyBytes = readFileSync(new URL("./testing/google-ctf-2024-otp-source-recovered.key", import.meta.url));
    const gitBlob = (data: Uint8Array) => createHash("sha1").update(`blob ${data.length}\0`).update(data).digest("hex");
    expect(gitBlob(encryptedBytes)).toBe("fa833e5853e39d403d3aa50c340b63f6e7f9e3d5");
    expect(gitBlob(referenceBytes)).toBe("6b3f6308a1c0e1390f47a2483dff110a700d765f");
    expect(gitBlob(keyBytes)).toBe("bd06a25c98cbc8bb33972ff8a0ee0597ba906604");
    const key = keyBytes.toString("utf8");
    const encrypted = new MemorySource(encryptedBytes);
    const reference = new MemorySource(referenceBytes);
    const expected = (await decodePng(reference, await parsePng(reference))).image.samples;
    const replayed = await replayPixelPermutation(encrypted, key);
    const actual = (await decodePng(new MemorySource(replayed.png), await parsePng(new MemorySource(replayed.png)))).image.samples;
    expect(actual).toEqual(expected);
    const restored = await replayPixelPermutation(new MemorySource(replayed.png), key, undefined, true);
    const original = (await decodePng(encrypted, await parsePng(encrypted))).image.samples;
    expect((await decodePng(new MemorySource(restored.png), await parsePng(new MemorySource(restored.png)))).image.samples).toEqual(original);
    const swapped = JSON.parse(key) as number[];
    [swapped[0], swapped[1]] = [swapped[1], swapped[0]];
    const altered = await replayPixelPermutation(encrypted, JSON.stringify(swapped));
    expect((await decodePng(new MemorySource(altered.png), await parsePng(new MemorySource(altered.png)))).image.samples).not.toEqual(expected);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "image.permutation.replay",
      inputs: { data: bytesFrom(encryptedBytes) }, params: { mapping: key } });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: { mapVerified: true, flagRecovered: false } });
    if (operation.outputs.image?.type !== "bytes") throw new Error("Expected replayed PNG");
    expect((await decodePng(operation.outputs.image.source, await parsePng(operation.outputs.image.source))).image.samples).toEqual(expected);
  });
  it("reduces independently measured color-neighbor error on two real challenge images", async () => {
    const { png, map, report } = await improveSharedPermutation(new MemorySource(original), 20261012, 2_000);
    expect(report).toMatchObject({ width: 64, height: 64, images: ["google-ctf-2024-otp-2nd00.png", "google-ctf-2024-otp-2nd01.png"],
      selectedImage: "google-ctf-2024-otp-2nd00.png", initialScore: 323_017_296, seed: 20261012, iterations: 2_000, flagRecovered: false });
    expect(report.accepted).toBeGreaterThan(0);
    expect(report.finalScore).toBeLessThan(report.initialScore - 20_000_000);
    expect(new Set(map).size).toBe(4096);
    const firstOriginal = new MemorySource(new Uint8Array(readFileSync(new URL("./testing/google-ctf-2024-otp-2nd00.png", import.meta.url))));
    expect((await replayPixelPermutation(firstOriginal, JSON.stringify(map), undefined, true)).png).toEqual(png);
    const restored = await replayPixelPermutation(new MemorySource(png), JSON.stringify(map));
    const before = await decodePng(firstOriginal, await parsePng(firstOriginal));
    const restoredSource = new MemorySource(restored.png);
    expect((await decodePng(restoredSource, await parsePng(restoredSource))).image).toEqual(before.image);
    const parsed = new MemorySource(png);
    expect((await decodePng(parsed, await parsePng(parsed))).image).toMatchObject({ width: 64, height: 64 });
    const result = await executeOperation(createDefaultRegistry(), { operationId: "image.permutation.improve",
      inputs: { data: bytesFrom(original) }, params: { seed: 20261012, iterations: 2_000 } });
    expect(result.run.error).toBeUndefined();
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { finalScore: report.finalScore, flagRecovered: false } });
    expect(result.outputs.mapping).toMatchObject({ type: "text", text: JSON.stringify(map) });
    if (result.outputs.image?.type !== "bytes") throw new Error("Expected candidate PNG");
    expect(await readAll(result.outputs.image.source)).toEqual(png);
  });

  it("runs bounded shared swaps on 24 original challenge PNGs without claiming full recovery", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/google-ctf-2024-otp-24.zip", import.meta.url)));
    const entries = await readZip(new Blob([bytes]));
    expect(entries.map((entry) => entry.name)).toEqual(Array.from({ length: 24 }, (_, i) => `2nd${String(i).padStart(2, "0")}.png`));
    const first = new Uint8Array(await (await zipEntryData(entries[0], 64 * 1024)).arrayBuffer());
    expect(createHash("sha1").update(`blob ${first.length}\0`).update(first).digest("hex"))
      .toBe("fa833e5853e39d403d3aa50c340b63f6e7f9e3d5");
    const { png, map, report } = await improveSharedPermutation(new MemorySource(bytes), 20261012, 2_000);
    expect(report).toMatchObject({ iterations: 2_000, flagRecovered: false });
    expect(report.images).toHaveLength(24);
    expect(report.selectedImage).toBe("2nd00.png");
    expect(report.finalScore).toBeLessThan(report.initialScore);
    expect(new Set(map).size).toBe(4096);
    const second = new MemorySource(new Uint8Array(await (await zipEntryData(entries[1], 64 * 1024)).arrayBuffer()));
    const replayedSecond = await replayPixelPermutation(second, JSON.stringify(map), undefined, true);
    const inverse = await replayPixelPermutation(new MemorySource(replayedSecond.png), JSON.stringify(map));
    expect((await decodePng(new MemorySource(inverse.png), await parsePng(new MemorySource(inverse.png)))).image)
      .toEqual((await decodePng(second, await parsePng(second))).image);
    const decoded = await decodePng(new MemorySource(png), await parsePng(new MemorySource(png)));
    expect(decoded.image).toMatchObject({ width: 64, height: 64 });
    const registered = await executeOperation(createDefaultRegistry(), { operationId: "image.permutation.improve",
      inputs: { data: bytesFrom(bytes) }, params: { seed: 20261012, iterations: 2_000 } });
    expect(registered.outputs.report).toMatchObject({ type: "structured", data: { images: report.images, finalScore: report.finalScore, flagRecovered: false } });
    expect(registered.outputs.mapping).toMatchObject({ type: "text", text: JSON.stringify(map) });
    const chosen = await improveSharedPermutation(new MemorySource(bytes), 20261012, 2_000, undefined, 1);
    expect(chosen.report).toMatchObject({ selectedImage: "2nd01.png", initialScore: report.initialScore, finalScore: report.finalScore });
    expect(chosen.map).toEqual(map);
    expect(chosen.png).toEqual(replayedSecond.png);
    const selectedOperation = await executeOperation(createDefaultRegistry(), { operationId: "image.permutation.improve",
      inputs: { data: bytesFrom(bytes) }, params: { seed: 20261012, iterations: 2_000, imageIndex: 1 } });
    expect(selectedOperation.outputs.report).toMatchObject({ type: "structured", data: { selectedImage: "2nd01.png" } });
    await expect(improveSharedPermutation(new MemorySource(bytes), 0, 1, undefined, 24)).rejects.toThrow(/outside the ZIP/);
  });

  it("measures the full bounded swap budget on the original 24-image package", { timeout: 60_000 }, async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/google-ctf-2024-otp-24.zip", import.meta.url)));
    const result = await improveSharedPermutation(new MemorySource(bytes), 20261012, 100_000);
    expect(result.report).toMatchObject({ iterations: 100_000, flagRecovered: false });
    expect(result.report.finalScore).toBeLessThan(result.report.initialScore);
    expect(result.report.finalScore).toBe(2_384_008_426);
    expect(new Set(result.map).size).toBe(4096);
  });

  it("accepts all 64 original second-round encrypted images within the offline archive budget", { timeout: 60_000 }, async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/google-ctf-2024-otp-64.zip", import.meta.url)));
    expect(bytes.length).toBe(872_804);
    const entries = await readZip(new Blob([bytes]));
    expect(entries.map((entry) => entry.name)).toEqual(Array.from({ length: 64 }, (_, index) => `2nd${String(index).padStart(2, "0")}.png`));
    const first = await improveSharedPermutation(new MemorySource(bytes), 20261012, 1_000);
    expect(first.report).toMatchObject({ iterations: 1_000, selectedImage: "2nd00.png", flagRecovered: false });
    expect(first.report.images).toHaveLength(64);
    expect(first.report.finalScore).toBeLessThan(first.report.initialScore);
    const resumed = await improveSharedPermutation(new MemorySource(bytes), 20261012, 1_000, undefined, 63, JSON.stringify(first.map), 1_000);
    const continuous = await improveSharedPermutation(new MemorySource(bytes), 20261012, 2_000, undefined, 63);
    expect(resumed.report).toMatchObject({ selectedImage: "2nd63.png", finalScore: continuous.report.finalScore });
    expect(resumed.map).toEqual(continuous.map);
    expect(resumed.png).toEqual(continuous.png);
    const larger = await improveSharedPermutation(new MemorySource(bytes), 20261012, 100_000);
    expect(larger.report).toMatchObject({ iterations: 100_000, selectedImage: "2nd00.png", flagRecovered: false });
    expect(larger.report.finalScore).toBeLessThan(first.report.finalScore);
    const oracle = JSON.parse(readFileSync(new URL("./testing/google-ctf-2024-otp-source-recovered.key", import.meta.url), "utf8")) as number[];
    expect(oracle).toHaveLength(4096);
    expect(larger.map.filter((position, index) => position === oracle[index])).toHaveLength(0);
    expect(oracle.filter((position, index) => position === index)).toHaveLength(1);
  });

  it("reproduces a continuous seeded run by resuming from a candidate map and prior attempt count", async () => {
    const bytes = new MemorySource(original);
    const first = await improveSharedPermutation(bytes, 20261012, 1_000);
    const resumed = await improveSharedPermutation(bytes, 20261012, 1_000, undefined, 1, JSON.stringify(first.map), 1_000);
    const continuous = await improveSharedPermutation(bytes, 20261012, 2_000, undefined, 1);
    expect(resumed.map).toEqual(continuous.map);
    expect(resumed.png).toEqual(continuous.png);
    expect(resumed.report.finalScore).toBe(continuous.report.finalScore);
    expect(resumed.report.initialScore).toBe(first.report.finalScore);
    const registered = await executeOperation(createDefaultRegistry(), { operationId: "image.permutation.improve",
      inputs: { data: bytesFrom(original) }, params: { seed: 20261012, iterations: 1_000, imageIndex: 1,
        resumeMap: JSON.stringify(first.map), previousIterations: 1_000 } });
    expect(registered.outputs.mapping).toMatchObject({ type: "text", text: JSON.stringify(continuous.map) });
    const fullBytes = new MemorySource(new Uint8Array(readFileSync(new URL("./testing/google-ctf-2024-otp-24.zip", import.meta.url))));
    const fullFirst = await improveSharedPermutation(fullBytes, 20261012, 1_000);
    const fullNext = await improveSharedPermutation(fullBytes, 20261012, 1_000, undefined, 1, JSON.stringify(fullFirst.map), 1_000);
    const fullContinuous = await improveSharedPermutation(fullBytes, 20261012, 2_000, undefined, 1);
    expect(fullNext.map).toEqual(fullContinuous.map);
    expect(fullNext.png).toEqual(fullContinuous.png);
    await expect(improveSharedPermutation(bytes, 20261012, 1, undefined, 0, "", 1)).rejects.toThrow(/supplied together/);
    await expect(improveSharedPermutation(bytes, 20261012, 1, undefined, 0, JSON.stringify(new Array(4096).fill(0)), 1))
      .rejects.toThrow(/exactly once/);
    await expect(improveSharedPermutation(bytes, 20261012, 2, undefined, 0, JSON.stringify(first.map), 9_999_999))
      .rejects.toThrow(/ten million/);
  });

  it("allows cancellation to interrupt a long full-image search between swap batches", { timeout: 60_000 }, async () => {
    const bytes = new MemorySource(new Uint8Array(readFileSync(new URL("./testing/google-ctf-2024-otp-64.zip", import.meta.url))));
    const controller = new AbortController();
    const promise = improveSharedPermutation(bytes, 20261012, 100_000, controller.signal);
    setTimeout(() => controller.abort(new Error("stopped")), 20);
    await expect(promise).rejects.toThrow(/stopped/);
  });

  it("rejects a mismatched image count or malformed archive without guessing a permutation", async () => {
    await expect(improveSharedPermutation(new MemorySource(original), 20261012, 0)).rejects.toThrow(/iteration budget/);
    await expect(improveSharedPermutation(new MemorySource(original.subarray(0, 90)), 20261012, 100)).rejects.toThrow(/ZIP archive/);
  });

  it("replays a known pixel-position map on an original licensed challenge PNG", async () => {
    const input = new MemorySource(new Uint8Array(readFileSync(new URL("./testing/google-ctf-2024-otp-2nd00.png", import.meta.url))));
    const positions = Array.from({ length: 4096 }, (_, index) => index);
    const identity = await replayPixelPermutation(input, JSON.stringify(positions));
    const before = await decodePng(input, await parsePng(input));
    const afterSource = new MemorySource(identity.png);
    const after = await decodePng(afterSource, await parsePng(afterSource));
    expect(after.image).toMatchObject({ width: 64, height: 64 });
    expect(after.image).toEqual(before.image);
    [positions[0], positions[1]] = [positions[1], positions[0]];
    const swapped = await replayPixelPermutation(input, JSON.stringify(positions));
    expect(swapped.png).not.toEqual(identity.png);
    const restored = await replayPixelPermutation(new MemorySource(swapped.png), JSON.stringify(positions), undefined, true);
    const restoredSource = new MemorySource(restored.png);
    expect((await decodePng(restoredSource, await parsePng(restoredSource))).image).toEqual(before.image);
    const result = await executeOperation(createDefaultRegistry(), { operationId: "image.permutation.replay",
      inputs: { data: bytesFrom(await readAll(input)) }, params: { mapping: JSON.stringify(positions) } });
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { pixels: 4096, mapVerified: true, flagRecovered: false } });
    const invalid = positions.slice(); invalid[0] = invalid[1];
    await expect(replayPixelPermutation(input, JSON.stringify(invalid))).rejects.toThrow(/exactly once/);
  });
});
