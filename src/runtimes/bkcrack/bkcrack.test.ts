import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { MemorySource } from "../../core/bytes/sources";
import { inspectZip } from "../../formats/zip";
import wasmUrl from "./bkcrack.wasm?inline";
import { setPackFileReader } from "../files";
import { loadBkcrack, prepareBkcrack } from ".";
import type { BkcrackModule } from "./bkcrack.js";

const wasm = Uint8Array.from(atob(wasmUrl.slice(wasmUrl.indexOf(",") + 1)), (character) => character.charCodeAt(0));
setPackFileReader(async (url) => {
  if (url.includes("bkcrack.wasm")) return wasm;
  throw new Error(`No test pack file for ${url}`);
});

describe("bkcrack runtime pack", () => {
  it("recovers the canonical upstream ZipCrypto key vector in its self-test", async () => {
    const module = await loadBkcrack();
    expect(module._bk_self_test()).toBe(1);
  });

  it("prepares and advances a bounded public recovery session", async () => {
    const module = await loadBkcrack();
    const cipher = Uint8Array.from([0x3e, 0xb4, 0xc5, 0x92, 0x58, 0x40, 0x9a, 0x6c, 0xed, 0x99, 0x65, 0x81, 0x66, 0x1b, 0x1d, 0xda, 0x5d, 0x8a, 0x8c, 0x30, 0x07, 0x76, 0x50, 0xbb]);
    const session = prepareBkcrack(module, cipher, new TextEncoder().encode("Hello World!"), 0);
    expect(session.total).toBeGreaterThan(0);
    expect(session.step(1)).toMatch(/running|found/);
    expect(session.cursor()).toBe(1);
    session.reset();
  });

  it("prepares an encrypted stored entry with additional contiguous plaintext", async () => {
    const module = await loadBkcrack();
    const source = new MemorySource(new Uint8Array(readFileSync(new URL("../../formats/testing/offline-pack.zip", import.meta.url))));
    const entry = (await inspectZip(source)).entries[0];
    if (entry.dataOffset === null) throw new Error("Expected a ZipCrypto data offset");
    const cipher = await source.read(entry.dataOffset, entry.compressedSize);
    const full = new TextEncoder().encode("offline-known-plaintext-fixture\n");
    for (const length of [12, 13, 16, 24, 29, 30, 31]) {
      const session = prepareBkcrack(module, cipher, full.subarray(0, length), 0);
      expect(session.total, `known length ${length}`).toBeGreaterThan(0);
      expect(session.step(1)).toMatch(/running|found/);
      session.reset();
    }
  });

  it("frees the first allocation when the second allocation fails", () => {
    const freed: number[] = [];
    const module = {
      writeArrayToMemory: () => undefined,
      _malloc: (() => {
        let calls = 0;
        return () => ++calls === 1 ? 8 : 0;
      })(),
      _free: (pointer: number) => freed.push(pointer),
    } as unknown as BkcrackModule;
    expect(() => prepareBkcrack(module, Uint8Array.of(1), Uint8Array.of(2), 0)).toThrow("could not allocate");
    expect(freed).toEqual([8, 0]);
  });

  it("rejects non-positive native step counts", async () => {
    const module = await loadBkcrack();
    expect(module._bk_step(0)).toBe(-1);
    expect(module.UTF8ToString(module._bk_error())).toBe("step count must be positive");
  });
});