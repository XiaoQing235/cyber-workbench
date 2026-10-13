import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { decodePng } from "./png/decode";
import { encodeRgbaPng } from "./png/encode";
import { parsePng } from "./png/parse";
import { decodeSymatrix } from "./symatrix";

describe("Google CTF Symatrix mirrored steganography", () => {
  it("recovers the original challenge message from its licensed PNG", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/google-ctf-2023-symatrix.png", import.meta.url)));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("72cac9a514a475e1be32864a1a31bf0115cbccbe");
    const expected = { candidate: "CTF{W4ke_Up_Ne0+Th1s_I5_Th3_Fl4g!}", bits: 272,
      differingPairs: 272, width: 1546, height: 1020, verifiedFlag: false };
    expect(await decodeSymatrix(new MemorySource(bytes))).toEqual(expected);
    const run = await executeOperation(createDefaultRegistry(), { operationId: "image.symatrix.decode",
      inputs: { data: bytesValue(new MemorySource(bytes)) }, params: {} });
    expect(run.outputs.report).toMatchObject({ type: "structured", data: expected });
    const corrupt = bytes.slice(); corrupt[corrupt.length - 8] ^= 1;
    await expect(decodeSymatrix(new MemorySource(corrupt))).rejects.toThrow(/CRC-valid/);
    await expect(decodeSymatrix(new MemorySource(bytes.subarray(0, bytes.length - 1)))).rejects.toThrow();
    const source = new MemorySource(bytes);
    const parsed = await parsePng(source);
    const image = (await decodePng(source, parsed)).image;
    const channels = image.channels.length;
    const changed = new Uint8Array(image.width * image.height * 4);
    for (let pixel = 0; pixel < image.width * image.height; pixel++) {
      changed.set(image.samples.subarray(pixel * channels, pixel * channels + 3), pixel * 4);
      changed[pixel * 4 + 3] = channels === 4 ? image.samples[pixel * channels + 3] : 255;
    }
    let pair = -1;
    for (let x = 0; x < image.width / 2; x++) {
      const left = x * 4, right = (image.width - 1 - x) * 4;
      if (changed[left + 2] === changed[right + 2] && changed[left + 2] < 253) { pair = x; break; }
    }
    expect(pair).toBeGreaterThanOrEqual(0);
    changed[(image.width - 1 - pair) * 4 + 2] = changed[pair * 4 + 2] + 2;
    const invalidBit = await encodeRgbaPng(image.width, image.height, changed);
    await expect(decodeSymatrix(new MemorySource(invalidBit))).rejects.toThrow(/not a binary digit/);
  });
});
