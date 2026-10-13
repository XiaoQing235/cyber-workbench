import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MemorySource } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { inspectAuxinPayload, inspectAuxinRom } from "./uxnAuxin";

const HEALTHCHECK = "efef3921212fefefefa5a5a53a3a3a3a3a3a3a3a840494cfcf1a01190505152194cfcfcf8484011a011a1a1a011a1a0da528058509442babd41d99850a1d0a0a1a85adbcd41dbcd41d3c090999851d1c85158509241d992504f50505050505056b71616c";

describe("Google CTF 2024 Auxin2 static constraints", () => {
  it("checks original licensed ROM identity and independently published healthcheck bytes", async () => {
    const rom = new Uint8Array(readFileSync(new URL("./testing/google-ctf-2024-auxin2.rom", import.meta.url)));
    expect(createHash("sha1").update(`blob ${rom.length}\0`).update(rom).digest("hex"))
      .toBe("24b36d8c300b55eda14d3d53535a1c7cee048a41");
    expect(await inspectAuxinRom(new MemorySource(rom))).toEqual({ romBytes: 208,
      shellcodeAddress: "0x01d0", forbiddenLowNibbles: [0, 2, 3, 6, 7, 14], executingRom: false });
    expect(createHash("sha256").update(Buffer.from(HEALTHCHECK, "hex")).digest("hex"))
      .toBe("2aca9e138c9d4a81f123b64c8470222d2c7fbe823e897c5aad124309cf111846");
    expect(inspectAuxinPayload(HEALTHCHECK)).toEqual({ bytes: 100, bannedOffsets: [], acceptedByStaticFilter: true, executed: false });
    const run = await executeOperation(createDefaultRegistry(), { operationId: "reverse.uxn.auxin2",
      inputs: { data: bytesValue(new MemorySource(rom)) }, params: { payloadHex: HEALTHCHECK } });
    expect(run.outputs.report).toMatchObject({ type: "structured", data: { rom: { executingRom: false }, payload: {
      bytes: 100, acceptedByStaticFilter: true, executed: false,
    } } });
    expect(inspectAuxinPayload("10ef13")).toMatchObject({ bannedOffsets: [0, 2], acceptedByStaticFilter: false });
    expect(() => inspectAuxinPayload("EF")).toThrow(/lowercase/);
    expect(() => inspectAuxinPayload("a")).toThrow(/even-length/);
    expect(() => inspectAuxinPayload("a1".repeat(113))).toThrow(/112 bytes/);
    const changedMask = rom.slice(); changedMask[0x6b] ^= 1;
    await expect(inspectAuxinRom(new MemorySource(changedMask))).rejects.toThrow(/low-nibble mask/);
    const changed = rom.slice(); changed[0x6f] ^= 1;
    await expect(inspectAuxinRom(new MemorySource(changed))).rejects.toThrow(/forbidden-low-nibble/);
    const changedBranch = rom.slice(); changedBranch[0x73] ^= 1;
    await expect(inspectAuxinRom(new MemorySource(changedBranch))).rejects.toThrow(/forbidden-low-nibble/);
  });
});
