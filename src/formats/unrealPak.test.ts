import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractUnrealPakEntry, inspectUnrealPak, listUnrealPak } from "./unrealPak";

function pak(): Uint8Array<ArrayBuffer> {
  const index = new TextEncoder().encode("bounded-index-vector");
  const bytes = new Uint8Array(index.length + 44);
  bytes.set(index);
  const footer = new DataView(bytes.buffer, index.length, 44);
  footer.setUint32(0, 0x5a6f12e1, true);
  footer.setUint32(4, 3, true);
  footer.setBigUint64(8, 0n, true);
  footer.setBigUint64(16, BigInt(index.length), true);
  bytes.set(createHash("sha1").update(index).digest(), index.length + 24);
  return bytes;
}

function legacyIndex(): Uint8Array<ArrayBuffer> {
  const payload = new TextEncoder().encode("DATA");
  const index = new Uint8Array(4 + 3 + 4 + 4 + 9 + 8 * 3 + 4 + 20 + 1 + 4);
  const view = new DataView(index.buffer);
  let offset = 0;
  view.setInt32(offset, 3, true); offset += 4;
  index.set([0x2e, 0x2f, 0], offset); offset += 3;
  view.setUint32(offset, 1, true); offset += 4;
  view.setInt32(offset, 9, true); offset += 4;
  index.set(new TextEncoder().encode("file.bin\0"), offset); offset += 9;
  view.setBigUint64(offset, 0n, true); offset += 8;
  view.setBigUint64(offset, 4n, true); offset += 8;
  view.setBigUint64(offset, 4n, true); offset += 8;
  view.setUint32(offset, 0, true); offset += 4;
  index.set(createHash("sha1").update(payload).digest(), offset); offset += 20;
  index[offset++] = 0;
  view.setUint32(offset, 0, true);
  const bytes = new Uint8Array(53 + payload.length + index.length + 44);
  const local = new DataView(bytes.buffer);
  local.setBigUint64(8, 4n, true);
  local.setBigUint64(16, 4n, true);
  bytes.set(createHash("sha1").update(payload).digest(), 28);
  bytes.set(payload, 53);
  bytes.set(index, 53 + payload.length);
  const footer = new DataView(bytes.buffer, 53 + payload.length + index.length, 44);
  footer.setUint32(0, 0x5a6f12e1, true);
  footer.setUint32(4, 3, true);
  footer.setBigUint64(8, BigInt(53 + payload.length), true);
  footer.setBigUint64(16, BigInt(index.length), true);
  bytes.set(createHash("sha1").update(index).digest(), 53 + payload.length + index.length + 24);
  return bytes;
}

describe("legacy Unreal PAK footer inspection", () => {
  it("verifies a bounded index digest without decoding or executing assets", async () => {
    const data = bytesValue(new MemorySource(pak()));
    expect(await inspectUnrealPak(data.source)).toMatchObject({ version: 3, indexOffset: 0, indexBytes: 20,
      indexSha1Verified: true, indexDecoded: false });
    const result = await executeOperation(createDefaultRegistry(), { operationId: "reverse.unreal-pak.inspect", inputs: { data }, params: {} });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { version: 3, indexSha1Verified: true } });
  });

  it("rejects damaged digest, invalid extents and unsupported footer versions", async () => {
    const digest = pak(); digest[digest.length - 1] ^= 1;
    await expect(inspectUnrealPak(new MemorySource(digest))).rejects.toThrow(/SHA-1 mismatch/);
    const extent = pak(); new DataView(extent.buffer, extent.length - 44).setBigUint64(16, 1000n, true);
    await expect(inspectUnrealPak(new MemorySource(extent))).rejects.toThrow(/extent/);
    const version = pak(); new DataView(version.buffer, version.length - 44).setUint32(4, 9, true);
    await expect(inspectUnrealPak(new MemorySource(version))).rejects.toThrow(/different footer parser/);
  });

  it("lists and verifies an uncompressed legacy PAK entry", async () => {
    const source = new MemorySource(legacyIndex());
    expect(await listUnrealPak(source)).toMatchObject({ mountPoint: "./", indexSha1Verified: true,
      entries: [{ path: "file.bin", offset: 0, dataOffset: 53, bytes: 4 }] });
    expect(new TextDecoder().decode(await readAll(await extractUnrealPakEntry(source, "file.bin")))).toBe("DATA");
    const result = await executeOperation(createDefaultRegistry(), { operationId: "reverse.unreal-pak.extract",
      inputs: { data: bytesValue(source) }, params: { path: "file.bin" } });
    expect(result.run.status).toBe("success");
    const damaged = legacyIndex(); damaged[53] ^= 1;
    await expect(extractUnrealPakEntry(new MemorySource(damaged), "file.bin")).rejects.toThrow(/SHA-1 mismatch/);
    const badLocal = legacyIndex(); badLocal[8] ^= 1;
    await expect(extractUnrealPakEntry(new MemorySource(badLocal), "file.bin")).rejects.toThrow(/local entry disagrees/);
  });
});
