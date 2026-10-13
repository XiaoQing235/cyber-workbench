import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import type { ByteSource } from "../core/bytes/ByteSource";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesFrom } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { decodeRegistryValue, extractRegistryValue, inspectRegistryHive } from "./registryHive";
import { importWindowsTimeline } from "./windowsTimeline";

function hive(): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(8192);
  const view = new DataView(bytes.buffer);
  const ascii = (offset: number, value: string) => bytes.set(new TextEncoder().encode(value), offset);
  ascii(0, "regf");
  view.setUint32(0x24, 32, true);
  view.setUint32(0x28, 4096, true);
  ascii(4096, "hbin");
  view.setUint32(4096 + 8, 4096, true);
  const cell = (relative: number, payload: number) => view.setInt32(4096 + relative, -(payload + 4), true);
  const root = 4096 + 32 + 4;
  const child = 4096 + 136 + 4;
  cell(32, 100); // 104-byte root cell, padded to eight bytes
  ascii(root, "nk");
  view.setUint16(root + 2, 0x20, true);
  view.setBigUint64(root + 4, 133801632000000000n, true); // 2025-01-01 UTC
  view.setUint32(root + 0x14, 1, true);
  view.setUint32(root + 0x1c, 240, true);
  view.setUint32(root + 0x24, 2, true);
  view.setUint32(root + 0x28, 256, true);
  view.setUint16(root + 0x48, 4, true);
  ascii(root + 0x4c, "ROOT");
  cell(136, 100);
  ascii(child, "nk");
  view.setUint16(child + 2, 0x20, true);
  view.setBigUint64(child + 4, 133802496000000000n, true); // 2025-01-02 UTC
  view.setUint16(child + 0x48, 5, true);
  ascii(child + 0x4c, "Child");
  cell(240, 12);
  ascii(4096 + 244, "li");
  view.setUint16(4096 + 246, 1, true);
  view.setUint32(4096 + 248, 136, true);
  cell(256, 12);
  view.setUint32(4096 + 260, 272, true);
  view.setUint32(4096 + 264, 304, true);
  for (const [relative, label, data] of [[272, "Mode", 0x41424344], [304, "", 0x12345678]] as const) {
    cell(relative, 28);
    const offset = 4096 + relative + 4;
    ascii(offset, "vk");
    view.setUint16(offset + 2, label.length, true);
    view.setUint32(offset + 4, 0x80000004, true);
    view.setUint32(offset + 8, data, true);
    view.setUint32(offset + 12, 4, true);
    view.setUint16(offset + 16, 1, true);
    ascii(offset + 20, label);
  }
  let checksum = 0;
  for (let offset = 0; offset < 0x1fc; offset += 4) checksum ^= view.getUint32(offset, true);
  view.setUint32(0x1fc, checksum, true);
  return bytes;
}

describe("bounded offline registry hive inspection", () => {
  it("inspects original Plaso NTUSER-RunTests.DAT cells without synthesizing metadata", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/plaso-ntuser-runtests.dat", import.meta.url)));
    expect(createHash("sha1").update(`blob ${bytes.length}\0`).update(bytes).digest("hex"))
      .toBe("a7e65e13b7dd760d98472182685a12b26ad9cfa7");
    const report = await inspectRegistryHive(new MemorySource(bytes));
    expect(report.headerChecksumValid).toBe(true);
    expect(report).toMatchObject({ hiveBytes: 262144, root: { path: expect.any(String) }, synchronized: true });
    expect(report.root.path).not.toBe("");
    expect(report.children.length).toBeGreaterThan(0);
    const child = report.children[0].path;
    expect((await inspectRegistryHive(new MemorySource(bytes), child)).selected.path).toBe(child);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.registry.inspect",
      inputs: { data: bytesFrom(bytes) }, params: { keyPath: child } });
    expect(operation.run.status).toBe("success");
  });
  it("reads key last-write metadata and navigates named subkeys without loading the hive", async () => {
    const bytes = hive();
    expect(new DataView(bytes.buffer).getBigUint64(4096 + 32 + 4 + 4, true)).toBe(133801632000000000n);
    let readBytes = 0;
    const source: ByteSource = {
      size: 200 * 1024 * 1024,
      async read(offset, length) { readBytes += length; return offset < bytes.length ? bytes.slice(offset, offset + length) : new Uint8Array(length); },
      stream() { throw new Error("Inspector must not stream the full hive"); },
    };
    const root = await inspectRegistryHive(source);
    expect(root).toMatchObject({ headerChecksumValid: true, root: { path: "ROOT", subkeyCount: 1, valueCount: 2 },
      synchronized: true, primarySequence: 0, secondarySequence: 0,
      selected: { path: "ROOT", lastWrite: { utc: "2025-01-01T00:00:00.000000Z" } },
      children: [{ path: "ROOT\\Child", lastWrite: { utc: "2025-01-02T00:00:00.000000Z" } }],
      values: [{ name: "Mode", type: 4, bytes: 4, inline: true }, { name: "", type: 4, bytes: 4, inline: true }] });
    expect((await inspectRegistryHive(new MemorySource(bytes), "root\\cHiLd")).selected.path).toBe("ROOT\\Child");
    expect(readBytes).toBeLessThan(5100);
  });

  it("follows allocated cells in a second hbin and rejects cross-bin cells", async () => {
    const first = hive();
    const bytes = new Uint8Array(12288);
    bytes.set(first);
    const view = new DataView(bytes.buffer);
    view.setUint32(0x28, 8192, true);
    bytes.set(new TextEncoder().encode("hbin"), 8192);
    view.setUint32(8192 + 4, 4096, true);
    view.setUint32(8192 + 8, 4096, true);
    // Move a standalone child nk cell to the next bin, keeping the first-bin subkey list.
    bytes.copyWithin(8192 + 32, 4096 + 136, 4096 + 240);
    view.setUint32(4096 + 248, 4096 + 32, true);
    let checksum = 0;
    for (let offset = 0; offset < 0x1fc; offset += 4) checksum ^= view.getUint32(offset, true);
    view.setUint32(0x1fc, checksum, true);
    expect((await inspectRegistryHive(new MemorySource(bytes))).children[0].path).toBe("ROOT\\Child");
    view.setInt32(8192 + 32, -4096, true);
    await expect(inspectRegistryHive(new MemorySource(bytes))).rejects.toThrow(/extent/);
  });

  it("extracts explicit inline registry values without returning other cells", async () => {
    const source = new MemorySource(hive());
    expect(await readAll(await extractRegistryValue(source, "ROOT", "mode"))).toEqual(Uint8Array.of(0x44, 0x43, 0x42, 0x41));
    expect(await readAll(await extractRegistryValue(source, "", ""))).toEqual(Uint8Array.of(0x78, 0x56, 0x34, 0x12));
    await expect(extractRegistryValue(source, "ROOT", "missing")).rejects.toThrow(/not present/);
    const result = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.registry.value-extract",
      inputs: { data: bytesFrom(hive()) }, params: { keyPath: "", valueName: "Mode" } });
    expect(result.run.status).toBe("success");
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected registry bytes");
    expect(await readAll(result.outputs.data.source)).toEqual(Uint8Array.of(0x44, 0x43, 0x42, 0x41));
  });

  it("reads one- and two-byte inline data from the end of the four-byte field", async () => {
    const bytes = hive();
    const view = new DataView(bytes.buffer);
    const vk = 4096 + 272 + 4;
    view.setUint32(vk + 8, 0x44332211, true);
    view.setUint32(vk + 4, 0x80000001, true);
    expect(await readAll(await extractRegistryValue(new MemorySource(bytes), "", "Mode"))).toEqual(Uint8Array.of(0x44));
    view.setUint32(vk + 4, 0x80000002, true);
    expect(await readAll(await extractRegistryValue(new MemorySource(bytes), "", "Mode"))).toEqual(Uint8Array.of(0x33, 0x44));
    view.setUint32(vk + 4, 0x80000004, true);
    expect(await readAll(await extractRegistryValue(new MemorySource(bytes), "", "Mode"))).toEqual(Uint8Array.of(0x11, 0x22, 0x33, 0x44));
  });

  it("exposes non-inline value bytes lazily and rejects a truncated data cell", async () => {
    const bytes = hive();
    const view = new DataView(bytes.buffer);
    const vk = 4096 + 272 + 4;
    view.setUint32(vk + 4, 5, true);
    view.setUint32(vk + 8, 336, true);
    view.setInt32(4096 + 336, -16, true);
    bytes.set([1, 2, 3, 4, 5], 4096 + 340);
    expect(await readAll(await extractRegistryValue(new MemorySource(bytes), "", "Mode"))).toEqual(Uint8Array.of(1, 2, 3, 4, 5));
    view.setInt32(4096 + 336, -8, true);
    await expect(extractRegistryValue(new MemorySource(bytes), "", "Mode")).rejects.toThrow(/truncated/);
    view.setInt32(4096 + 336, -0x7ffffff8, true);
    await expect(extractRegistryValue(new MemorySource(bytes), "", "Mode")).rejects.toThrow(/invalid/);
  });

  it("decodes selected REG_DWORD and terminated REG_SZ without guessing other types", async () => {
    const bytes = hive();
    expect(await decodeRegistryValue(new MemorySource(bytes), "", "Mode")).toEqual({ name: "Mode", type: "REG_DWORD", value: 0x41424344, bytes: 4 });
    const view = new DataView(bytes.buffer);
    const second = 4096 + 304 + 4;
    view.setUint32(second + 12, 1, true);
    view.setUint32(second + 8, 360, true);
    view.setUint32(second + 4, 8, true);
    view.setInt32(4096 + 360, -16, true);
    bytes.set(new TextEncoder().encode("H\0i\0!\0\0\0"), 4096 + 364);
    expect(await decodeRegistryValue(new MemorySource(bytes), "", "")).toEqual({ name: "", type: "REG_SZ", value: "Hi!", bytes: 8 });
    view.setUint32(second + 12, 7, true);
    await expect(decodeRegistryValue(new MemorySource(bytes), "", "")).rejects.toThrow(/supports REG_SZ and REG_DWORD/);
    const run = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.registry.value-decode",
      inputs: { data: bytesFrom(hive()) }, params: { keyPath: "", valueName: "Mode" } });
    expect(run.outputs.report).toMatchObject({ type: "structured", data: { type: "REG_DWORD", value: 0x41424344 } });
  });

  it("rejects damaged checksum, truncated cells and bad list pointers", async () => {
    const badHeader = hive(); badHeader[0x1fc] ^= 1;
    await expect(inspectRegistryHive(new MemorySource(badHeader))).rejects.toThrow(/checksum/);
    const badCell = hive(); new DataView(badCell.buffer).setInt32(4096 + 32, -4096, true);
    await expect(inspectRegistryHive(new MemorySource(badCell))).rejects.toThrow(/extent/);
    const badList = hive(); new DataView(badList.buffer).setUint32(4096 + 32 + 4 + 0x1c, 0xffffffff, true);
    await expect(inspectRegistryHive(new MemorySource(badList))).rejects.toThrow(/cell offset/);
    await expect(inspectRegistryHive(new MemorySource(hive()), "ROOT\\..")).rejects.toThrow(/path/);
    const unsupportedBin = hive(); new DataView(unsupportedBin.buffer).setUint32(4096 + 8, 0, true);
    await expect(inspectRegistryHive(new MemorySource(unsupportedBin))).rejects.toThrow(/hbin/);
  });

  it("reports a dirty hive sequence mismatch rather than claiming synchronized state", async () => {
    const bytes = hive();
    const view = new DataView(bytes.buffer);
    view.setUint32(4, 5, true);
    view.setUint32(8, 4, true);
    let checksum = 0;
    for (let offset = 0; offset < 0x1fc; offset += 4) checksum ^= view.getUint32(offset, true);
    view.setUint32(0x1fc, checksum, true);
    expect(await inspectRegistryHive(new MemorySource(bytes))).toMatchObject({ primarySequence: 5, secondarySequence: 4, synchronized: false });
    const result = await executeOperation(createDefaultRegistry(), { operationId: "forensics.windows.registry.inspect",
      inputs: { data: bytesFrom(bytes) }, params: {} });
    expect(result.run.diagnostics).toContain("Registry header sequence numbers disagree; transaction logs may be needed for current state.");
  });

  it("exports last writes through the registry into the shared timeline", async () => {
    const data = bytesFrom(hive());
    const registry = createDefaultRegistry();
    const inspected = await executeOperation(registry, { operationId: "forensics.windows.registry.inspect", inputs: { data }, params: {} });
    expect(inspected.run.status).toBe("success");
    const exported = await executeOperation(registry, { operationId: "forensics.windows.registry.timeline-export", inputs: { data }, params: { hostname: "LAB" } });
    expect(exported.run.status).toBe("success");
    if (exported.outputs.text?.type !== "text") throw new Error("Expected JSONL text");
    const timeline = await importWindowsTimeline(exported.outputs.text.text, "plaso-jsonl", 0, 60);
    expect(timeline.events.map((event) => event.artifact)).toEqual(["ROOT", "ROOT\\Child"]);
  });
});
