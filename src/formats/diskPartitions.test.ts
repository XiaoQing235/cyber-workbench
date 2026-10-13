import { describe, expect, it } from "vitest";
import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { ConcatSource, MemorySource, MissingSource } from "../core/bytes/sources";
import { crc32 } from "../core/checksum/crc32";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { inspectDiskPartitions } from "./diskPartitions";

const HEADER = Uint8Array.from(atob("RUZJIFBBUlQAAAEAXAAAAAJbNTQAAAAAAQAAAAAAAAD/fwAAAAAAACIAAAAAAAAA3n8AAAAAAAAThCwvI0yYQKlLybeZDgevAgAAAAAAAACAAAAAgAAAAHX3Zuw="), (character) => character.charCodeAt(0));
const FIRST_ENTRY = new Uint8Array(128);
FIRST_ENTRY.set(Uint8Array.from("a2a0d0ebe5b9334487c068b6b72699c7ed39fc43cfe486458278fce89b8b1bc80008000000000000ff0f00000000000000000000000000004400410054004100".match(/../g)!, (pair) => Number.parseInt(pair, 16)));

function gpt(): ConcatSource {
  const leading = new Uint8Array(34 * 512);
  const mbr = new DataView(leading.buffer);
  leading[446 + 4] = 0xee;
  mbr.setUint32(446 + 8, 1, true);
  mbr.setUint32(446 + 12, 32767, true);
  leading[510] = 0x55;
  leading[511] = 0xaa;
  leading.set(HEADER, 512);
  leading.set(FIRST_ENTRY, 1024);
  return new ConcatSource([new MemorySource(leading), new MissingSource(16 * 1024 * 1024 - leading.length)]);
}

function imageWithPrefix(prefix: Bytes): ConcatSource {
  return new ConcatSource([new MemorySource(prefix), new MissingSource(16 * 1024 * 1024 - prefix.length)]);
}

function alterHeader(change: (view: DataView) => void): ConcatSource {
  const prefix = (gpt().parts[0] as MemorySource).bytes.slice();
  const view = new DataView(prefix.buffer);
  change(view);
  const checked = prefix.slice(512, 604);
  checked.fill(0, 16, 20);
  view.setUint32(512 + 16, crc32(checked), true);
  return imageWithPrefix(prefix);
}

describe("disk partition inventory", () => {
  it("validates a real sgdisk GPT header and entry-array CRC", async () => {
    const report = await inspectDiskPartitions(gpt());
    expect(report).toMatchObject({
      scheme: "GPT", sectorBytes: 512, primaryHeaderCrcValid: true, partitionArrayCrcValid: true, backupHeaderChecked: false,
      partitions: [{ number: 1, startLba: 2048, endLba: 4095, bytes: 1_048_576, name: "DATA", type: "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7" }],
    });
  });

  it("rejects independently damaged GPT header and entry CRCs", async () => {
    const header = gpt().parts[0] as MemorySource;
    const damagedHeader = header.bytes.slice();
    damagedHeader[512 + 16] ^= 1;
    const rest = new MissingSource(16 * 1024 * 1024 - damagedHeader.length);
    await expect(inspectDiskPartitions(new ConcatSource([new MemorySource(damagedHeader), rest]))).rejects.toThrow(/header CRC-32/);
    const damagedEntry = header.bytes.slice();
    damagedEntry[1024 + 56] ^= 1;
    await expect(inspectDiskPartitions(new ConcatSource([new MemorySource(damagedEntry), rest]))).rejects.toThrow(/array CRC-32/);
  });

  it("rejects GPT metadata outside its valid extent even when the header CRC matches", async () => {
    await expect(inspectDiskPartitions(alterHeader((view) => view.setBigUint64(512 + 40, 2n, true)))).rejects.toThrow(/metadata overlaps/);
    await expect(inspectDiskPartitions(alterHeader((view) => view.setBigUint64(512 + 48, 32767n, true)))).rejects.toThrow(/metadata overlaps/);
    await expect(inspectDiskPartitions(alterHeader((view) => view.setBigUint64(512 + 72, 32766n, true)))).rejects.toThrow(/entry array exceeds/);
  });

  it("rejects hybrid MBR entries instead of silently hiding them", async () => {
    const prefix = (gpt().parts[0] as MemorySource).bytes.slice();
    const view = new DataView(prefix.buffer);
    prefix[462 + 4] = 0x07;
    view.setUint32(462 + 8, 2048, true);
    view.setUint32(462 + 12, 2048, true);
    await expect(inspectDiskPartitions(imageWithPrefix(prefix))).rejects.toThrow(/Hybrid protective MBR/);
  });

  it("inspects a bounded legacy MBR partition", async () => {
    const bytes = new Uint8Array(9 * 512);
    const view = new DataView(bytes.buffer);
    bytes[446] = 0x80;
    bytes[450] = 0x07;
    view.setUint32(454, 1, true);
    view.setUint32(458, 8, true);
    bytes[510] = 0x55;
    bytes[511] = 0xaa;
    expect(await inspectDiskPartitions(new MemorySource(bytes))).toMatchObject({
      scheme: "MBR", partitions: [{ number: 1, type: "0x07", startLba: 1, endLba: 8, bootable: true, bytes: 4096 }],
    });
  });

  it("exposes large disk sources through the Forensics operation without loading the image", async () => {
    const disk = gpt();
    let bytesRead = 0;
    const source: ByteSource = {
      size: disk.size,
      async read(offset, length) {
        bytesRead += length;
        if (offset + length > 34 * 512) throw new Error("Unexpected read outside primary GPT metadata");
        return disk.read(offset, length);
      },
      stream: disk.stream.bind(disk),
    };
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.disk.partitions", inputs: { data: bytesValue(source) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(bytesRead).toBe(512 + 512 + 128 * 128);
    expect(result.run.diagnostics.join(" ")).toMatch(/backup GPT was not read/);
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { scheme: "GPT", partitions: [{ name: "DATA" }] } });
  });
});