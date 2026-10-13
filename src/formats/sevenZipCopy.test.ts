import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { MemorySource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractSevenZipCopy, inspectSevenZipCopy } from "./sevenZipCopy";

// This archive was independently created with 7-Zip 26.04 (Copy method) from a licensed corpus fixture.

const archive = () => new Uint8Array(readFileSync(new URL("./testing/7zip-26-copy.7z", import.meta.url)));

describe("7-Zip 26 Copy archive inspection", () => {
  it("lists and extracts an independently written Copy stream with verified CRC", async () => {
    const source = new MemorySource(archive());
    const report = await inspectSevenZipCopy(source);
    expect(report).toMatchObject({ payloadOffset: 32, copyOnly: true,
      files: [{ name: "src/formats/testing/google-ctf-2023-lcg-dump.txt", bytes: 930, crc32: "0xd6f628d2", payloadOffset: 32, directory: false }] });
    const extracted = await readAll(await extractSevenZipCopy(source));
    const original = readFileSync(new URL("./testing/google-ctf-2023-lcg-dump.txt", import.meta.url));
    expect(createHash("sha256").update(extracted).digest("hex")).toBe(createHash("sha256").update(original).digest("hex"));
    const result = await executeOperation(createDefaultRegistry(), { operationId: "archive.sevenzip.copy.extract",
      inputs: { data: bytesValue(source) }, params: {} });
    expect(result.run.status).toBe("success");
  });

  it("indexes and CRC-verifies two independent 7-Zip 26 Copy streams", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/7zip-26-two-copy.7z", import.meta.url)));
    const source = new MemorySource(bytes);
    const report = await inspectSevenZipCopy(source);
    expect(report.files).toEqual([
      { name: "src/formats/testing/google-ctf-2023-lcg-dump.txt", bytes: 930, crc32: "0xd6f628d2", payloadOffset: 32, directory: false },
      { name: "src/formats/testing/google-ctf-2023-lcg-public.pem", bytes: 795, crc32: "0xe15fdf7f", payloadOffset: 962, directory: false },
    ]);
    for (const index of report.files.keys()) {
      const extracted = await readAll(await extractSevenZipCopy(source, undefined, index));
      const original = readFileSync(new URL(`./testing/google-ctf-2023-lcg-${index === 0 ? "dump.txt" : "public.pem"}`, import.meta.url));
      expect(createHash("sha256").update(extracted).digest("hex")).toBe(createHash("sha256").update(original).digest("hex"));
    }
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "archive.sevenzip.copy.extract",
      inputs: { data: bytesValue(source) }, params: { entryIndex: 1 } });
    expect(operation.run.status).toBe("success");
    if (operation.outputs.data?.type !== "bytes") throw new Error("Missing selected Copy entry");
    expect(await readAll(operation.outputs.data.source)).toEqual(new Uint8Array(readFileSync(new URL("./testing/google-ctf-2023-lcg-public.pem", import.meta.url))));
    await expect(extractSevenZipCopy(source, undefined, 2)).rejects.toThrow(/entry index/);
    const damaged = bytes.slice(); damaged[962] ^= 1;
    await expect(extractSevenZipCopy(new MemorySource(damaged), undefined, 1)).rejects.toThrow(/CRC mismatch/);
  });

  it("lists a 7-Zip 26 empty file separately from its nonempty Copy stream", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/7zip-26-empty-copy.7z", import.meta.url)));
    const source = new MemorySource(bytes);
    expect((await inspectSevenZipCopy(source)).files).toEqual([
      { name: "m6-empty.txt", bytes: 0, crc32: "0x00000000", payloadOffset: 32, directory: false },
      { name: "src/formats/testing/google-ctf-2023-lcg-dump.txt", bytes: 930, crc32: "0xd6f628d2", payloadOffset: 32, directory: false },
    ]);
    expect(await readAll(await extractSevenZipCopy(source, undefined, 0))).toEqual(new Uint8Array());
    expect(await readAll(await extractSevenZipCopy(source, undefined, 1)))
      .toEqual(new Uint8Array(readFileSync(new URL("./testing/google-ctf-2023-lcg-dump.txt", import.meta.url))));
    const corrupt = bytes.slice();
    // Switch the empty-file bitmap into a directory flag and recompute both header CRCs.
    const start = new DataView(corrupt.buffer).getBigUint64(12, true);
    const header = 32 + Number(start);
    const emptyFileBitmap = header + 36;
    corrupt[emptyFileBitmap] = 0;
    const { crc32 } = await import("../core/checksum/crc32");
    const view = new DataView(corrupt.buffer);
    view.setUint32(28, crc32(corrupt.subarray(header)), true);
    view.setUint32(8, crc32(corrupt.subarray(12, 32)), true);
    expect((await inspectSevenZipCopy(new MemorySource(corrupt))).files[0]).toMatchObject({ directory: true, crc32: null });
    await expect(extractSevenZipCopy(new MemorySource(corrupt))).rejects.toThrow(/directory/);
  });

  it("lists a real 7-Zip 26 directory without treating it as an empty regular file", async () => {
    const bytes = new Uint8Array(readFileSync(new URL("./testing/7zip-26-folder-copy.7z", import.meta.url)));
    const source = new MemorySource(bytes);
    expect((await inspectSevenZipCopy(source)).files).toEqual([
      { name: "m6-directory", bytes: 0, crc32: null, payloadOffset: 32, directory: true },
      { name: "src/formats/testing/google-ctf-2023-lcg-dump.txt", bytes: 930, crc32: "0xd6f628d2", payloadOffset: 32, directory: false },
    ]);
    await expect(extractSevenZipCopy(source, undefined, 0)).rejects.toThrow(/directory/);
    expect(await readAll(await extractSevenZipCopy(source, undefined, 1)))
      .toEqual(new Uint8Array(readFileSync(new URL("./testing/google-ctf-2023-lcg-dump.txt", import.meta.url))));
  });

  it("handles independent 7-Zip 26 archives with no packed streams", async () => {
    const empty = new MemorySource(new Uint8Array(readFileSync(new URL("./testing/7zip-26-empty-only.7z", import.meta.url))));
    expect((await inspectSevenZipCopy(empty)).files).toEqual([
      { name: "m6-empty.txt", bytes: 0, crc32: "0x00000000", payloadOffset: 32, directory: false },
    ]);
    expect(await readAll(await extractSevenZipCopy(empty))).toEqual(new Uint8Array());
    const folder = new MemorySource(new Uint8Array(readFileSync(new URL("./testing/7zip-26-folder-only.7z", import.meta.url))));
    expect((await inspectSevenZipCopy(folder)).files).toEqual([
      { name: "m6-directory", bytes: 0, crc32: null, payloadOffset: 32, directory: true },
    ]);
    await expect(extractSevenZipCopy(folder)).rejects.toThrow(/directory/);
    const operation = await executeOperation(createDefaultRegistry(), { operationId: "archive.sevenzip.copy.inspect",
      inputs: { data: bytesValue(folder) }, params: {} });
    expect(operation.outputs.report).toMatchObject({ type: "structured", data: { files: [{ directory: true }] } });
  });

  it("rejects damaged payload bytes and unsupported coder metadata", async () => {
    const damaged = archive(); damaged[32] ^= 1;
    await expect(extractSevenZipCopy(new MemorySource(damaged))).rejects.toThrow(/CRC mismatch/);
    const header = archive(); header[0x3ca] ^= 1;
    await expect(inspectSevenZipCopy(new MemorySource(header))).rejects.toThrow(/CRC mismatch/);
  });
});
