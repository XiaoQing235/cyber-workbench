import { describe, expect, it } from "vitest";
import { ConcatSource, MemorySource, MissingSource, readAll } from "../core/bytes/sources";
import { executeOperation } from "../core/operation/execute";
import { bytesValue } from "../core/value";
import { createDefaultRegistry } from "../operations";
import { extractDeletedFat32Candidate, extractFat32File, inspectFat32 } from "./fat32";

const hex = (text: string) => Uint8Array.from(text.match(/../g)!, (pair) => Number.parseInt(pair, 16));
const BOOT = "eb58906d6b66732e66617400020120000200000000f80000200008000000000000000200f103000000000000020000000100060000000000000000000000000080002908b60a4b435942455246532020202046415433322020200e1fbe777cac";
const ROOT = "435942455246532020202008000076a24b5d4b5d000076a24b5d00000000000044455349474e20205458542000007aa24b5d4b5d00007aa24b5d03006ab90000e5454c45544544205458542000007aa24b5d4b5d00007aa24b5d6000d98d0100";
const ROOT_OFFSET = 1_049_600;
const IMAGE_BYTES = 64 * 1024 * 1024;

function fatVolume(): ConcatSource {
  const boot = new Uint8Array(512);
  boot.set(hex(BOOT));
  boot[510] = 0x55;
  boot[511] = 0xaa;
  const root = new Uint8Array(512);
  root.set(hex(ROOT));
  return new ConcatSource([
    new MemorySource(boot), new MissingSource(ROOT_OFFSET - boot.length), new MemorySource(root),
    new MissingSource(IMAGE_BYTES - ROOT_OFFSET - root.length),
  ]);
}

describe("FAT32 root metadata", () => {
  it("reads live and deleted records from a dosfstools/mtools image without the whole image", async () => {
    const report = await inspectFat32(fatVolume());
    expect(report).toMatchObject({
      filesystem: "FAT32", volumeLabel: "CYBERFS", rootOnly: true, timestampZone: "unknown",
      bytesPerSector: 512, sectorsPerCluster: 1, rootCluster: 2,
      entries: [
        { name: "DESIGN.TXT", deleted: false, bytes: 47466, startCluster: 3, directoryEntryOffset: ROOT_OFFSET + 32 },
        { name: "?ELETED.TXT", deleted: true, bytes: 101849, startCluster: 96, directoryEntryOffset: ROOT_OFFSET + 64 },
      ],
    });
    expect(report.entries[0].createdLocal).toMatch(/^2026-10-11T/);
    expect(report.entries[1].accessedLocalDate).toBe("2026-10-11");
  });

  it("extracts a live file lazily through its FAT chain and refuses deleted data", async () => {
    const boot = fatVolume().parts[0];
    const root = fatVolume().parts[2];
    const fat = new Uint8Array(512);
    const fatEntries = new DataView(fat.buffer);
    for (let cluster = 3; cluster < 95; cluster++) fatEntries.setUint32(cluster * 4, cluster + 1, true);
    fatEntries.setUint32(95 * 4, 0x0fffffff, true);
    const content = Uint8Array.from({ length: 47466 }, (_, index) => index % 251);
    const volume = new ConcatSource([
      boot, new MissingSource(16_384 - 512), new MemorySource(fat),
      new MissingSource(ROOT_OFFSET - 16_896), root, new MemorySource(content),
      new MissingSource(IMAGE_BYTES - ROOT_OFFSET - 512 - content.length),
    ]);
    const file = await extractFat32File(volume, 0);
    expect(file.name).toBe("DESIGN.TXT");
    expect(await readAll(file.data)).toEqual(content);
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.disk.fat32.extract", inputs: { data: bytesValue(volume) }, params: { entryIndex: 0 },
    });
    expect(result.run.status).toBe("success");
    if (result.outputs.data?.type !== "bytes") throw new Error("Expected extracted bytes");
    expect(await readAll(result.outputs.data.source)).toEqual(content);
    await expect(extractFat32File(volume, 1)).rejects.toThrow(/Deleted FAT32 entry/);
    fatEntries.setUint32(3 * 4, 3, true);
    await expect(extractFat32File(volume, 0)).rejects.toThrow(/cyclic/);
  });

  it("exposes the root inventory through the Forensics registry", async () => {
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.disk.fat32.inspect", inputs: { data: bytesValue(fatVolume()) }, params: {},
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { volumeLabel: "CYBERFS", entries: [{ name: "DESIGN.TXT" }, { deleted: true }] } });
  });

  it("treats a contiguous deleted file as an unverified candidate only while all clusters are free", async () => {
    const boot = fatVolume().parts[0];
    const root = fatVolume().parts[2];
    const fat = new Uint8Array(2_048);
    const content = Uint8Array.from({ length: 101849 }, (_, index) => index % 239);
    const candidateOffset = ROOT_OFFSET + (96 - 2) * 512;
    const volume = new ConcatSource([
      boot, new MissingSource(16_384 - 512), new MemorySource(fat),
      new MissingSource(ROOT_OFFSET - 16_384 - fat.length), root,
      new MissingSource(candidateOffset - ROOT_OFFSET - 512), new MemorySource(content),
      new MissingSource(IMAGE_BYTES - candidateOffset - content.length),
    ]);
    const candidate = await extractDeletedFat32Candidate(volume, 1);
    expect(candidate.report).toMatchObject({ name: "?ELETED.TXT", assumedClusters: 199, confidence: "unverified", firstCharacterLost: true });
    expect(await readAll(candidate.data)).toEqual(content);
    const result = await executeOperation(createDefaultRegistry(), {
      operationId: "forensics.disk.fat32.deleted-candidate", inputs: { data: bytesValue(volume) }, params: { entryIndex: 1 },
    });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { confidence: "unverified" } });
    new DataView(fat.buffer).setUint32(100 * 4, 101, true);
    await expect(extractDeletedFat32Candidate(volume, 1)).rejects.toThrow(/no longer free/);
  });
});