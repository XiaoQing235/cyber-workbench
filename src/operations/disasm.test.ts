import capstoneWasm from "@alexaltea/capstone-js/dist/capstone.wasm?inline";
import { describe, expect, it } from "vitest";
import type { Bytes } from "../core/bytes/ByteSource";
import { executeOperation } from "../core/operation/execute";
import type { Params } from "../core/operation/types";
import { bytesFrom } from "../core/value";
import { parseExecutable } from "../formats/executable";
import { setPackFileReader } from "../runtimes/files";
import { createDefaultRegistry } from "./index";

const registry = createDefaultRegistry();
const wasm = Uint8Array.from(atob(capstoneWasm.slice(capstoneWasm.indexOf(",") + 1)), (c) => c.charCodeAt(0));
setPackFileReader(async (url) => {
  if (url.includes("capstone")) return wasm;
  throw new Error(`No test file for ${url}`);
});

async function run(input: Bytes, params: Params = {}) {
  const result = await executeOperation(registry, { operationId: "code.disasm", inputs: { data: bytesFrom(input) }, params });
  const value = Object.values(result.outputs)[0];
  return { text: value?.type === "text" ? value.text : "", error: result.run.error, diagnostics: result.run.diagnostics };
}

const CODE = Uint8Array.of(0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x0f, 0x05, 0xc3);

function file(size: number, fill: (view: DataView, bytes: Uint8Array) => void): Bytes {
  const bytes = new Uint8Array(size);
  fill(new DataView(bytes.buffer), bytes);
  return bytes;
}

const elf64 = file(0x1000 + CODE.length, (v, b) => {
  b.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
  v.setUint16(16, 2, true);
  v.setUint16(18, 62, true);
  v.setUint32(20, 1, true);
  v.setBigUint64(24, 0x401000n, true);
  v.setBigUint64(32, 64n, true);
  v.setUint16(52, 64, true);
  v.setUint16(54, 56, true);
  v.setUint16(56, 1, true);
  v.setUint16(58, 64, true);
  v.setUint32(64, 1, true);
  v.setUint32(68, 5, true);
  v.setBigUint64(72, 0x1000n, true);
  v.setBigUint64(80, 0x401000n, true);
  v.setBigUint64(96, BigInt(CODE.length), true);
  b.set(CODE, 0x1000);
});

const pe64 = file(0x400, (v, b) => {
  b.set([0x4d, 0x5a]);
  v.setUint32(0x3c, 0x40, true);
  b.set([0x50, 0x45, 0, 0], 0x40);
  v.setUint16(0x44, 0x8664, true);
  v.setUint16(0x46, 1, true);
  v.setUint16(0x54, 0xf0, true);
  v.setUint16(0x58, 0x20b, true);
  v.setUint32(0x58 + 16, 0x1000, true);
  v.setBigUint64(0x58 + 24, 0x140000000n, true);
  const section = 0x58 + 0xf0;
  b.set([0x2e, 0x74, 0x65, 0x78, 0x74], section);
  v.setUint32(section + 8, CODE.length, true);
  v.setUint32(section + 12, 0x1000, true);
  v.setUint32(section + 16, 0x200, true);
  v.setUint32(section + 20, 0x200, true);
  v.setUint32(section + 36, 0x60000020, true);
  b.set(CODE, 0x200);
});

const ascii = (text: string) => Uint8Array.from(text, (c) => c.charCodeAt(0));
const macho64 = file(0x1000, (v, b) => {
  v.setUint32(0, 0xfeedfacf, true);
  v.setUint32(4, 0x01000007, true);
  v.setUint32(12, 2, true);
  v.setUint32(16, 2, true);
  v.setUint32(20, 72 + 80 + 24, true);
  const seg = 32;
  v.setUint32(seg, 0x19, true);
  v.setUint32(seg + 4, 72 + 80, true);
  b.set(ascii("__TEXT"), seg + 8);
  v.setBigUint64(seg + 24, 0x100000000n, true);
  v.setBigUint64(seg + 32, 0x1000n, true);
  v.setBigUint64(seg + 48, 0x1000n, true);
  v.setUint32(seg + 56, 5, true);
  v.setUint32(seg + 60, 5, true);
  v.setUint32(seg + 64, 1, true);
  const sect = seg + 72;
  b.set(ascii("__text"), sect);
  b.set(ascii("__TEXT"), sect + 16);
  v.setBigUint64(sect + 32, 0x100000f00n, true);
  v.setBigUint64(sect + 40, BigInt(CODE.length), true);
  v.setUint32(sect + 48, 0xf00, true);
  v.setUint32(sect + 64, 0x80000400, true);
  const main = sect + 80;
  v.setUint32(main, 0x80000028, true);
  v.setUint32(main + 4, 24, true);
  v.setBigUint64(main + 8, 0xf00n, true);
  b.set(CODE, 0xf00);
});

describe("Capstone pack: disassembly", () => {
  it("finds the architecture, entry point and addresses of ELF, PE and Mach-O files", async () => {
    expect(parseExecutable(elf64)).toMatchObject({ format: "ELF", arch: "x86-64", entryAddress: 0x401000n, entryOffset: 0x1000 });
    expect(parseExecutable(pe64)).toMatchObject({ format: "PE", arch: "x86-64", entryAddress: 0x140001000n, entryOffset: 0x200 });
    expect(parseExecutable(macho64)).toMatchObject({ format: "Mach-O", arch: "x86-64", entryAddress: 0x100000f00n, entryOffset: 0xf00 });

    const elf = await run(elf64);
    expect(elf.text.split("\n")).toEqual([
      "00401000:  55                       push rbp",
      "00401001:  48 89 e5                 mov rbp, rsp",
      "00401004:  31 c0                    xor eax, eax",
      "00401006:  0f 05                    syscall",
      "00401008:  c3                       ret",
    ]);
    expect(elf.diagnostics[0]).toBe("ELF 64-bit little-endian executable, machine 62; x86-64 from entry point 0x401000 in segment 0.");
    expect((await run(pe64)).text.split("\n")[0]).toBe("140001000:  55                       push rbp");
    expect((await run(pe64, { start: ".text", syntax: "att" })).text.split("\n")[0]).toBe("140001000:  55                       pushq %rbp");
    expect((await run(macho64, { start: "@0x100000f04" })).text.split("\n")[0]).toBe("100000f04:  31 c0                    xor eax, eax");
  });

  it("disassembles raw code for other architectures and keeps going over data", async () => {
    const line = async (arch: string, bytes: number[]) => (await run(Uint8Array.from(bytes), { arch, start: "0" })).text.split("\n").map((text) => text.slice(36));
    expect(await line("arm", [0x01, 0x00, 0xa0, 0xe3, 0x1e, 0xff, 0x2f, 0xe1])).toEqual(["mov r0, #1", "bx lr"]);
    expect(await line("arm64", [0x20, 0x00, 0x80, 0xd2, 0xc0, 0x03, 0x5f, 0xd6])).toEqual(["mov x0, #1", "ret"]);
    expect((await line("mips32-be", [0x24, 0x02, 0x00, 0x01, 0x03, 0xe0, 0x00, 0x08]))[1]).toBe("jr $ra");
    expect((await line("riscv64", [0x13, 0x05, 0x10, 0x00, 0x67, 0x80, 0x00, 0x00]))[1]).toBe("ret");
    // ff ff is invalid; skipping one byte resynchronises on ff c3 (inc ebx).
    expect(await line("x86-32", [0x90, 0xff, 0xff, 0xc3])).toEqual(["nop", ".byte 0xff", "inc ebx"]);
  });

  it("explains what it needs", async () => {
    expect((await run(CODE)).error?.message).toBe("Not an ELF, PE or Mach-O file: choose the architecture for raw code");
    expect((await run(elf64, { start: ".text" })).error?.message).toMatch(/^Start must be "entry", an offset, @address or a section name \(segment 0\)$/);
    expect((await run(elf64, { start: "@0x500000" })).error?.message).toBe("0x500000 is not mapped from the file");
    expect((await run(CODE, { arch: "x86-64", start: "0x100" })).error?.message).toBe("Offset 0x100 is past the end of the data (9 bytes)");
  });
});

describe("bounded x86 ROP filtering", () => {
  it("finds short ret gadgets with exact bytes and filters addresses by forbidden pointer bytes", async () => {
    const input = bytesFrom(Uint8Array.of(0x58, 0xc3, 0x90, 0xc3));
    const first = await executeOperation(registry, { operationId: "reverse.rop.filter", inputs: { data: input },
      params: { arch: "x86-64", badBytes: "", maxGadgets: 16, maxInstructions: 2 } });
    expect(first.run.status).toBe("success");
    expect(first.outputs.report).toMatchObject({ type: "structured", data: { gadgets: [
      { address: "0x0", bytes: "58c3", instructions: ["pop rax", "ret"] },
      { address: "0x1", bytes: "c3", instructions: ["ret"] },
      { address: "0x2", bytes: "90c3", instructions: ["nop", "ret"] },
      { address: "0x3", bytes: "c3", instructions: ["ret"] },
    ], verifiedChain: false } });
    const filtered = await executeOperation(registry, { operationId: "reverse.rop.filter", inputs: { data: input },
      params: { arch: "x86-64", badBytes: "00", maxGadgets: 16, maxInstructions: 2 } });
    expect(filtered.outputs.report).toMatchObject({ type: "structured", data: { gadgets: [] } });
  });

  it("rejects malformed forbidden-byte lists and mismatched executable architectures", async () => {
    const invalid = await executeOperation(registry, { operationId: "reverse.rop.filter", inputs: { data: bytesFrom(CODE) }, params: { badBytes: "0" } });
    expect(invalid.run.error?.code).toBe("INVALID_PARAMS");
    const mismatch = await executeOperation(registry, { operationId: "reverse.rop.filter", inputs: { data: bytesFrom(elf64) }, params: { arch: "x86-32" } });
    expect(mismatch.run.error?.code).toBe("INVALID_PARAMS");
  });

  it("stops disassembly at the search-work budget on dense ret data", async () => {
    const result = await executeOperation(registry, { operationId: "reverse.rop.filter",
      inputs: { data: bytesFrom(new Uint8Array(6000).fill(0xc3)) },
      params: { arch: "x86-64", badBytes: "", maxGadgets: 256, maxInstructions: 1 } });
    expect(result.run.status).toBe("success");
    expect(result.outputs.report).toMatchObject({ type: "structured", data: { truncated: true,
      gadgets: expect.any(Array), verifiedChain: false } });
  });
});
