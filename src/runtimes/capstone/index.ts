import createCapstone, { type CapstoneModule } from "@alexaltea/capstone-js";
import wasmUrl from "@alexaltea/capstone-js/dist/capstone.wasm?url";
import type { ArchId } from "../../formats/executable";
import { once, readPackFile } from "../files";

export const loadCapstone = once(async (): Promise<CapstoneModule> => createCapstone({ wasmBinary: await readPackFile("Capstone", wasmUrl) }));

const MODES: Record<ArchId, [string, string[]]> = {
  "x86-16": ["ARCH_X86", ["MODE_16"]],
  "x86-32": ["ARCH_X86", ["MODE_32"]],
  "x86-64": ["ARCH_X86", ["MODE_64"]],
  arm: ["ARCH_ARM", ["MODE_ARM"]],
  "arm-be": ["ARCH_ARM", ["MODE_ARM", "MODE_BIG_ENDIAN"]],
  thumb: ["ARCH_ARM", ["MODE_THUMB"]],
  arm64: ["ARCH_ARM64", ["MODE_LITTLE_ENDIAN"]],
  mips32: ["ARCH_MIPS", ["MODE_MIPS32"]],
  "mips32-be": ["ARCH_MIPS", ["MODE_MIPS32", "MODE_BIG_ENDIAN"]],
  mips64: ["ARCH_MIPS", ["MODE_MIPS64"]],
  "mips64-be": ["ARCH_MIPS", ["MODE_MIPS64", "MODE_BIG_ENDIAN"]],
  "ppc32-be": ["ARCH_PPC", ["MODE_32", "MODE_BIG_ENDIAN"]],
  ppc64: ["ARCH_PPC", ["MODE_64"]],
  "ppc64-be": ["ARCH_PPC", ["MODE_64", "MODE_BIG_ENDIAN"]],
  riscv32: ["ARCH_RISCV", ["MODE_RISCV32", "MODE_RISCVC"]],
  riscv64: ["ARCH_RISCV", ["MODE_RISCV64", "MODE_RISCVC"]],
  sparc: ["ARCH_SPARC", ["MODE_BIG_ENDIAN"]],
  sparc64: ["ARCH_SPARC", ["MODE_BIG_ENDIAN", "MODE_V9"]],
  m68k: ["ARCH_M68K", ["MODE_M68K_040"]],
  "6502": ["ARCH_MOS65XX", ["MODE_MOS65XX_6502"]],
  bpf: ["ARCH_BPF", ["MODE_BPF_EXTENDED"]],
  evm: ["ARCH_EVM", []],
  wasm: ["ARCH_WASM", []],
};

export interface Line {
  address: bigint;
  bytes: number[];
  text: string;
}

/** Disassembles with SKIPDATA on, so bytes that are not valid code appear as .byte instead of stopping. */
export function disassemble(cs: CapstoneModule, arch: ArchId, code: Uint8Array, address: bigint, max: number, att: boolean): Line[] {
  const constant = (name: string) => {
    const value = cs[name];
    if (typeof value !== "number") throw new Error(`Capstone has no ${name}`);
    return value;
  };
  const [archName, modeNames] = MODES[arch];
  const engine = new cs.Capstone(constant(archName), modeNames.reduce((mode, name) => mode | constant(name), 0));
  try {
    engine.option(constant("OPT_SKIPDATA"), constant("OPT_ON"));
    if (att && archName === "ARCH_X86") engine.option(constant("OPT_SYNTAX"), constant("OPT_SYNTAX_ATT"));
    return engine.disasm(code, address, max).map((insn) => ({
      address: BigInt.asUintN(64, BigInt(insn.address)),
      bytes: insn.bytes,
      text: insn.op_str ? `${insn.mnemonic} ${insn.op_str}` : insn.mnemonic,
    }));
  } finally {
    engine.close();
  }
}
