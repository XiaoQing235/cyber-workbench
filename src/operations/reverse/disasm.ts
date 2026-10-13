import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { textValue } from "../../core/value";
import { ARCHES, parseExecutable, regionAt, type ArchId, type Executable } from "../../formats/executable";
import { importPack } from "../../runtimes/files";
import { bytesInput, MiB } from "../util";

const hex = (value: number | bigint) => `0x${value.toString(16)}`;

/** "entry", a file offset (0x400, 1024), "@address" (virtual) or a section name (.text). */
function resolveStart(spec: string, exe: Executable | null, size: number): { offset: number; label: string } {
  const text = spec.trim();
  if (text === "" || text === "entry") {
    if (!exe) return { offset: 0, label: "start of data" };
    if (exe.entryOffset === null) throw new OperationError("INVALID_PARAMS", `${exe.format}: the entry point is not inside the file; give an offset or a section name`);
    return { offset: exe.entryOffset, label: `entry point ${exe.entryAddress === null ? "" : hex(exe.entryAddress)}` };
  }
  if (text.startsWith("@")) {
    if (!exe) throw new OperationError("INVALID_PARAMS", "Virtual addresses (@…) need an ELF, PE or Mach-O file; use a file offset");
    const address = BigInt(text.slice(1).trim());
    const region = exe.regions.find((item) => address >= item.address && address < item.address + BigInt(item.size));
    if (!region) throw new OperationError("INVALID_PARAMS", `${hex(address)} is not mapped from the file`);
    return { offset: region.offset + Number(address - region.address), label: `address ${hex(address)}` };
  }
  if (/^(0x[0-9a-f]+|[0-9]+)$/i.test(text)) {
    const offset = Number(text);
    if (offset >= size) throw new OperationError("INVALID_PARAMS", `Offset ${text} is past the end of the data (${size} bytes)`);
    return { offset, label: `offset ${hex(offset)}` };
  }
  const region = exe?.regions.find((item) => item.name === text);
  if (!region) {
    const names = exe ? [...new Set(exe.regions.map((item) => item.name))].join(", ") : "";
    throw new OperationError("INVALID_PARAMS", `Start must be "entry", an offset, @address or a section name${names ? ` (${names})` : ""}`);
  }
  return { offset: region.offset, label: `section ${region.name}` };
}

export const disasm = defineOperation<{ arch: string; start: string; length: number; maxInstructions: number; syntax: "intel" | "att" }>({
  spec: {
    id: "code.disasm",
    version: "1.0.0",
    title: "Disassemble",
    category: "Reverse",
    description:
      "Disassemble with Capstone. For ELF, PE and Mach-O files the architecture, entry point and virtual addresses are found automatically; raw shellcode needs an architecture.",
    keywords: ["disassemble", "disassembly", "capstone", "assembly", "shellcode", "x86", "arm", "mips", "elf", "pe", "reverse", "objdump"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "text", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: {
        arch: { type: "string", title: "Architecture", enum: ["auto", ...ARCHES], default: "auto" },
        start: { type: "string", title: "Start (entry, offset, @address or section)", default: "entry", maxLength: 100 },
        length: { type: "integer", title: "Bytes (0 = to the end of the section)", minimum: 0, maximum: 4 * MiB, default: 0 },
        maxInstructions: { type: "integer", title: "Max instructions", minimum: 1, maximum: 200_000, default: 2000 },
        syntax: { type: "string", title: "x86 syntax", enum: ["intel", "att"], default: "intel" },
      },
      required: ["arch", "start", "length", "maxInstructions", "syntax"],
      additionalProperties: false,
    },
    runtime: "wasm",
    deterministic: true,
    sideEffects: "none",
    streaming: false,
    cost: "medium",
    limits: { maxInputBytes: 256 * MiB },
  },
  async run(ctx, inputs, params) {
    const bytes = await readAll(bytesInput(inputs));
    const exe = parseExecutable(bytes);
    let arch: ArchId;
    if (params.arch === "auto") {
      if (!exe) throw new OperationError("INVALID_PARAMS", "Not an ELF, PE or Mach-O file: choose the architecture for raw code");
      if (!exe.arch) throw new OperationError("INVALID_PARAMS", `${exe.description}: unsupported architecture; choose one`);
      arch = exe.arch;
    } else {
      arch = params.arch as ArchId;
    }
    const { offset, label } = resolveStart(params.start, exe, bytes.length);
    const region = exe ? regionAt(exe, offset) : undefined;
    const end = params.length > 0 ? Math.min(bytes.length, offset + params.length) : region ? region.offset + region.size : bytes.length;
    const address = region ? region.address + BigInt(offset - region.offset) : BigInt(offset);
    if (exe) ctx.diagnostic(`${exe.description}; ${arch} from ${label}${region ? ` in ${region.name}` : ""}.`);

    const { loadCapstone, disassemble } = await importPack("Capstone", () => import("../../runtimes/capstone"));
    const cs = await loadCapstone();
    const lines = disassemble(cs, arch, bytes.subarray(offset, Math.min(end, offset + 4 * MiB)), address, params.maxInstructions, params.syntax === "att");
    const width = Math.max(8, ...lines.map((line) => line.address.toString(16).length));
    const text = lines
      .map((line) => `${line.address.toString(16).padStart(width, "0")}:  ${line.bytes.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(24)} ${line.text}`)
      .join("\n");
    const consumed = lines.reduce((sum, line) => sum + line.bytes.length, 0);
    ctx.diagnostic(`${lines.length.toLocaleString()} instruction(s) over ${consumed.toLocaleString()} bytes${lines.length === params.maxInstructions ? " (instruction limit reached)" : ""}.`);
    return { text: textValue(text) };
  },
});
