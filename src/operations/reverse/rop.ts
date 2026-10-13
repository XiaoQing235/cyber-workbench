import { readAll } from "../../core/bytes/sources";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { structuredValue } from "../../core/value";
import { parseExecutable } from "../../formats/executable";
import { importPack } from "../../runtimes/files";
import { bytesInput, MiB } from "../util";

export const ropFilter = defineOperation<{ arch: "x86-32" | "x86-64"; badBytes: string; maxGadgets: number; maxInstructions: number }>({
  spec: {
    id: "reverse.rop.filter", version: "1.0.0", title: "Filter x86 ROP gadgets", category: "Reverse",
    description: "Find bounded short instruction sequences ending in ret in raw x86 bytes or executable regions of an ELF/PE/Mach-O. Filter pointer addresses containing chosen bad bytes; candidates are not verified exploit chains.",
    keywords: ["rop", "gadget", "ret", "bad bytes", "shellcode", "capstone", "constraint"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      arch: { type: "string", title: "Architecture", enum: ["x86-32", "x86-64"], default: "x86-64" },
      badBytes: { type: "string", title: "Forbidden pointer bytes (hex pairs separated by spaces)", maxLength: 128, default: "" },
      maxGadgets: { type: "integer", title: "Maximum gadget candidates", minimum: 1, maximum: 256, default: 32 },
      maxInstructions: { type: "integer", title: "Maximum instructions per gadget", minimum: 1, maximum: 6, default: 3 },
    }, required: ["arch", "badBytes", "maxGadgets", "maxInstructions"], additionalProperties: false },
    runtime: "wasm", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 8 * MiB },
  },
  async run(ctx, inputs, params) {
    ctx.throwIfAborted();
    const text = params.badBytes.trim();
    if (text && !/^(?:[0-9a-f]{2})(?:\s+[0-9a-f]{2})*$/i.test(text)) throw new OperationError("INVALID_PARAMS", "Forbidden bytes must be hex pairs separated by spaces");
    const forbidden = new Set(text ? text.split(/\s+/).map((pair) => Number.parseInt(pair, 16)) : []);
    const bytes = await readAll(bytesInput(inputs), 8 * MiB);
    const exe = parseExecutable(bytes);
    if (exe?.arch && exe.arch !== params.arch) throw new OperationError("INVALID_PARAMS", `Executable architecture is ${exe.arch}, not ${params.arch}`);
    const regions = exe ? exe.regions.filter((region) => region.executable && region.offset < bytes.length)
      : [{ name: "raw", offset: 0, size: bytes.length, address: 0n }];
    if (!regions.length) throw new OperationError("INVALID_INPUT", "No executable file-backed region was found");
    const { loadCapstone, disassemble } = await importPack("Capstone", () => import("../../runtimes/capstone"));
    const cs = await loadCapstone();
    const gadgets: { address: string; offset: number; bytes: string; instructions: string[] }[] = [];
    let examined = 0;
    let disassemblyAttempts = 0;
    let truncated = false;
    const width = params.arch === "x86-64" ? 8 : 4;
    outer: for (const region of regions) {
      const end = Math.min(bytes.length, region.offset + region.size);
      for (let offset = region.offset; offset < end; offset++) {
        if ((examined++ & 0x3fff) === 0) ctx.throwIfAborted();
        if (bytes[offset] !== 0xc3) continue; // near RET only; RET imm16 needs stack-adjust semantics
        const first = Math.max(region.offset, offset - 24);
        for (let start = first; start <= offset; start++) {
          const address = region.address + BigInt(start - region.offset);
          if (Array.from({ length: width }, (_, i) => Number((address >> BigInt(i * 8)) & 255n)).some((part) => forbidden.has(part))) continue;
          if (++disassemblyAttempts > 5_000) { truncated = true; break outer; }
          const window = bytes.subarray(start, offset + 1);
          const lines = disassemble(cs, params.arch, window, address, params.maxInstructions + 1, false);
          if (lines.length < 1 || lines.length > params.maxInstructions || lines.reduce((size, line) => size + line.bytes.length, 0) !== window.length ||
            lines.at(-1)?.text !== "ret" || lines.some((line) => line.text.startsWith(".byte") || line.text.startsWith("ret "))) continue;
          gadgets.push({ address: `0x${address.toString(16)}`, offset: start,
            bytes: Array.from(window, (byte) => byte.toString(16).padStart(2, "0")).join(""), instructions: lines.map((line) => line.text) });
          if (gadgets.length >= params.maxGadgets) { truncated = true; break outer; }
        }
      }
    }
    ctx.diagnostic(`Found ${gadgets.length} x86 ret-terminated candidate(s)${truncated ? " (search or output limit reached)" : ""}.`);
    return { report: structuredValue({ arch: params.arch, forbiddenBytes: [...forbidden].map((byte) => byte.toString(16).padStart(2, "0")),
      examinedBytes: examined, disassemblyAttempts, truncated, gadgets, verifiedChain: false }) };
  },
});
