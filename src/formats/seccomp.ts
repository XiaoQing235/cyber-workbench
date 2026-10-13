import type { ByteSource } from "../core/bytes/ByteSource";

/** Linux classic-BPF sock_filter instructions (code, jt, jf, k), little-endian. */
export const MAX_SECCOMP_INSTRUCTIONS = 4096;
export const MAX_SECCOMP_BYTES = MAX_SECCOMP_INSTRUCTIONS * 8;

export interface SeccompInstruction {
  index: number;
  code: string;
  kind: string;
  k: number;
  trueTarget?: number;
  falseTarget?: number;
}

export interface SeccompReport {
  instructions: SeccompInstruction[];
  reachableReturns: { index: number; action: string; value: string }[];
  sample: { arch: number; syscall: number; args: string[]; trace: number[]; action: string; value: string };
}

function action(k: number): string {
  switch ((k & 0xffff0000) >>> 0) {
    case 0x00000000: return "KILL_THREAD";
    case 0x00030000: return "TRAP";
    case 0x00050000: return "ERRNO";
    case 0x7fc00000: return "USER_NOTIF";
    case 0x7ff00000: return "TRACE";
    case 0x7ffc0000: return "LOG";
    case 0x7fff0000: return "ALLOW";
    case 0x80000000: return "KILL_PROCESS";
    default: return "UNKNOWN";
  }
}

function argumentWords(text: string): { words: number[]; args: string[] } {
  const parts = text.split(",").map((part) => part.trim());
  if (parts.length !== 6) throw new Error("Provide exactly six comma-separated syscall arguments");
  const words: number[] = [];
  const args: string[] = [];
  for (const part of parts) {
    if (!/^(?:0[xX][0-9a-fA-F]+|[0-9]+)$/.test(part)) throw new Error("Syscall arguments must be unsigned decimal or 0x-prefixed hex integers");
    const value = BigInt(part);
    if (value > 0xffffffffffffffffn) throw new Error("Syscall arguments must fit in 64 bits");
    words.push(Number(value & 0xffffffffn), Number(value >> 32n));
    args.push(`0x${value.toString(16)}`);
  }
  return { words, args };
}

/** Inspect and simulate a deliberately restricted, read-only subset of Linux seccomp cBPF. */
export async function inspectSeccomp(source: ByteSource, arch: number, syscall: number, argsText: string, signal?: AbortSignal): Promise<SeccompReport> {
  if (!Number.isSafeInteger(source.size) || source.size < 8 || source.size > MAX_SECCOMP_BYTES || source.size % 8 !== 0) {
    throw new Error("Seccomp input must contain 1–4096 complete 8-byte sock_filter instructions");
  }
  if (![arch, syscall].every((value) => Number.isInteger(value) && value >= 0 && value <= 0xffffffff)) throw new Error("Arch and syscall must be unsigned 32-bit integers");
  const { words, args } = argumentWords(argsText);
  if (signal?.aborted) throw signal.reason;
  const bytes = await source.read(0, source.size);
  if (bytes.length !== source.size) throw new Error("Seccomp filter is truncated");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = bytes.length / 8;
  const instructions: SeccompInstruction[] = [];
  for (let index = 0; index < count; index++) {
    if (signal?.aborted) throw signal.reason;
    const offset = index * 8;
    const code = view.getUint16(offset, true);
    const jt = view.getUint8(offset + 2);
    const jf = view.getUint8(offset + 3);
    const k = view.getUint32(offset + 4, true);
    let kind: string;
    let trueTarget: number | undefined;
    let falseTarget: number | undefined;
    if (code === 0x20) {
      if (k !== 0 && k !== 4 && (k < 16 || k > 60 || k % 4 !== 0)) throw new Error(`Instruction ${index}: unsupported seccomp_data offset ${k}`);
      kind = k === 0 ? "LD syscall" : k === 4 ? "LD arch" : `LD arg${Math.floor((k - 16) / 8)} ${k % 8 === 0 ? "low" : "high"}`;
    } else if (code === 0x05) {
      kind = "JA";
      trueTarget = index + 1 + k;
    } else if ([0x15, 0x25, 0x35, 0x45].includes(code)) {
      kind = ({ 0x15: "JEQ", 0x25: "JGT", 0x35: "JGE", 0x45: "JSET" } as Record<number, string>)[code];
      trueTarget = index + 1 + jt;
      falseTarget = index + 1 + jf;
    } else if (code === 0x06) {
      kind = "RET";
      if (action(k) === "UNKNOWN") throw new Error(`Instruction ${index}: unknown seccomp return action 0x${k.toString(16)}`);
    } else {
      throw new Error(`Instruction ${index}: unsupported cBPF opcode 0x${code.toString(16)}`);
    }
    if (![0x15, 0x25, 0x35, 0x45].includes(code) && (jt !== 0 || jf !== 0)) {
      throw new Error(`Instruction ${index}: unused jump fields must be zero`);
    }
    if ((trueTarget !== undefined && trueTarget >= count) || (falseTarget !== undefined && falseTarget >= count)) {
      throw new Error(`Instruction ${index}: jump leaves the filter`);
    }
    instructions.push({ index, code: `0x${code.toString(16).padStart(4, "0")}`, kind, k,
      ...(trueTarget === undefined ? {} : { trueTarget }), ...(falseTarget === undefined ? {} : { falseTarget }) });
  }

  // All paths are forward-only; require every reachable path to terminate in a return.
  const reachable = new Set([0]);
  for (let index = 0; index < count; index++) {
    if (!reachable.has(index)) continue;
    const instruction = instructions[index];
    if (instruction.kind === "RET") continue;
    const targets = instruction.kind === "JA" ? [instruction.trueTarget!] : instruction.trueTarget !== undefined
      ? [instruction.trueTarget, instruction.falseTarget!] : [index + 1];
    for (const target of targets) {
      if (target >= count) throw new Error(`Instruction ${index}: reachable path falls off the filter without RET`);
      reachable.add(target);
    }
  }
  const reachableReturns = instructions.filter((instruction) => reachable.has(instruction.index) && instruction.kind === "RET")
    .map((instruction) => ({ index: instruction.index, action: action(instruction.k), value: `0x${instruction.k.toString(16).padStart(8, "0")}` }));

  const trace: number[] = [];
  let accumulator = 0;
  let pc = 0;
  while (true) {
    if (signal?.aborted) throw signal.reason;
    const instruction = instructions[pc];
    trace.push(pc);
    if (instruction.kind === "RET") return { instructions, reachableReturns, sample: { arch, syscall, args, trace,
      action: action(instruction.k), value: `0x${instruction.k.toString(16).padStart(8, "0")}` } };
    if (instruction.kind.startsWith("LD")) {
      accumulator = instruction.k === 0 ? syscall : instruction.k === 4 ? arch : words[(instruction.k - 16) / 4];
      pc++;
    } else if (instruction.kind === "JA") pc = instruction.trueTarget!;
    else {
      const match = instruction.kind === "JEQ" ? accumulator === instruction.k
        : instruction.kind === "JGT" ? accumulator > instruction.k
          : instruction.kind === "JGE" ? accumulator >= instruction.k : (accumulator & instruction.k) !== 0;
      pc = match ? instruction.trueTarget! : instruction.falseTarget!;
    }
  }
}
