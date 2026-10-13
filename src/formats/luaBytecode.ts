import type { ByteSource } from "../core/bytes/ByteSource";

export const MAX_LUA_CHUNK_BYTES = 8 * 1024 * 1024;
const LUA_SIGNATURE = [0x1b, 0x4c, 0x75, 0x61, 0x54, 0x00, 0x19, 0x93, 0x0d, 0x0a, 0x1a, 0x0a];

export interface LuaChunkHeader {
  version: "5.4";
  endianness: "little" | "big";
  instructionSize: 4;
  integerSize: 8;
  numberSize: 8;
  mainUpvalues: number;
  bodyOffset: 32;
  bodyBytes: number;
  executed: false;
}

export interface LuaPrototype {
  path: string;
  lineDefined: number;
  lastLineDefined: number;
  parameters: number;
  vararg: boolean;
  maxStack: number;
  instructionOffset: number;
  instructionCount: number;
  instructions: { pc: number; opcode: number; hex: string }[];
  constantCount: number;
  upvalueCount: number;
  nestedCount: number;
}

export interface LuaBytecodeReport extends LuaChunkHeader {
  prototypes: LuaPrototype[];
  totalInstructions: number;
}

class ChunkReader {
  readonly view: DataView;
  offset = 32;

  constructor(readonly bytes: Uint8Array, readonly littleEndian: boolean) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  byte(): number {
    if (this.offset >= this.bytes.length) throw new Error("Lua bytecode prototype is truncated");
    return this.bytes[this.offset++];
  }

  count(): number {
    let value = 0;
    for (let index = 0; index < 5; index++) {
      const part = this.byte();
      value = value * 128 + (part & 0x7f);
      if (value > 0x7fffffff) throw new Error("Lua bytecode count exceeds 32-bit range");
      if (part & 0x80) return value;
    }
    throw new Error("Lua bytecode count is unterminated");
  }

  skip(length: number): void {
    if (!Number.isSafeInteger(length) || length < 0 || length > this.bytes.length - this.offset) {
      throw new Error("Lua bytecode section exceeds the chunk");
    }
    this.offset += length;
  }

  string(): void {
    const length = this.count();
    if (length) this.skip(length - 1);
  }
}

export async function inspectLuaBytecodeHeader(source: ByteSource, signal?: AbortSignal): Promise<LuaChunkHeader> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < 33 || source.size > MAX_LUA_CHUNK_BYTES) {
    throw new Error("Lua bytecode chunk is truncated or exceeds 8 MiB");
  }
  const header = await source.read(0, 32);
  if (signal?.aborted) throw signal.reason;
  if (header.length !== 32 || !LUA_SIGNATURE.every((byte, index) => header[index] === byte)) {
    throw new Error("Unsupported Lua bytecode signature or version (expected Lua 5.4)");
  }
  if (header[12] !== 4 || header[13] !== 8 || header[14] !== 8) {
    throw new Error("Unsupported Lua bytecode instruction, integer, or number size");
  }
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  const littleEndian = view.getBigInt64(15, true) === 0x5678n;
  if (!littleEndian && view.getBigInt64(15, false) !== 0x5678n) {
    throw new Error("Lua bytecode integer validation failed");
  }
  if (view.getFloat64(23, littleEndian) !== 370.5) {
    throw new Error("Lua bytecode number validation failed");
  }
  return {
    version: "5.4", endianness: littleEndian ? "little" : "big", instructionSize: 4,
    integerSize: 8, numberSize: 8, mainUpvalues: header[31], bodyOffset: 32,
    bodyBytes: source.size - 32, executed: false,
  };
}

export async function inspectLuaBytecode(source: ByteSource, signal?: AbortSignal): Promise<LuaBytecodeReport> {
  const header = await inspectLuaBytecodeHeader(source, signal);
  const bytes = await source.read(0, source.size);
  if (signal?.aborted) throw signal.reason;
  if (bytes.length !== source.size) throw new Error("Lua bytecode chunk is truncated");
  const reader = new ChunkReader(bytes, header.endianness === "little");
  const prototypes: LuaPrototype[] = [];
  let totalInstructions = 0;

  function parsePrototype(path: string, depth: number): void {
    if (signal?.aborted) throw signal.reason;
    if (depth > 24 || prototypes.length >= 512) throw new Error("Lua bytecode prototype limit exceeded");
    reader.string();
    const lineDefined = reader.count();
    const lastLineDefined = reader.count();
    const parameters = reader.byte();
    const vararg = reader.byte() !== 0;
    const maxStack = reader.byte();
    const instructionCount = reader.count();
    if (instructionCount > 200_000 - totalInstructions) throw new Error("Lua bytecode instruction limit exceeded");
    const instructionOffset = reader.offset;
    reader.skip(instructionCount * 4);
    totalInstructions += instructionCount;
    const instructions = [];
    for (let pc = 0; pc < Math.min(instructionCount, 12); pc++) {
      const offset = instructionOffset + pc * 4;
      const word = reader.view.getUint32(offset, reader.littleEndian);
      instructions.push({ pc, opcode: word & 0x7f, hex: word.toString(16).padStart(8, "0") });
    }
    const constantCount = reader.count();
    if (constantCount > 65_536) throw new Error("Lua bytecode constant limit exceeded");
    for (let index = 0; index < constantCount; index++) {
      if ((index & 0x3ff) === 0 && signal?.aborted) throw signal.reason;
      const tag = reader.byte();
      if (tag === 3 || tag === 19) reader.skip(8);
      else if (tag === 4 || tag === 20) reader.string();
      else if (tag !== 0 && tag !== 1 && tag !== 17) throw new Error(`Lua bytecode constant tag ${tag} is unsupported`);
    }
    const upvalueCount = reader.count();
    if (upvalueCount > 255) throw new Error("Lua bytecode upvalue limit exceeded");
    reader.skip(upvalueCount * 3);
    const nestedCount = reader.count();
    if (nestedCount > 512 - prototypes.length) throw new Error("Lua bytecode prototype limit exceeded");
    const prototype: LuaPrototype = {
      path, lineDefined, lastLineDefined, parameters, vararg, maxStack,
      instructionOffset, instructionCount, instructions, constantCount, upvalueCount, nestedCount,
    };
    prototypes.push(prototype);
    for (let index = 0; index < nestedCount; index++) parsePrototype(`${path}/${index}`, depth + 1);
    const lineInfoCount = reader.count();
    reader.skip(lineInfoCount);
    const absLineInfoCount = reader.count();
    if (absLineInfoCount > instructionCount) throw new Error("Lua bytecode line table exceeds instruction count");
    for (let index = 0; index < absLineInfoCount; index++) {
      reader.count();
      reader.count();
    }
    const localCount = reader.count();
    if (localCount > 65_536) throw new Error("Lua bytecode local limit exceeded");
    for (let index = 0; index < localCount; index++) {
      reader.string();
      reader.count();
      reader.count();
    }
    const upvalueNameCount = reader.count();
    if (upvalueNameCount > upvalueCount) throw new Error("Lua bytecode upvalue names exceed upvalues");
    for (let index = 0; index < upvalueNameCount; index++) reader.string();
  }

  parsePrototype("main", 0);
  if (prototypes[0].upvalueCount !== header.mainUpvalues || reader.offset !== bytes.length) {
    throw new Error("Lua bytecode upvalues or final extent do not match the header");
  }
  return { ...header, prototypes, totalInstructions };
}