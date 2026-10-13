import type { ByteSource } from "../core/bytes/ByteSource";

const ROM_BYTES = 208;
const BANNED = [0, 2, 3, 6, 7, 14];
const SHELLCODE_OFFSET = 0xd0;

/** Inspect only the fixed Auxin2 ROM's input-filter bytecode; never execute the Uxn VM. */
export async function inspectAuxinRom(source: ByteSource, signal?: AbortSignal): Promise<{
  romBytes: number; shellcodeAddress: string; forbiddenLowNibbles: number[]; executingRom: false;
}> {
  if (source.size !== ROM_BYTES) throw new Error("Auxin2 ROM must contain 208 bytes");
  const bytes = await source.read(0, ROM_BYTES);
  if (signal?.aborted) throw signal.reason;
  if (bytes.length !== ROM_BYTES || bytes[0] !== 0xa0 || bytes[1] !== 0x01 || bytes[2] !== 0x16 ||
    new TextDecoder("ascii").decode(bytes.subarray(0x17, 0x1d)) !== "auxin2" ||
    bytes[0xca] !== 0xa0 || bytes[0xcb] !== 0x01 || bytes[0xcc] !== 0xc2 || bytes[0xcd] !== 0x80 ||
    bytes[0xc2] !== 0 || bytes[0xc3] !== 1 || bytes[0xc4] !== 0xd0 || SHELLCODE_OFFSET !== ROM_BYTES) {
    throw new Error("Auxin2 ROM has unsupported fixed header or shellcode entry");
  }
  const checks = BANNED;
  // DUP LIT 0x0f AND precedes all comparisons. Without this mask they would reject whole bytes.
  if (![0x80, 0x0f, 0x1c, 0x06].every((byte, index) => bytes[0x6a + index] === byte)) {
    throw new Error("Auxin2 low-nibble mask differs from the supported ROM");
  }
  // Source TAL implements each banned low-nibble comparison with DUP LIT <nibble> EQU ?fail.
  for (let i = 0, at = 0x6e; i < checks.length; i++, at += 7) {
    if (bytes[at] !== 0x80 || bytes[at + 1] !== checks[i] || bytes[at + 2] !== 0x08 ||
      bytes[at + 3] !== 0x20 || bytes[at + 4] !== 0 || bytes[at + 5] !== (0x34 - i * 7) ||
      bytes[at + 6] !== (i === checks.length - 1 ? 0x02 : 0x06)) {
      throw new Error("Auxin2 forbidden-low-nibble checks differ from the supported ROM");
    }
  }
  return { romBytes: ROM_BYTES, shellcodeAddress: "0x01d0", forbiddenLowNibbles: BANNED.slice(), executingRom: false };
}

/** Validate the published server's hex-input envelope and the ROM's low-nibble filter. */
export function inspectAuxinPayload(text: string): { bytes: number; bannedOffsets: number[]; acceptedByStaticFilter: boolean;
  executed: false } {
  if (text.length < 2 || text.length > 224 || text.length % 2 || !/^[0-9a-f]+$/.test(text)) {
    throw new Error("Auxin2 payload must be 1–112 bytes of lowercase even-length hex");
  }
  const bannedOffsets: number[] = [];
  for (let i = 0; i < text.length; i += 2) if (BANNED.includes(Number.parseInt(text[i + 1], 16))) bannedOffsets.push(i / 2);
  return { bytes: text.length / 2, bannedOffsets, acceptedByStaticFilter: bannedOffsets.length === 0, executed: false };
}
