/** Minimal ELF, PE and Mach-O headers: architecture, entry point and the offset ↔ address mapping. */

export const ARCHES = [
  "x86-16", "x86-32", "x86-64",
  "arm", "arm-be", "thumb", "arm64",
  "mips32", "mips32-be", "mips64", "mips64-be",
  "ppc32-be", "ppc64", "ppc64-be",
  "riscv32", "riscv64",
  "sparc", "sparc64", "m68k", "6502", "bpf", "evm", "wasm",
] as const;

export type ArchId = (typeof ARCHES)[number];

export interface Region {
  name: string;
  offset: number;
  size: number;
  address: bigint;
  executable: boolean;
}

export interface Executable {
  format: "ELF" | "PE" | "Mach-O";
  description: string;
  /** null when Capstone has no matching architecture. */
  arch: ArchId | null;
  entryAddress: bigint | null;
  entryOffset: number | null;
  regions: Region[];
}

class Reader {
  readonly view: DataView;
  constructor(
    readonly bytes: Uint8Array,
    public le: boolean,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  ok(offset: number, size: number): boolean {
    return offset >= 0 && offset + size <= this.bytes.length;
  }
  u16(offset: number): number {
    return this.view.getUint16(offset, this.le);
  }
  u32(offset: number): number {
    return this.view.getUint32(offset, this.le);
  }
  u64(offset: number): bigint {
    return this.view.getBigUint64(offset, this.le);
  }
  name(offset: number, max: number): string {
    let end = offset;
    while (end < Math.min(this.bytes.length, offset + max) && this.bytes[end] !== 0) end++;
    return String.fromCharCode(...this.bytes.subarray(offset, end));
  }
}

const num = (value: bigint) => (value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : Infinity);

function regionOf(regions: readonly Region[], address: bigint): Region | undefined {
  return regions.find((region) => address >= region.address && address < region.address + BigInt(region.size));
}

function locate(exe: Omit<Executable, "entryOffset">): number | null {
  if (exe.entryAddress === null) return null;
  const region = regionOf(exe.regions, exe.entryAddress);
  return region ? region.offset + Number(exe.entryAddress - region.address) : null;
}

function elf(bytes: Uint8Array): Executable | null {
  if (bytes.length < 52 || bytes[0] !== 0x7f || bytes[1] !== 0x45 || bytes[2] !== 0x4c || bytes[3] !== 0x46) return null;
  const wide = bytes[4] === 2;
  const r = new Reader(bytes, bytes[5] !== 2);
  if (wide && bytes.length < 64) return null;
  const machine = r.u16(18);
  let entry = wide ? r.u64(24) : BigInt(r.u32(24));
  const phoff = wide ? num(r.u64(32)) : r.u32(28);
  const shoff = wide ? num(r.u64(40)) : r.u32(32);
  const [phentsize, phnum, shentsize, shnum, shstrndx] = (wide ? [54, 56, 58, 60, 62] : [42, 44, 46, 48, 50]).map((at) => r.u16(at));
  const big = !r.le;
  let arch: ArchId | null = null;
  switch (machine) {
    case 3:
      arch = "x86-32";
      break;
    case 62:
      arch = "x86-64";
      break;
    case 40:
      arch = entry & 1n ? "thumb" : big ? "arm-be" : "arm";
      entry &= ~1n;
      break;
    case 183:
      arch = "arm64";
      break;
    case 8:
      arch = wide ? (big ? "mips64-be" : "mips64") : big ? "mips32-be" : "mips32";
      break;
    case 20:
      arch = "ppc32-be";
      break;
    case 21:
      arch = big ? "ppc64-be" : "ppc64";
      break;
    case 243:
      arch = wide ? "riscv64" : "riscv32";
      break;
    case 2:
    case 18:
      arch = "sparc";
      break;
    case 43:
      arch = "sparc64";
      break;
    case 4:
      arch = "m68k";
      break;
    case 247:
      arch = "bpf";
      break;
  }
  const regions: Region[] = [];
  // Sections give names; program headers (below) cover stripped binaries without section headers.
  if (shoff > 0 && shnum > 0 && r.ok(shoff, shnum * shentsize)) {
    const strtab = shstrndx < shnum ? (wide ? num(r.u64(shoff + shstrndx * shentsize + 24)) : r.u32(shoff + shstrndx * shentsize + 16)) : -1;
    for (let i = 0; i < shnum; i++) {
      const at = shoff + i * shentsize;
      const type = r.u32(at + 4);
      const flags = wide ? r.u64(at + 8) : BigInt(r.u32(at + 8));
      const address = wide ? r.u64(at + 16) : BigInt(r.u32(at + 12));
      const offset = wide ? num(r.u64(at + 24)) : r.u32(at + 16);
      const size = wide ? num(r.u64(at + 32)) : r.u32(at + 20);
      // SHT_NOBITS (.bss) has no file bytes; unallocated sections have no address.
      if (type === 8 || !(flags & 2n) || !r.ok(offset, size)) continue;
      regions.push({ name: strtab >= 0 && r.ok(strtab, 1) ? r.name(strtab + r.u32(at), 64) || `section ${i}` : `section ${i}`, offset, size, address, executable: (flags & 4n) !== 0n });
    }
  }
  if (phoff > 0 && phnum > 0 && r.ok(phoff, phnum * phentsize)) {
    for (let i = 0; i < phnum; i++) {
      const at = phoff + i * phentsize;
      if (r.u32(at) !== 1) continue;
      const flags = wide ? r.u32(at + 4) : r.u32(at + 24);
      const offset = wide ? num(r.u64(at + 8)) : r.u32(at + 4);
      const address = wide ? r.u64(at + 16) : BigInt(r.u32(at + 8));
      const size = wide ? num(r.u64(at + 32)) : r.u32(at + 16);
      if (r.ok(offset, size)) regions.push({ name: `segment ${i}`, offset, size, address, executable: (flags & 1) !== 0 });
    }
  }
  const types: Record<number, string> = { 1: "relocatable", 2: "executable", 3: "shared object", 4: "core dump" };
  const exe = {
    format: "ELF" as const,
    description: `ELF ${wide ? 64 : 32}-bit ${big ? "big" : "little"}-endian ${types[r.u16(16)] ?? "file"}, machine ${machine}`,
    arch,
    entryAddress: entry === 0n ? null : entry,
    regions,
  };
  return { ...exe, entryOffset: locate(exe) };
}

function pe(bytes: Uint8Array): Executable | null {
  if (bytes.length < 0x40 || bytes[0] !== 0x4d || bytes[1] !== 0x5a) return null;
  const r = new Reader(bytes, true);
  const header = r.u32(0x3c);
  if (!r.ok(header, 24) || r.u32(header) !== 0x00004550) return null;
  const machine = r.u16(header + 4);
  const sections = r.u16(header + 6);
  const optionalSize = r.u16(header + 20);
  const optional = header + 24;
  if (!r.ok(optional, Math.max(optionalSize, 32))) return null;
  const plus = r.u16(optional) === 0x20b;
  const entryRva = r.u32(optional + 16);
  const imageBase = plus ? r.u64(optional + 24) : BigInt(r.u32(optional + 28));
  const arch: ArchId | null = ({ 0x14c: "x86-32", 0x8664: "x86-64", 0x1c0: "arm", 0x1c2: "thumb", 0x1c4: "thumb", 0xaa64: "arm64", 0x5032: "riscv32", 0x5064: "riscv64" } as Record<number, ArchId>)[machine] ?? null;
  const regions: Region[] = [];
  const table = optional + optionalSize;
  for (let i = 0; i < sections && r.ok(table + i * 40, 40); i++) {
    const at = table + i * 40;
    const rva = r.u32(at + 12);
    const rawSize = r.u32(at + 16);
    const rawOffset = r.u32(at + 20);
    const size = Math.min(rawSize, Math.max(r.u32(at + 8), rawSize) || rawSize);
    if (rawSize === 0 || !r.ok(rawOffset, Math.min(size, bytes.length - rawOffset))) continue;
    regions.push({
      name: r.name(at, 8),
      offset: rawOffset,
      size: Math.min(size, bytes.length - rawOffset),
      address: imageBase + BigInt(rva),
      executable: (r.u32(at + 36) & 0x20000000) !== 0,
    });
  }
  const exe = {
    format: "PE" as const,
    description: `PE${plus ? "32+" : "32"} ${r.u16(header + 22) & 0x2000 ? "DLL" : "executable"}, machine 0x${machine.toString(16)}`,
    arch,
    entryAddress: entryRva === 0 ? null : imageBase + BigInt(entryRva),
    regions,
  };
  return { ...exe, entryOffset: locate(exe) };
}

function macho(bytes: Uint8Array): Executable | null {
  if (bytes.length < 32 || bytes[0] !== 0xcf || bytes[1] !== 0xfa || bytes[2] !== 0xed || bytes[3] !== 0xfe) return null;
  const r = new Reader(bytes, true);
  const cpu = r.u32(4);
  const arch: ArchId | null = cpu === 0x01000007 ? "x86-64" : cpu === 0x0100000c ? "arm64" : null;
  const regions: Region[] = [];
  let entryFileOffset: number | null = null;
  let at = 32;
  for (let i = 0, count = r.u32(16); i < count && r.ok(at, 8); i++) {
    const cmd = r.u32(at);
    const size = r.u32(at + 4);
    if (size < 8 || !r.ok(at, size)) break;
    if (cmd === 0x19 && r.ok(at, 72)) {
      const segment = r.name(at + 8, 16);
      const sections = r.u32(at + 64);
      for (let s = 0; s < sections && r.ok(at + 72 + s * 80, 80); s++) {
        const section = at + 72 + s * 80;
        const offset = r.u32(section + 48);
        const length = num(r.u64(section + 40));
        if (offset === 0 || !r.ok(offset, length)) continue;
        regions.push({
          name: `${segment},${r.name(section, 16)}`,
          offset,
          size: length,
          address: r.u64(section + 32),
          executable: (r.u32(section + 64) & 0x80000400) !== 0,
        });
      }
      const fileoff = num(r.u64(at + 40));
      const filesize = num(r.u64(at + 48));
      if (filesize > 0 && r.ok(fileoff, filesize)) regions.push({ name: segment, offset: fileoff, size: filesize, address: r.u64(at + 24), executable: (r.u32(at + 60) & 4) !== 0 });
    } else if (cmd === 0x80000028 && r.ok(at, 16)) {
      entryFileOffset = num(r.u64(at + 8));
    }
    at += size;
  }
  const region = entryFileOffset === null ? undefined : regions.find((item) => entryFileOffset! >= item.offset && entryFileOffset! < item.offset + item.size);
  return {
    format: "Mach-O",
    description: `Mach-O 64-bit, CPU type 0x${cpu.toString(16)}`,
    arch,
    entryAddress: region ? region.address + BigInt(entryFileOffset! - region.offset) : null,
    entryOffset: region ? entryFileOffset : null,
    regions,
  };
}

export function parseExecutable(bytes: Uint8Array): Executable | null {
  return elf(bytes) ?? pe(bytes) ?? macho(bytes) ?? fat(bytes);
}

/** Universal Mach-O: the first x86-64 or arm64 slice, with offsets made relative to the whole file. */
function fat(bytes: Uint8Array): Executable | null {
  if (bytes.length < 8 || bytes[0] !== 0xca || bytes[1] !== 0xfe || bytes[2] !== 0xba || bytes[3] !== 0xbe) return null;
  const r = new Reader(bytes, false);
  const count = r.u32(4);
  // Java class files share the magic; their next field (version) is far larger than a slice count.
  if (count === 0 || count > 32) return null;
  for (let i = 0; i < count && r.ok(8 + i * 20, 20); i++) {
    const at = 8 + i * 20;
    const offset = r.u32(at + 8);
    const size = r.u32(at + 12);
    if (!r.ok(offset, size)) continue;
    const slice = macho(bytes.subarray(offset, offset + size));
    if (!slice?.arch) continue;
    return {
      ...slice,
      description: `Universal binary (${count} slices); ${slice.description}`,
      entryOffset: slice.entryOffset === null ? null : slice.entryOffset + offset,
      regions: slice.regions.map((region) => ({ ...region, offset: region.offset + offset })),
    };
  }
  return null;
}

/** The most specific region (section before segment) containing a file offset. */
export function regionAt(exe: Executable, offset: number): Region | undefined {
  return exe.regions
    .filter((region) => offset >= region.offset && offset < region.offset + region.size)
    .sort((a, b) => a.size - b.size)[0];
}
