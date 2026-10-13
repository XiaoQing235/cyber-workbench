export interface FormatWrite {
  byteOffset: number;
  address: string;
  value: number;
  argument: number;
  padding: number;
  printed: number;
}

export interface FormatStringPlan {
  format: string;
  writes: FormatWrite[];
  totalPrinted: number;
  pointerArgumentsRequired: number[];
  paddingArgument: number;
  /** Addresses are metadata only: the caller must arrange the positional pointer arguments. */
  addressesEmbedded: false;
  writeWidthBytes: 1 | 2;
}

const MAX_PADDING = 65_536;

function unsignedHex(text: string, label: string, bits: number): bigint {
  if (!/^0x[0-9a-f]+$/i.test(text)) throw new Error(`${label} must be 0x-prefixed hexadecimal`);
  const value = BigInt(text);
  if (value >= (1n << BigInt(bits))) throw new Error(`${label} must fit in ${bits} bits`);
  return value;
}

/** Plan positional %hhn writes without embedding addresses or executing a format string. */
export function planFormatWrites(addressText: string, valueText: string, byteCount: number,
  firstArgument: number, paddingArgument: number, alreadyPrinted: number, writeWidthBytes: 1 | 2 = 1): FormatStringPlan {
  if (![1, 2].includes(writeWidthBytes) || !Number.isSafeInteger(byteCount) || byteCount < 1 || byteCount > 8 || byteCount % writeWidthBytes !== 0 ||
      !Number.isSafeInteger(firstArgument) || firstArgument < 1 || firstArgument + byteCount / writeWidthBytes > 256 ||
      !Number.isSafeInteger(paddingArgument) || paddingArgument < 1 || paddingArgument > 256 ||
      (paddingArgument >= firstArgument && paddingArgument < firstArgument + byteCount / writeWidthBytes) ||
      !Number.isSafeInteger(alreadyPrinted) || alreadyPrinted < 0 || alreadyPrinted > 1_000_000) {
    throw new Error("Format write count, positional arguments or initial printed count are outside their bounds");
  }
  const address = unsignedHex(addressText, "Address", 64);
  const target = unsignedHex(valueText, "Value", byteCount * 8);
  if (address + BigInt(byteCount - 1) > 0xffffffffffffffffn) throw new Error("Address range wraps 64 bits");
  // POSIX positional conversion requires every preceding argument to have a known type.
  // Restrict the planner to a leading character argument and contiguous pointer arguments.
  if (paddingArgument !== 1 || firstArgument !== 2) throw new Error("Format writes require character argument 1 and pointer arguments starting at 2");
  if (writeWidthBytes === 2 && address % 2n !== 0n) throw new Error("Halfword write address must be 2-byte aligned");
  const modulus = 256 ** writeWidthBytes;
  const desired = Array.from({ length: byteCount / writeWidthBytes }, (_, index) => ({
    byteOffset: index * writeWidthBytes, value: Number((target >> BigInt(index * writeWidthBytes * 8)) & BigInt(modulus - 1)),
  }));
  // Each non-overlapping byte/halfword offset has a distinct pointer argument.
  const relative = (value: number) => (value - alreadyPrinted % modulus + modulus) % modulus;
  desired.sort((a, b) => relative(a.value) - relative(b.value) || a.byteOffset - b.byteOffset);
  const writes: FormatWrite[] = [];
  let printed = alreadyPrinted;
  let format = "";
  for (const { byteOffset, value } of desired) {
    const delta = (value - (printed % modulus) + modulus) % modulus;
    // Positional %c prints at least one character; width 1 is valid and prints exactly one.
    const padding = delta;
    if (padding > 0) format += `%${paddingArgument}$${padding}c`;
    printed += padding;
    if (printed > alreadyPrinted + MAX_PADDING) throw new Error("Format string exceeds the output budget");
    const argument = firstArgument + byteOffset / writeWidthBytes;
    format += `%${argument}$${writeWidthBytes === 1 ? "hhn" : "hn"}`;
    writes.push({ byteOffset, address: `0x${(address + BigInt(byteOffset)).toString(16)}`, value, argument, padding, printed });
  }
  return { format, writes, totalPrinted: printed,
    pointerArgumentsRequired: Array.from({ length: byteCount / writeWidthBytes }, (_, i) => firstArgument + i),
    paddingArgument, addressesEmbedded: false, writeWidthBytes };
}
