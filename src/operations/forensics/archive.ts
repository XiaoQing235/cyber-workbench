import { ConcatSource, MemorySource, readAll, SliceSource } from "../../core/bytes/sources";
import { readZip, zipEntryData } from "../../core/archive/zip";
import { crc32, crc32FourBytePreimage } from "../../core/checksum/crc32";
import { OperationError } from "../../core/operation/errors";
import { defineOperation } from "../../core/operation/types";
import { bytesFrom, bytesValue, structuredValue, textValue } from "../../core/value";
import { generateMaskCandidates } from "../../formats/passwordCandidates";
import { exportRar5Hash, exportSevenZipHash, inspectRar7z } from "../../formats/rar7z";
import { discoverRecoverableZipRecords, inspectZip } from "../../formats/zip";
import { inspectZipEndChain } from "../../formats/zipEndChain";
import { buildPolyglotZip } from "../../formats/zipPolyglot";
import { testZipCryptoKeys, testZipCryptoPassword } from "../../formats/zipCrypto";
import { importPack } from "../../runtimes/files";
import { bytesInput, MiB, parseHex, textInput, toHex, yieldToEventLoop } from "../util";

const MAX_HASHCAT_PKZIP_DATA = 320 * 1024;
const MAX_HASHCAT_AES_DATA = 8 * MiB;
const header = (size: number, fill: (view: DataView) => void): Uint8Array<ArrayBuffer> => {
  const bytes = new Uint8Array(size);
  fill(new DataView(bytes.buffer));
  return bytes;
};

function restorePkzip2(hash: string, entryName: string): { archive: Uint8Array<ArrayBuffer>; method: number; encryptedBytes: number; uncompressedBytes: number } {
  if (hash.length > MAX_HASHCAT_PKZIP_DATA * 2 + 1_024 || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(entryName) || entryName === "..") {
    throw new OperationError("INVALID_PARAMS", "PKZIP2 hash budget or safe entry name is invalid");
  }
  const start = hash.indexOf("$pkzip2$");
  const end = hash.indexOf("*$/pkzip2$", start + 8);
  if (start < 0 || end < 0) throw new OperationError("INVALID_INPUT", "Expected an inline $pkzip2$ record");
  const fields = hash.slice(start + 8, end).split("*");
  if (fields.length !== 14 || fields[0] !== "1" || (fields[1] !== "1" && fields[1] !== "2") || fields[2] !== "2" ||
    fields[3] !== "0" || fields[7] !== "0" || !["0", "8"].includes(fields[9]) ||
    ![fields[4], fields[5], fields[8], fields[10]].every((field) => /^[0-9a-f]{1,8}$/i.test(field)) || !/^[0-9a-f]{4}$/i.test(fields[11]) ||
    !/^[0-9a-f]{4}$/i.test(fields[12]) || !/^[0-9a-f]{1,8}$/i.test(fields[6]) || !/^[0-9a-f]+$/i.test(fields[13])) {
    throw new OperationError("UNAVAILABLE", "Only single-entry inline ZipCrypto $pkzip2$ with stored/deflated data is supported");
  }
  const crcHex = fields[6].padStart(8, "0");
  const crc = Number.parseInt(crcHex, 16);
  const compressed = Number.parseInt(fields[4], 16);
  const uncompressed = Number.parseInt(fields[5], 16);
  const inlineBytes = Number.parseInt(fields[10], 16);
  if (![compressed, uncompressed, inlineBytes].every(Number.isSafeInteger) || compressed < 12 || compressed > MAX_HASHCAT_PKZIP_DATA ||
    uncompressed > 8 * MiB || uncompressed > compressed * 100 || inlineBytes !== compressed ||
    fields[13].length !== compressed * 2 || Number.parseInt(crcHex.slice(0, 4), 16) !== Number.parseInt(fields[11], 16)) {
    throw new OperationError("INVALID_INPUT", "PKZIP2 encrypted bytes, lengths or CRC check do not agree");
  }
  const cipher = parseHex(fields[13], false);
  const name = new TextEncoder().encode(entryName);
  const method = Number(fields[9]);
  const modifiedTime = Number.parseInt(fields[12], 16);
  const version = method === 8 || fields[1] === "1" ? 20 : 10;
  const local = header(30 + name.length, (view) => {
    view.setUint32(0, 0x04034b50, true);
    view.setUint16(4, version, true);
    view.setUint16(6, 9, true);
    view.setUint16(8, method, true);
    view.setUint16(10, modifiedTime, true);
    view.setUint32(14, crc, true);
    view.setUint32(18, compressed, true);
    view.setUint32(22, uncompressed, true);
    view.setUint16(26, name.length, true);
  });
  local.set(name, 30);
  const descriptor = header(16, (view) => {
    view.setUint32(0, 0x08074b50, true);
    view.setUint32(4, crc, true);
    view.setUint32(8, compressed, true);
    view.setUint32(12, uncompressed, true);
  });
  const centralOffset = local.length + cipher.length + descriptor.length;
  const central = header(46 + name.length, (view) => {
    view.setUint32(0, 0x02014b50, true);
    view.setUint16(4, version, true);
    view.setUint16(6, version, true);
    view.setUint16(8, 9, true);
    view.setUint16(10, method, true);
    view.setUint16(12, modifiedTime, true);
    view.setUint32(16, crc, true);
    view.setUint32(20, compressed, true);
    view.setUint32(24, uncompressed, true);
    view.setUint16(28, name.length, true);
  });
  central.set(name, 46);
  const eocd = header(22, (view) => {
    view.setUint32(0, 0x06054b50, true);
    view.setUint16(8, 1, true);
    view.setUint16(10, 1, true);
    view.setUint32(12, central.length, true);
    view.setUint32(16, centralOffset, true);
  });
  const archive = new Uint8Array(local.length + cipher.length + descriptor.length + central.length + eocd.length);
  archive.set(local);
  archive.set(cipher, local.length);
  archive.set(descriptor, local.length + cipher.length);
  archive.set(central, centralOffset);
  archive.set(eocd, centralOffset + central.length);
  return { archive, method, encryptedBytes: compressed, uncompressedBytes: uncompressed };
}

export const zipHashRestore = defineOperation<{ entryName: string }>({
  spec: {
    id: "archive.zip.hash-restore", version: "1.0.0", title: "Restore ZIP from PKZIP2 hash", category: "Forensics",
    description: "Rebuild a one-entry traditional ZipCrypto archive from inline encrypted bytes in a $pkzip2$ hash. Requires the original entry name; other hash variants and split data are not supported.",
    keywords: ["zip", "pkzip2", "zip2john", "hash", "rebuild", "archive"],
    inputs: [{ name: "text", type: "text" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      entryName: { type: "string", title: "ZIP entry name", minLength: 1, maxLength: 128, default: "recovered.bin" },
    }, required: ["entryName"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs, params) {
    const result = restorePkzip2(textInput(inputs), params.entryName);
    ctx.diagnostic(`Restored ${params.entryName} with ${result.encryptedBytes} encrypted byte(s); a password is still required to extract it.`);
    return { data: bytesFrom(result.archive), report: structuredValue({ entryName: params.entryName, method: result.method,
      encryptedBytes: result.encryptedBytes, uncompressedBytes: result.uncompressedBytes }) };
  },
});

export const zipPolyglotCompose = defineOperation<Record<string, never>>({
  spec: {
    id: "archive.zip.polyglot-compose", version: "1.0.0", title: "Compose ZIP polyglot", category: "Forensics",
    description: "Compose a bounded three-entry dual-directory ZIP from a wrapper archive containing first.zip and second.zip. The two views require independent extractor validation; some unzip versions extract the second set but exit with structural warnings.",
    keywords: ["zip", "polyglot", "unzip", "7-zip", "central directory", "unicode comment"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "archive", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 512 * 1024 },
  },
  async run(ctx, inputs) {
    const source = bytesInput(inputs);
    if (source.size > 512 * 1024) throw new OperationError("INPUT_TOO_LARGE", "Polyglot wrapper exceeds 512 KiB");
    try {
      ctx.throwIfAborted();
      const entries = await readZip(new Blob([await readAll(source)]));
      if (entries.length !== 2 || entries[0].name !== "first.zip" || entries[1].name !== "second.zip" ||
        entries.some((entry) => entry.size > 128 * 1024 || entry.compressedSize > 128 * 1024)) {
        throw new Error("Polyglot wrapper needs only first.zip and second.zip, each at most 128 KiB");
      }
      const original = await Promise.all(entries.map((entry) => zipEntryData(entry, 128 * 1024)));
      ctx.throwIfAborted();
      const result = buildPolyglotZip(new Uint8Array(await original[0].arrayBuffer()), new Uint8Array(await original[1].arrayBuffer()));
      ctx.diagnostic("Constructed two ZIP directory views; verify both extracted file sets with independent tools. Unzip may report structural warnings.");
      return { archive: bytesFrom(result), report: structuredValue({ bytes: result.length,
        inputs: ["first.zip", "second.zip"], independentExtractorValidationRequired: true, flagRecovered: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const zipEndChainRecover = defineOperation<{ prefix: string }>({
  spec: {
    id: "archive.zip.eocd-chain", version: "1.0.0", title: "Recover ZIP end-record chain", category: "Forensics",
    description: "Find all EOF-anchored, single-entry stored ZIP end records, validate their local and central headers and CRCs, then concatenate contiguous numbered entries. Does not execute contents or claim an extracted flag is verified.",
    keywords: ["zip", "eocd", "comment", "polyglot", "central directory", "forensics"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "candidate", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      prefix: { type: "string", title: "Numbered entry prefix", pattern: "^[A-Za-z0-9_-]{1,32}$", default: "flag" },
    }, required: ["prefix"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 1 * MiB },
  },
  async run(ctx, inputs, params) {
    const source = bytesInput(inputs);
    if (source.size > MiB) throw new OperationError("INPUT_TOO_LARGE", "ZIP end-record chain exceeds 1 MiB");
    try {
      ctx.throwIfAborted();
      const result = inspectZipEndChain(await readAll(source), params.prefix, ctx.signal);
      if (!result.candidate) throw new Error("No contiguous CRC-verified numbered ZIP entries were found for the selected prefix");
      ctx.diagnostic(`${result.records.length} EOF-anchored end records; recovered ${result.candidate.length} candidate byte(s) from CRC-verified entries.`);
      return { candidate: bytesFrom(result.candidate), report: structuredValue({ records: result.records,
        candidateText: result.candidateText, candidateBytes: result.candidate.length, verified: false }) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const zipPlainExtract = defineOperation<{ entryIndex: number; maxOutputBytes: number }>({
  spec: {
    id: "archive.zip.extract-plain", version: "1.0.0", title: "Extract unencrypted ZIP entry", category: "Forensics",
    description: "Extract one stored or deflated entry from a consistent, unencrypted ZIP. Checks size and CRC; does not interpret ambiguous local versus central records.",
    keywords: ["zip", "extract", "plaintext", "deflate", "crc", "archive"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      entryIndex: { type: "integer", title: "Central-directory entry index", minimum: 0, maximum: 9999, default: 0 },
      maxOutputBytes: { type: "integer", title: "Maximum extracted bytes", minimum: 1, maximum: 16 * MiB, default: 1 * MiB },
    }, required: ["entryIndex", "maxOutputBytes"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
    limits: { maxInputBytes: 16 * MiB },
  },
  async run(ctx, inputs, params) {
    const source = bytesInput(inputs);
    if (source.size > 16 * MiB) throw new OperationError("INPUT_TOO_LARGE", "Plain ZIP input exceeds 16 MiB");
    try {
      ctx.throwIfAborted();
      const inspected = await inspectZip(source, ctx.signal);
      const candidate = inspected.entries[params.entryIndex];
      if (!inspected.eocd || !candidate || !candidate.consistent || candidate.encryption !== "none" ||
        (candidate.method !== 0 && candidate.method !== 8)) throw new Error("Selected ZIP entry must be consistent, unencrypted, stored or deflated");
      if (candidate.uncompressedSize > params.maxOutputBytes || candidate.compressedSize > 16 * MiB) {
        throw new OperationError("INPUT_TOO_LARGE", "Selected ZIP entry exceeds the extraction budget");
      }
      const entries = await readZip(new Blob([await readAll(source)]));
      const entry = entries[params.entryIndex];
      if (!entry || entry.name !== candidate.name || entry.crc32 !== Number.parseInt(candidate.crc32.slice(2), 16)) {
        throw new Error("ZIP directory parsers disagree about the selected entry");
      }
      const output = await zipEntryData(entry, params.maxOutputBytes);
      ctx.throwIfAborted();
      ctx.diagnostic(`Extracted ${candidate.name}: ${output.size} CRC-verified byte(s).`);
      return { data: bytesFrom(new Uint8Array(await output.arrayBuffer())),
        report: structuredValue({ name: candidate.name, bytes: output.size, method: candidate.method, verified: true }) };
    } catch (error) {
      ctx.throwIfAborted();
      if (error instanceof OperationError) throw error;
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const zipExtract = defineOperation<{ entryIndex: number; password: string; maxEncryptedBytes: number; maxOutputBytes: number }>({
  spec: {
    id: "archive.zip.extract", version: "1.0.0", title: "Extract encrypted ZIP entry", category: "Forensics",
    description: "Decrypt and extract one traditional ZipCrypto ZIP entry with a known password. Stored and deflated content is returned only after size and CRC validation; AES is not supported.",
    keywords: ["zip", "zipcrypto", "password", "decrypt", "extract", "deflate"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      entryIndex: { type: "integer", title: "Central-directory entry index", minimum: 0, maximum: 9999, default: 0 },
      password: { type: "string", title: "Password", minLength: 1, maxLength: 128, default: "" },
      maxEncryptedBytes: { type: "integer", title: "Maximum encrypted entry bytes", minimum: 12, maximum: 64 * MiB, default: 1 * MiB },
      maxOutputBytes: { type: "integer", title: "Maximum decompressed bytes", minimum: 1, maximum: 64 * MiB, default: 1 * MiB },
    }, required: ["entryIndex", "password", "maxEncryptedBytes", "maxOutputBytes"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
  },
  async run(ctx, inputs, params) {
    const source = bytesInput(inputs);
    const archive = await inspectZip(source, ctx.signal);
    const entry = archive.entries[params.entryIndex];
    if (!entry) throw new OperationError("INVALID_PARAMS", `ZIP entry ${params.entryIndex} does not exist`);
    if (entry.encryption !== "ZipCrypto") throw new OperationError("INVALID_INPUT", `${entry.name} is not a traditional ZipCrypto entry`);
    if (entry.dataOffset === null || entry.dataEnd === null || entry.dataEnd > source.size) throw new OperationError("INVALID_INPUT", `${entry.name} has no complete encrypted data record`);
    if (entry.compressedSize > params.maxEncryptedBytes || entry.uncompressedSize > params.maxOutputBytes) throw new OperationError("INPUT_TOO_LARGE", `${entry.name} exceeds the selected encrypted or decompressed byte limit`);
    const encrypted = await source.read(entry.dataOffset, entry.compressedSize);
    const check = entry.flags & 0x0008 ? entry.modifiedTime : Number.parseInt(entry.crc32.slice(2), 16) >>> 16;
    const result = await testZipCryptoPassword(encrypted, new TextEncoder().encode(params.password), {
      checkByte: (check >>> 8) & 0xff, method: entry.method, crc32: Number.parseInt(entry.crc32.slice(2), 16),
      uncompressedSize: entry.uncompressedSize, maxOutputBytes: params.maxOutputBytes, exposePlaintext: true, signal: ctx.signal,
    });
    if (result.status === "header-match") throw new OperationError("UNAVAILABLE", result.reason);
    if (result.status !== "verified" || !result.plaintext) throw new OperationError("INVALID_INPUT", "Password did not fully verify against decrypted size and CRC");
    ctx.diagnostic(`Extracted ${entry.name}: ${result.plaintext.length} verified byte(s).`);
    return { data: bytesFrom(result.plaintext), report: structuredValue({ name: entry.name, method: entry.method, bytes: result.plaintext.length, verified: true }) };
  },
});

export const zipExtractKeys = defineOperation<{ entryIndex: number; keys: string; maxEncryptedBytes: number; maxOutputBytes: number }>({
  spec: {
    id: "archive.zip.extract-keys", version: "1.0.0", title: "Extract ZIP with internal keys", category: "Forensics",
    description: "Extract one traditional ZipCrypto entry with three independently recovered internal keys, not a password. Return plaintext only after header, size and CRC-32 verification.",
    keywords: ["zip", "zipcrypto", "bkcrack", "internal keys", "decrypt", "extract"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      entryIndex: { type: "integer", title: "Central-directory entry index", minimum: 0, maximum: 9999, default: 0 },
      keys: { type: "string", title: "Internal keys (three 8-digit hex words)", minLength: 26, maxLength: 26, default: "" },
      maxEncryptedBytes: { type: "integer", title: "Maximum encrypted entry bytes", minimum: 12, maximum: 64 * MiB, default: 1 * MiB },
      maxOutputBytes: { type: "integer", title: "Maximum decompressed bytes", minimum: 1, maximum: 64 * MiB, default: 1 * MiB },
    }, required: ["entryIndex", "keys", "maxEncryptedBytes", "maxOutputBytes"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: false, sideEffects: "none", cost: "medium",
  },
  async run(ctx, inputs, params) {
    if (!/^[0-9a-f]{8} [0-9a-f]{8} [0-9a-f]{8}$/i.test(params.keys)) throw new OperationError("INVALID_PARAMS", "Supply three 8-digit hexadecimal ZipCrypto keys separated by spaces");
    const source = bytesInput(inputs);
    const archive = await inspectZip(source, ctx.signal);
    const entry = archive.entries[params.entryIndex];
    if (!entry) throw new OperationError("INVALID_PARAMS", `ZIP entry ${params.entryIndex} does not exist`);
    if (entry.encryption !== "ZipCrypto" || !entry.consistent || entry.dataOffset === null || entry.dataEnd === null || entry.dataEnd > source.size) {
      throw new OperationError("INVALID_INPUT", `${entry.name} is not a complete, consistent ZipCrypto entry`);
    }
    if (entry.compressedSize > params.maxEncryptedBytes || entry.uncompressedSize > params.maxOutputBytes) throw new OperationError("INPUT_TOO_LARGE", `${entry.name} exceeds the selected encrypted or decompressed byte limit`);
    const encrypted = await source.read(entry.dataOffset, entry.compressedSize);
    const check = entry.flags & 0x0008 ? entry.modifiedTime : Number.parseInt(entry.crc32.slice(2), 16) >>> 16;
    const [first, second, third] = params.keys.split(" ").map((key) => Number.parseInt(key, 16));
    const result = await testZipCryptoKeys(encrypted, { first, second, third }, {
      checkByte: (check >>> 8) & 0xff, method: entry.method, crc32: Number.parseInt(entry.crc32.slice(2), 16),
      uncompressedSize: entry.uncompressedSize, maxOutputBytes: params.maxOutputBytes, exposePlaintext: true, signal: ctx.signal,
    });
    if (result.status === "header-match") throw new OperationError("UNAVAILABLE", result.reason);
    if (result.status !== "verified" || !result.plaintext) throw new OperationError("INVALID_INPUT", "Internal keys did not fully verify against decrypted size and CRC");
    ctx.diagnostic(`Extracted ${entry.name}: ${result.plaintext.length} verified byte(s) with supplied internal keys.`);
    return { data: bytesFrom(result.plaintext), report: structuredValue({ name: entry.name, method: entry.method, bytes: result.plaintext.length, verified: true, keySource: "supplied" }) };
  },
});

export const rar7zInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "archive.rar7z.inspect",
    version: "1.0.0",
    title: "Inspect RAR / 7z archive",
    category: "Forensics",
    description: "Inspect bounded RAR4, RAR5, or 7z headers and identify supported archive- or file-encryption markers without extracting content.",
    keywords: ["rar", "rar4", "rar5", "7z", "7zip", "archive", "encryption"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "medium",
  },
  async run(ctx, inputs) {
    try {
      return { report: structuredValue(await inspectRar7z(bytesInput(inputs), ctx.signal)) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const sevenZipHashExport = defineOperation<Record<string, never>>({
  spec: {
    id: "archive.sevenzip.hash-export",
    version: "1.0.0",
    title: "Export 7z password hash",
    category: "Forensics",
    description: "Export a single-stream AES-256 encrypted 7z header in $7z$ form for Hashcat and John the Ripper.",
    keywords: ["7z", "7zip", "7z2john", "hashcat", "john", "password", "hash export"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "hash", type: "text" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "medium",
  },
  async run(ctx, inputs) {
    try {
      const exported = await exportSevenZipHash(bytesInput(inputs), ctx.signal);
      ctx.diagnostic("Exported an AES-256 encrypted 7z header for Hashcat mode 11600 and John the Ripper.");
      return { hash: textValue(exported.hash) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const rar5HashExport = defineOperation<Record<string, never>>({
  spec: {
    id: "archive.rar5.hash-export",
    version: "1.0.0",
    title: "Export RAR5 password hash",
    category: "Forensics",
    description: "Export a RAR5 encrypted-header password hash in $rar5$ form for Hashcat and John the Ripper.",
    keywords: ["rar", "rar5", "rar2john", "hashcat", "john", "password", "hash export"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "hash", type: "text" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "low",
  },
  async run(ctx, inputs) {
    try {
      const exported = await exportRar5Hash(bytesInput(inputs), ctx.signal);
      ctx.diagnostic("Exported a RAR5 encrypted header for Hashcat mode 13000 and John the Ripper.");
      return { hash: textValue(exported.hash) };
    } catch (error) {
      ctx.throwIfAborted();
      throw new OperationError("INVALID_INPUT", error instanceof Error ? error.message : String(error));
    }
  },
});

export const zipInspect = defineOperation<Record<string, never>>({
  spec: {
    id: "archive.zip.inspect",
    version: "1.0.0",
    title: "Inspect ZIP archive",
    category: "Forensics",
    description: "Compare ZIP local headers with the central directory and identify encryption, duplicate names, overlapping entries, malformed bounds, and trailing data.",
    keywords: ["zip", "archive", "recover", "central directory", "local header", "encryption", "polyglot"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "medium",
  },
  async run(ctx, inputs) {
    return { report: structuredValue(await inspectZip(bytesInput(inputs), ctx.signal)) };
  },
});

export const zipCrc32FourByte = defineOperation<{ entryIndex: number }>({
  spec: {
    id: "archive.zip.crc32-preimage4", version: "1.0.0", title: "Recover four-byte ZIP entry from CRC", category: "Forensics",
    description: "Recover the unique four-byte plaintext of a ZIP entry from its CRC-32 without a password. Only consistent entries declaring exactly four uncompressed bytes are accepted; other entry data stays encrypted.",
    keywords: ["zip", "crc32", "preimage", "encrypted", "four bytes", "recover"],
    inputs: [{ name: "data", type: "bytes" }], outputs: [{ name: "data", type: "bytes" }, { name: "report", type: "structured" }],
    parametersSchema: { type: "object", properties: {
      entryIndex: { type: "integer", title: "Central-directory entry index", minimum: 0, maximum: 9999, default: 0 },
    }, required: ["entryIndex"], additionalProperties: false },
    runtime: "ts", deterministic: true, streaming: true, sideEffects: "none", cost: "low",
  },
  async run(ctx, inputs, params) {
    const archive = await inspectZip(bytesInput(inputs), ctx.signal);
    const entry = archive.entries[params.entryIndex];
    if (!entry || archive.limited || !entry.consistent || entry.uncompressedSize !== 4 || !/^0x[0-9a-f]{8}$/i.test(entry.crc32)) {
      throw new OperationError("UNAVAILABLE", "A consistent four-byte ZIP entry with a CRC-32 is required");
    }
    const checksum = Number.parseInt(entry.crc32.slice(2), 16);
    const recovered = crc32FourBytePreimage(checksum);
    if (crc32(recovered) !== checksum) throw new OperationError("INVALID_INPUT", "Recovered bytes do not match the entry CRC-32");
    ctx.diagnostic(`Recovered four bytes for ${entry.name} from its CRC-32; this does not decrypt other archive entries.`);
    return { data: bytesValue(new MemorySource(recovered)), report: structuredValue({ name: entry.name, crc32: entry.crc32, length: 4, encryption: entry.encryption }) };
  },
});

export const zipRebuild = defineOperation<Record<string, never>>({
  spec: {
    id: "archive.zip.rebuild",
    version: "1.0.0",
    title: "Rebuild ZIP directory",
    category: "Forensics",
    description: "Recover intact ZIP local records with explicit sizes and write a new central directory. Records that rely on data descriptors are not guessed.",
    keywords: ["zip", "archive", "recover", "repair", "central directory", "carve"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "data", type: "bytes" }],
    parametersSchema: { type: "object", properties: {}, additionalProperties: false },
    runtime: "ts",
    deterministic: true,
    streaming: true,
    sideEffects: "none",
    cost: "medium",
  },
  async run(ctx, inputs) {
    const source = bytesInput(inputs);
    const { records, limited } = await discoverRecoverableZipRecords(source, ctx.signal);
    if (records.length === 0) throw new OperationError("INVALID_INPUT", "No recoverable ZIP local records with explicit sizes were found");
    if (records.length > 0xffff) throw new OperationError("INPUT_TOO_LARGE", "Too many records for a non-ZIP64 rebuilt archive");

    const parts = [];
    const central: Uint8Array<ArrayBuffer>[] = [];
    let outputOffset = 0;
    for (const record of records) {
      ctx.throwIfAborted();
      if (outputOffset >= 0xffffffff) throw new OperationError("INPUT_TOO_LARGE", "Recovered data is too large for a non-ZIP64 archive");
      parts.push(new SliceSource(source, record.offset, record.length));
      const centralHeader = header(46 + record.nameBytes.length + record.extraBytes.length, (data) => {
        data.setUint32(0, 0x02014b50, true);
        data.setUint16(4, 20, true);
        data.setUint16(6, record.versionNeeded, true);
        data.setUint16(8, record.flags, true);
        data.setUint16(10, record.method, true);
        data.setUint16(12, record.modifiedTime, true);
        data.setUint16(14, record.modifiedDate, true);
        data.setUint32(16, record.crc32, true);
        data.setUint32(20, record.compressedSize, true);
        data.setUint32(24, record.uncompressedSize, true);
        data.setUint16(28, record.nameBytes.length, true);
        data.setUint16(30, record.extraBytes.length, true);
        data.setUint32(42, outputOffset, true);
      });
      centralHeader.set(record.nameBytes, 46);
      centralHeader.set(record.extraBytes, 46 + record.nameBytes.length);
      central.push(centralHeader);
      outputOffset += record.length;
    }
    const centralSize = central.reduce((total, bytes) => total + bytes.length, 0);
    if (outputOffset + centralSize >= 0xffffffff) throw new OperationError("INPUT_TOO_LARGE", "Rebuilt archive is too large for ZIP32");
    const end = header(22, (data) => {
      data.setUint32(0, 0x06054b50, true);
      data.setUint16(8, records.length, true);
      data.setUint16(10, records.length, true);
      data.setUint32(12, centralSize, true);
      data.setUint32(16, outputOffset, true);
    });
    for (const bytes of central) parts.push(new MemorySource(bytes));
    parts.push(new MemorySource(end));
    ctx.diagnostic(`Recovered ${records.length} local record(s) into a new ZIP central directory.${limited ? " The scan limit was reached." : ""}`);
    return { data: bytesValue(new ConcatSource(parts)) };
  },
});

export const zipPasswordTest = defineOperation<{ entryIndex: number; source: "dictionary" | "mask"; candidates: string; mask: string; customCharset: string; maxAttempts: number; maxEncryptedBytes: number; maxOutputBytes: number }>({
  spec: {
    id: "archive.zip.password-test",
    version: "1.1.0",
    title: "Test ZIP passwords",
    category: "Forensics",
    description: "Test a bounded UTF-8 dictionary or Hashcat-style mask against one traditional ZipCrypto entry. Stored and deflated data is fully verified by size and CRC-32.",
    keywords: ["zip", "zipcrypto", "password", "dictionary", "mask", "decrypt"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        entryIndex: { type: "integer", title: "Central-directory entry index", minimum: 0, maximum: 9999, default: 0 },
        source: { type: "string", title: "Candidate source", enum: ["dictionary", "mask"], default: "dictionary" },
        candidates: { type: "string", title: "Candidate passwords (one per line)", multiline: true, maxLength: 1_000_000, default: "password\nsecret\nflag" },
        mask: { type: "string", title: "Mask (?l ?u ?d ?s ?a ?1 ??)", maxLength: 128, default: "flag?d?d?d" },
        customCharset: { type: "string", title: "Custom ?1 characters", maxLength: 1024, default: "" },
        maxAttempts: { type: "integer", title: "Maximum attempts", minimum: 1, maximum: 100_000, default: 1_000 },
        maxEncryptedBytes: { type: "integer", title: "Maximum encrypted entry bytes", minimum: 12, maximum: 256 * MiB, default: 64 * MiB },
        maxOutputBytes: { type: "integer", title: "Maximum decompressed bytes", minimum: 1, maximum: 512 * MiB, default: 64 * MiB },
      },
      required: ["entryIndex", "source", "candidates", "mask", "customCharset", "maxAttempts", "maxEncryptedBytes", "maxOutputBytes"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "high",
  },
  async run(ctx, inputs, params) {
    const source = bytesInput(inputs);
    const archive = await inspectZip(source, ctx.signal);
    const entry = archive.entries[params.entryIndex];
    if (!entry) throw new OperationError("INVALID_PARAMS", `ZIP entry ${params.entryIndex} does not exist`);
    if (entry.encryption !== "ZipCrypto") throw new OperationError("INVALID_INPUT", `${entry.name} uses ${entry.encryption === "AES" ? "AES encryption, not traditional ZipCrypto" : "no encryption"}`);
    if (entry.dataOffset === null || entry.passwordCheckByte === null) throw new OperationError("INVALID_INPUT", `${entry.name} has no usable local data record`);
    if (entry.compressedSize > params.maxEncryptedBytes) throw new OperationError("INPUT_TOO_LARGE", `${entry.name} has ${entry.compressedSize} encrypted bytes, above the configured ${params.maxEncryptedBytes} limit`);
    if (entry.uncompressedSize > params.maxOutputBytes) throw new OperationError("INPUT_TOO_LARGE", `${entry.name} declares ${entry.uncompressedSize} output bytes, above the configured ${params.maxOutputBytes} limit`);
    const encrypted = await source.read(entry.dataOffset, entry.compressedSize);
    if (encrypted.length !== entry.compressedSize) throw new OperationError("INVALID_INPUT", `${entry.name} is truncated`);
    const dictionary = params.candidates.replace(/\r/g, "").split("\n");
    const generated = params.source === "mask"
      ? generateMaskCandidates(params.mask, params.customCharset, params.maxAttempts)
      : { values: dictionary.slice(0, params.maxAttempts), truncated: dictionary.length > params.maxAttempts };
    const candidates = generated.values;
    const encoder = new TextEncoder();
    const matches: { password: string; status: "verified" | "header-match"; reason?: string }[] = [];
    for (let index = 0; index < candidates.length; index++) {
      ctx.throwIfAborted();
      const result = await testZipCryptoPassword(encrypted, encoder.encode(candidates[index]), {
        checkByte: entry.passwordCheckByte,
        method: entry.method,
        crc32: Number.parseInt(entry.crc32.slice(2), 16),
        uncompressedSize: entry.uncompressedSize,
        maxOutputBytes: params.maxOutputBytes,
        signal: ctx.signal,
      });
      if (result.status === "verified") matches.push({ password: candidates[index], status: "verified" });
      else if (result.status === "header-match") matches.push({ password: candidates[index], status: "header-match", reason: result.reason });
      if ((index + 1) % 250 === 0) await yieldToEventLoop();
    }
    return { report: structuredValue({ entryIndex: params.entryIndex, name: entry.name, encryption: entry.encryption, source: params.source, attempted: candidates.length, truncated: generated.truncated, matches }) };
  },
});

export const zipKnownPlaintext = defineOperation<{ entryIndex: number; knownPlaintext: string; encoding: "utf8" | "hex"; plaintextOffset: number; maxCandidates: number; maxEncryptedBytes: number }>({
  spec: {
    id: "archive.zip.known-plaintext",
    version: "1.0.0",
    title: "Recover ZipCrypto keys",
    category: "Forensics",
    description: "Run bkcrack's known-plaintext attack against one traditional ZipCrypto entry. The known bytes must correspond to the compressed plaintext stream; this does not work against AES ZIP encryption.",
    keywords: ["zip", "zipcrypto", "known plaintext", "bkcrack", "internal keys", "decrypt"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "report", type: "structured" }],
    parametersSchema: {
      type: "object",
      properties: {
        entryIndex: { type: "integer", title: "Central-directory entry index", minimum: 0, maximum: 9999, default: 0 },
        knownPlaintext: { type: "string", title: "Known compressed-stream bytes", multiline: true, maxLength: 1_000_000, default: "" },
        encoding: { type: "string", title: "Known-byte encoding", enum: ["utf8", "hex"], default: "hex" },
        plaintextOffset: { type: "integer", title: "Plaintext offset (-12 includes encryption header)", minimum: -12, maximum: 512 * MiB, default: 0 },
        maxCandidates: { type: "integer", title: "Maximum reduced states to test", minimum: 1, maximum: 10_000_000, default: 500_000 },
        maxEncryptedBytes: { type: "integer", title: "Maximum encrypted entry bytes", minimum: 24, maximum: 64 * MiB, default: 16 * MiB },
      },
      required: ["entryIndex", "knownPlaintext", "encoding", "plaintextOffset", "maxCandidates", "maxEncryptedBytes"],
      additionalProperties: false,
    },
    runtime: "wasm",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "high",
    limits: { maxInputBytes: 256 * MiB },
  },
  async run(ctx, inputs, params) {
    const source = bytesInput(inputs);
    const archive = await inspectZip(source, ctx.signal);
    const entry = archive.entries[params.entryIndex];
    if (!entry) throw new OperationError("INVALID_PARAMS", `ZIP entry ${params.entryIndex} does not exist`);
    if (entry.encryption !== "ZipCrypto") throw new OperationError("INVALID_INPUT", `${entry.name} uses ${entry.encryption === "AES" ? "AES encryption, which is not vulnerable to this attack" : "no encryption"}`);
    if (entry.dataOffset === null) throw new OperationError("INVALID_INPUT", `${entry.name} has no usable local data record`);
    if (entry.compressedSize > params.maxEncryptedBytes) throw new OperationError("INPUT_TOO_LARGE", `${entry.name} has ${entry.compressedSize} encrypted bytes, above the configured ${params.maxEncryptedBytes} limit`);
    const cipher = await source.read(entry.dataOffset, entry.compressedSize);
    if (cipher.length !== entry.compressedSize) throw new OperationError("INVALID_INPUT", `${entry.name} is truncated`);
    const plain = params.encoding === "hex" ? parseHex(params.knownPlaintext, true) : new TextEncoder().encode(params.knownPlaintext);
    if (plain.length < 12) throw new OperationError("INVALID_PARAMS", `Known plaintext has ${plain.length} bytes; bkcrack requires at least 12 contiguous bytes`);
    if (params.plaintextOffset + plain.length > entry.compressedSize - 12) {
      throw new OperationError("INVALID_PARAMS", `Known plaintext extends past the ${entry.compressedSize - 12}-byte compressed stream`);
    }

    const { loadBkcrack, prepareBkcrack } = await importPack("bkcrack", () => import("../../runtimes/bkcrack"));
    const module = await loadBkcrack();
    const session = prepareBkcrack(module, cipher, plain, params.plaintextOffset);
    let state: "found" | "complete" | "running" = "running";
    try {
      while (state === "running" && session.cursor() < params.maxCandidates) {
        ctx.throwIfAborted();
        state = session.step(Math.min(128, params.maxCandidates - session.cursor()));
        await yieldToEventLoop();
      }
      const keys = session.keys();
      const attempted = session.cursor();
      const hexKey = (value: number) => value.toString(16).padStart(8, "0");
      ctx.diagnostic(keys ? `Recovered ZipCrypto internal keys after ${attempted.toLocaleString()} candidate(s).` : `Tested ${attempted.toLocaleString()} of ${session.total.toLocaleString()} reduced states without finding keys.`);
      return { report: structuredValue({
        entryIndex: params.entryIndex,
        name: entry.name,
        algorithm: "traditional ZipCrypto",
        knownPlaintextBytes: plain.length,
        plaintextOffset: params.plaintextOffset,
        attempted,
        totalCandidates: session.total,
        exhausted: state === "complete",
        keys: keys ? { x: hexKey(keys.x), y: hexKey(keys.y), z: hexKey(keys.z), command: `bkcrack -k ${hexKey(keys.x)} ${hexKey(keys.y)} ${hexKey(keys.z)}` } : null,
      }) };
    } finally {
      session.reset();
    }
  },
});

export const zipHashExport = defineOperation<{ entryIndex: number }>({
  spec: {
    id: "archive.zip.hash-export",
    version: "1.0.0",
    title: "Export ZIP password hash",
    category: "Forensics",
    description: "Export one encrypted ZIP entry in John the Ripper and Hashcat compatible form: $pkzip$ for traditional ZipCrypto or $zip2$ for WinZip AES.",
    keywords: ["zip2john", "hashcat", "john", "pkzip", "zip2", "password", "hash export"],
    inputs: [{ name: "data", type: "bytes" }],
    outputs: [{ name: "hash", type: "text" }],
    parametersSchema: {
      type: "object",
      properties: { entryIndex: { type: "integer", title: "Central-directory entry index", minimum: 0, maximum: 9999, default: 0 } },
      required: ["entryIndex"],
      additionalProperties: false,
    },
    runtime: "ts",
    deterministic: true,
    streaming: false,
    sideEffects: "none",
    cost: "medium",
  },
  async run(ctx, inputs, params) {
    const source = bytesInput(inputs);
    const archive = await inspectZip(source, ctx.signal);
    const entry = archive.entries[params.entryIndex];
    if (!entry) throw new OperationError("INVALID_PARAMS", `ZIP entry ${params.entryIndex} does not exist`);
    if (entry.encryption === "none") throw new OperationError("INVALID_INPUT", `${entry.name} is not encrypted`);
    if (entry.dataOffset === null || entry.dataEnd === null || entry.dataEnd > source.size) throw new OperationError("INVALID_INPUT", `${entry.name} has no complete local data record`);

    if (entry.encryption === "ZipCrypto") {
      if (entry.method !== 0 && entry.method !== 8) throw new OperationError("UNAVAILABLE", `Traditional ZipCrypto export supports stored and deflated entries, not method ${entry.method}`);
      if (entry.compressedSize > MAX_HASHCAT_PKZIP_DATA) throw new OperationError("INPUT_TOO_LARGE", `${entry.name} has ${entry.compressedSize} encrypted bytes; inline $pkzip$ is capped at Hashcat's ${MAX_HASHCAT_PKZIP_DATA}-byte parser limit`);
      const encrypted = await source.read(entry.dataOffset, entry.compressedSize);
      const checksum = entry.flags & 0x0008 ? entry.modifiedTime : Number.parseInt(entry.crc32.slice(2), 16) >>> 16;
      const checkBytes = entry.versionNeeded < 20 ? 2 : 1;
      const fields = [
        "$pkzip$1", checkBytes, 2, 0,
        entry.compressedSize.toString(16), entry.uncompressedSize.toString(16), entry.crc32.slice(2),
        0, entry.dataOffset.toString(16), entry.method, entry.compressedSize.toString(16),
        checksum.toString(16).padStart(4, "0"), toHex(encrypted), "$/pkzip$",
      ];
      ctx.diagnostic(`Exported ${entry.name} for Hashcat mode ${entry.method === 0 ? 17210 : 17200} and John the Ripper.`);
      return { hash: textValue(fields.join("*")) };
    }

    if (!entry.aes) throw new OperationError("INVALID_INPUT", `${entry.name} is marked as AES but has no valid 0x9901 AES extra field`);
    if (entry.aes.vendorVersion < 1 || entry.aes.vendorVersion > 2) throw new OperationError("UNAVAILABLE", `${entry.name} uses unsupported WinZip AES vendor version ${entry.aes.vendorVersion}`);
    if (entry.compressedSize > MAX_HASHCAT_AES_DATA) throw new OperationError("INPUT_TOO_LARGE", `${entry.name} has ${entry.compressedSize} encrypted bytes; inline $zip2$ export is capped at ${MAX_HASHCAT_AES_DATA}`);
    const overhead = entry.aes.saltLength + 2 + 10;
    if (entry.compressedSize < overhead) throw new OperationError("INVALID_INPUT", `${entry.name} is too short to contain WinZip AES salt, verifier, and authentication code`);
    const encrypted = await source.read(entry.dataOffset, entry.compressedSize);
    const saltEnd = entry.aes.saltLength;
    const verifierEnd = saltEnd + 2;
    const authStart = encrypted.length - 10;
    const cipher = encrypted.slice(verifierEnd, authStart);
    const hash = `$zip2$*0*${entry.aes.strength}*0*${toHex(encrypted.slice(0, saltEnd))}*${toHex(encrypted.slice(saltEnd, verifierEnd))}*${cipher.length.toString(16)}*${toHex(cipher)}*${toHex(encrypted.slice(authStart))}*$/zip2$`;
    ctx.diagnostic(`Exported ${entry.name} (WinZip AES-${entry.aes.keyBits}) for Hashcat mode 13600 and John the Ripper.`);
    return { hash: textValue(hash) };
  },
});