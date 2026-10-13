import type { ByteSource, Bytes } from "../core/bytes/ByteSource";

const MAX_TAIL_BYTES = 1024 * 1024;
const MAX_XREF_BYTES = 2 * 1024 * 1024;
const MAX_OBJECT_BYTES = 1024 * 1024;
const decoder = new TextDecoder("windows-1252");

export interface PdfEncryptionReport {
  version: string;
  algorithm: number;
  revision: number;
  keyBits: number;
  permissions: number;
  encryptMetadata: boolean;
  documentId: string;
  userEntryBytes: number;
  ownerEntryBytes: number;
  userKeyBytes: number | null;
  ownerKeyBytes: number | null;
  hash: string;
}

async function exact(source: ByteSource, offset: number, length: number): Promise<Bytes | null> {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > source.size) return null;
  const bytes = await source.read(offset, length);
  return bytes.length === length ? bytes : null;
}

type TokenKind = "name" | "number" | "boolean" | "hex" | "literal" | "dictStart" | "dictEnd" | "arrayStart" | "arrayEnd" | "word";
interface Token { kind: TokenKind; value: string }

const isSpace = (char: string): boolean => /[\0\t\n\f\r ]/.test(char);
const isDelimiter = (char: string): boolean => isSpace(char) || /[()<>\[\]{}/%]/.test(char);

function tokens(text: string): Token[] {
  const result: Token[] = [];
  for (let index = 0; index < text.length;) {
    const char = text[index];
    if (isSpace(char)) { index++; continue; }
    if (char === "%") {
      while (index < text.length && text[index] !== "\n" && text[index] !== "\r") index++;
      continue;
    }
    if (text.startsWith("<<", index) || text.startsWith(">>", index)) {
      result.push({ kind: text[index] === "<" ? "dictStart" : "dictEnd", value: text.slice(index, index + 2) });
      index += 2;
      continue;
    }
    if (char === "[" || char === "]") {
      result.push({ kind: char === "[" ? "arrayStart" : "arrayEnd", value: char });
      index++;
      continue;
    }
    if (char === "<") {
      const end = text.indexOf(">", index + 1);
      if (end < 0) throw new Error("PDF contains an unterminated hex string");
      let value = text.slice(index + 1, end).replace(/[\0\t\n\f\r ]/g, "");
      if (!/^[0-9a-fA-F]*$/.test(value)) throw new Error("PDF contains an invalid hex string");
      if (value.length % 2 !== 0) value += "0";
      result.push({ kind: "hex", value: value.toLowerCase() });
      index = end + 1;
      continue;
    }
    if (char === "(") {
      const start = index++;
      let depth = 1;
      while (index < text.length && depth > 0) {
        if (text[index] === "\\") index += Math.min(2, text.length - index);
        else {
          if (text[index] === "(") depth++;
          if (text[index] === ")") depth--;
          index++;
        }
      }
      if (depth !== 0) throw new Error("PDF contains an unterminated literal string");
      result.push({ kind: "literal", value: text.slice(start, index) });
      continue;
    }
    if (char === "/") {
      const start = ++index;
      while (index < text.length && !isDelimiter(text[index])) index++;
      const raw = text.slice(start, index);
      result.push({ kind: "name", value: raw.replace(/#([0-9a-fA-F]{2})/g, (_match, pair: string) => String.fromCharCode(Number.parseInt(pair, 16))) });
      continue;
    }
    const start = index;
    while (index < text.length && !isDelimiter(text[index])) index++;
    if (start === index) throw new Error(`PDF contains an unexpected ${JSON.stringify(char)} token`);
    const value = text.slice(start, index);
    if (/^[+-]?(?:\d+\.\d*|\.\d+|\d+)$/.test(value)) result.push({ kind: "number", value });
    else if (value === "true" || value === "false") result.push({ kind: "boolean", value });
    else result.push({ kind: "word", value });
  }
  return result;
}

function dictionaryEntries(text: string, label: string): Map<string, Token[]> {
  const parsed = tokens(text);
  if (parsed[0]?.kind !== "dictStart") throw new Error(`PDF ${label} is not a direct dictionary`);
  const entries = new Map<string, Token[]>();
  for (let index = 1; index < parsed.length;) {
    const token = parsed[index];
    if (token.kind === "dictEnd") {
      if (index !== parsed.length - 1) throw new Error(`PDF ${label} has data after its dictionary`);
      return entries;
    }
    if (token.kind !== "name") throw new Error(`PDF ${label} contains an unexpected top-level ${token.kind} token`);
    if (entries.has(token.value)) throw new Error(`PDF ${label} contains duplicate /${token.value} entries`);
    const valueStart = index + 1;
    if (valueStart >= parsed.length || parsed[valueStart].kind === "dictEnd") throw new Error(`PDF /${token.value} has no value`);
    let valueEnd = valueStart + 1;
    if (parsed[valueStart].kind === "dictStart" || parsed[valueStart].kind === "arrayStart") {
      const open = parsed[valueStart].kind;
      const close = open === "dictStart" ? "dictEnd" : "arrayEnd";
      let depth = 1;
      while (valueEnd < parsed.length && depth > 0) {
        if (parsed[valueEnd].kind === open) depth++;
        if (parsed[valueEnd].kind === close) depth--;
        valueEnd++;
      }
      if (depth !== 0) throw new Error(`PDF /${token.value} compound value is unterminated`);
    } else if (parsed[valueStart].kind === "number" && parsed[valueStart + 1]?.kind === "number" && parsed[valueStart + 2]?.kind === "word" && parsed[valueStart + 2].value === "R") {
      valueEnd = valueStart + 3;
    }
    entries.set(token.value, parsed.slice(valueStart, valueEnd));
    index = valueEnd;
  }
  throw new Error(`PDF ${label} dictionary is unterminated`);
}

function directDictionaryExtent(text: string): { start: number; end: number } {
  let index = 0;
  while (index < text.length) {
    if (isSpace(text[index])) { index++; continue; }
    if (text[index] === "%") {
      while (index < text.length && text[index] !== "\n" && text[index] !== "\r") index++;
      continue;
    }
    break;
  }
  if (!text.startsWith("<<", index)) throw new Error("PDF encryption object is not a direct dictionary");
  const start = index;
  let depth = 0;
  while (index < text.length) {
    if (text[index] === "%") {
      while (index < text.length && text[index] !== "\n" && text[index] !== "\r") index++;
    } else if (text[index] === "(") {
      let literalDepth = 1;
      index++;
      while (index < text.length && literalDepth > 0) {
        if (text[index] === "\\") index += Math.min(2, text.length - index);
        else {
          if (text[index] === "(") literalDepth++;
          if (text[index] === ")") literalDepth--;
          index++;
        }
      }
      if (literalDepth !== 0) throw new Error("PDF contains an unterminated literal string");
    } else if (text.startsWith("<<", index)) {
      depth++;
      index += 2;
    } else if (text.startsWith(">>", index)) {
      depth--;
      index += 2;
      if (depth === 0) return { start, end: index };
    } else if (text[index] === "<") {
      const end = text.indexOf(">", index + 1);
      if (end < 0) throw new Error("PDF contains an unterminated hex string");
      index = end + 1;
    } else index++;
  }
  throw new Error("PDF encryption dictionary is unterminated");
}

function onlyWhitespaceAndComments(text: string): boolean {
  return text.replace(/%[^\r\n]*(?:\r\n|\r|\n|$)/g, "").trim().length === 0;
}

function entry(map: Map<string, Token[]>, name: string, required = true): Token[] | null {
  const value = map.get(name) ?? null;
  if (!value && required) throw new Error(`PDF encryption dictionary has no /${name} entry`);
  return value;
}

function integerEntry(map: Map<string, Token[]>, name: string, required = true): number | null {
  const value = entry(map, name, required);
  if (!value) return null;
  if (value.length !== 1 || value[0].kind !== "number" || !/^[+-]?\d+$/.test(value[0].value)) throw new Error(`PDF /${name} must be an integer`);
  const number = Number(value[0].value);
  if (!Number.isSafeInteger(number)) throw new Error(`PDF /${name} value exceeds JavaScript's safe integer range`);
  return number;
}

function hexEntry(map: Map<string, Token[]>, name: string, required = true): Bytes | null {
  const value = entry(map, name, required);
  if (!value) return null;
  if (value.length !== 1 || value[0].kind !== "hex") throw new Error(`PDF /${name} must be a direct hex string in this bounded exporter`);
  return Uint8Array.from(value[0].value.match(/../g) ?? [], (pair) => Number.parseInt(pair, 16));
}

function hex(bytes: Bytes): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function xrefEntries(text: string): Map<number, { offset: number; generation: number; inUse: boolean }> {
  if (!text.startsWith("xref")) throw new Error("PDF export currently supports classic xref tables only");
  const lines = text.slice(4).trim().split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const entries = new Map<number, { offset: number; generation: number; inUse: boolean }>();
  for (let index = 0; index < lines.length;) {
    const section = /^(\d+)\s+(\d+)$/.exec(lines[index++]);
    if (!section) throw new Error("PDF xref subsection header is invalid");
    const first = Number(section[1]);
    const count = Number(section[2]);
    if (!Number.isSafeInteger(first) || !Number.isSafeInteger(count) || count < 0 || count > 1_000_000) throw new Error("PDF xref subsection is too large");
    for (let entryIndex = 0; entryIndex < count; entryIndex++) {
      const entry = /^(\d{10})\s+(\d{5})\s+([fn])(?:\s|$)/.exec(lines[index++]);
      if (!entry) throw new Error("PDF xref entry is invalid or truncated");
      const objectNumber = first + entryIndex;
      if (entries.has(objectNumber)) throw new Error("PDF xref table contains overlapping subsections");
      entries.set(objectNumber, { offset: Number(entry[1]), generation: Number(entry[2]), inUse: entry[3] === "n" });
    }
  }
  return entries;
}

export async function inspectPdfEncryption(source: ByteSource, signal?: AbortSignal): Promise<PdfEncryptionReport> {
  if (signal?.aborted) throw signal.reason;
  const prefix = await exact(source, 0, Math.min(16, source.size));
  if (!prefix || !decoder.decode(prefix).startsWith("%PDF-")) throw new Error("Input is not a PDF document");
  const versionMatch = /^%PDF-(\d+\.\d+)/.exec(decoder.decode(prefix));
  if (!versionMatch) throw new Error("PDF version header is invalid");

  const tailOffset = Math.max(0, source.size - MAX_TAIL_BYTES);
  const tail = decoder.decode(await source.read(tailOffset, MAX_TAIL_BYTES));
  const starts = [...tail.matchAll(/startxref\s+(\d+)\s+%%EOF/g)];
  if (starts.length === 0) throw new Error("PDF has no bounded startxref trailer");
  if (starts.length !== 1) throw new Error("PDF export does not support multiple xref revisions");
  const finalStart = starts[0];
  if (!onlyWhitespaceAndComments(tail.slice((finalStart.index ?? 0) + finalStart[0].length))) throw new Error("PDF contains data after its final %%EOF marker");
  const xrefOffset = Number(finalStart[1]);
  if (!Number.isSafeInteger(xrefOffset) || xrefOffset < 0 || xrefOffset >= source.size) throw new Error("PDF startxref offset exceeds the document bounds");
  const xrefBytes = await source.read(xrefOffset, Math.min(MAX_XREF_BYTES, source.size - xrefOffset));
  const xrefAndTrailer = decoder.decode(xrefBytes);
  const trailerAt = xrefAndTrailer.indexOf("trailer");
  if (trailerAt < 0) throw new Error("PDF export currently supports classic xref tables only");
  const entries = xrefEntries(xrefAndTrailer.slice(0, trailerAt));
  const startxrefAt = xrefAndTrailer.indexOf("startxref", trailerAt);
  if (startxrefAt < 0) throw new Error("PDF xref trailer exceeds the bounded read limit");
  const trailerText = xrefAndTrailer.slice(trailerAt + 7, startxrefAt).trim();
  const trailerExtent = directDictionaryExtent(trailerText);
  if (!onlyWhitespaceAndComments(trailerText.slice(trailerExtent.end))) throw new Error("PDF trailer contains unexpected data");
  const trailer = dictionaryEntries(trailerText.slice(trailerExtent.start, trailerExtent.end), "trailer");
  if (trailer.has("Prev")) throw new Error("PDF export does not support incremental xref chains");
  if (trailer.has("XRefStm")) throw new Error("PDF export does not support hybrid xref streams");
  const encryptReference = trailer.get("Encrypt");
  const idValue = trailer.get("ID");
  if (!encryptReference || encryptReference.length !== 3 || encryptReference[0].kind !== "number" || encryptReference[1].kind !== "number" || encryptReference[2].kind !== "word" || encryptReference[2].value !== "R") throw new Error("PDF trailer has no direct indirect /Encrypt reference");
  if (!idValue || idValue.length !== 4 || idValue[0].kind !== "arrayStart" || idValue[1].kind !== "hex" || idValue[2].kind !== "hex" || idValue[3].kind !== "arrayEnd") throw new Error("PDF trailer /ID must contain two direct hex strings");
  const objectNumber = Number(encryptReference[0].value);
  const generation = Number(encryptReference[1].value);
  if (!Number.isSafeInteger(objectNumber) || objectNumber < 0 || !Number.isSafeInteger(generation) || generation < 0) throw new Error("PDF encryption object reference is invalid");
  const xrefEntry = entries.get(objectNumber);
  if (!xrefEntry || !xrefEntry.inUse || xrefEntry.generation !== generation || xrefEntry.offset >= xrefOffset) throw new Error("PDF encryption object has no matching xref entry");

  const nextOffset = Math.min(xrefOffset, ...Array.from(entries.values(), (candidate) => candidate.inUse && candidate.offset > xrefEntry.offset && candidate.offset < xrefOffset ? candidate.offset : xrefOffset));
  if (nextOffset - xrefEntry.offset > MAX_OBJECT_BYTES) throw new Error("PDF encryption object exceeds the object limit");
  const objectBytes = await exact(source, xrefEntry.offset, nextOffset - xrefEntry.offset);
  if (!objectBytes) throw new Error("PDF encryption object extent is truncated");
  const objectText = decoder.decode(objectBytes);
  const objectHeader = new RegExp(`^${objectNumber}\\s+${generation}\\s+obj\\b`).exec(objectText);
  if (!objectHeader) throw new Error("PDF encryption object header does not match its xref entry");
  const objectBody = objectText.slice(objectHeader[0].length);
  const dictionaryExtent = directDictionaryExtent(objectBody);
  const afterDictionary = objectBody.slice(dictionaryExtent.end);
  const endObject = /^\s*endobj\b/.exec(afterDictionary);
  if (!endObject || !onlyWhitespaceAndComments(afterDictionary.slice(endObject[0].length))) throw new Error("PDF encryption object has data outside its direct dictionary");
  const dictionary = dictionaryEntries(objectBody.slice(dictionaryExtent.start, dictionaryExtent.end), "encryption dictionary");
  const filter = entry(dictionary, "Filter");
  if (!filter || filter.length !== 1 || filter[0].kind !== "name" || filter[0].value !== "Standard") throw new Error("PDF uses an unsupported security handler");
  const algorithm = integerEntry(dictionary, "V") ?? 0;
  const revision = integerEntry(dictionary, "R") ?? 0;
  const keyBits = integerEntry(dictionary, "Length", false) ?? 40;
  const permissions = integerEntry(dictionary, "P") ?? 0;
  const metadata = entry(dictionary, "EncryptMetadata", false);
  if (metadata && (metadata.length !== 1 || metadata[0].kind !== "boolean")) throw new Error("PDF /EncryptMetadata must be a boolean");
  const encryptMetadata = metadata?.[0].value !== "false";
  const validRevision = (revision === 2 && algorithm === 1 && keyBits === 40)
    || (revision === 3 && algorithm === 2 && keyBits >= 40 && keyBits <= 128 && keyBits % 8 === 0)
    || (revision === 4 && algorithm === 4 && keyBits === 128)
    || ((revision === 5 || revision === 6) && algorithm === 5 && keyBits === 256);
  if (!validRevision) throw new Error(`PDF standard-security parameters V=${algorithm}, R=${revision}, Length=${keyBits} are unsupported`);
  if (permissions < -0x80000000 || permissions > 0x7fffffff) throw new Error("PDF permissions value is outside the signed 32-bit range");

  const documentId = idValue[1].value;
  if (documentId.length > 2048) throw new Error("PDF document ID exceeds the 1024-byte export limit");
  const credentialBytes = revision >= 5 ? 48 : 32;
  const user = hexEntry(dictionary, "U");
  const owner = hexEntry(dictionary, "O");
  if (!user || !owner || user.length !== credentialBytes || owner.length !== credentialBytes) throw new Error(`PDF /U and /O entries must each be exactly ${credentialBytes} bytes`);
  const fields = [`$pdf$${algorithm}`, revision, keyBits, permissions, encryptMetadata ? 1 : 0, documentId.length / 2, documentId, credentialBytes, hex(user), credentialBytes, hex(owner)];
  let userKeyBytes: number | null = null;
  let ownerKeyBytes: number | null = null;
  if (revision >= 5) {
    const ownerKey = hexEntry(dictionary, "OE");
    const userKey = hexEntry(dictionary, "UE");
    if (!ownerKey || !userKey || ownerKey.length !== 32 || userKey.length !== 32) throw new Error("PDF owner or user encryption-key entry is invalid");
    const perms = hexEntry(dictionary, "Perms");
    if (!perms || perms.length !== 16) throw new Error("PDF /Perms entry must be exactly 16 bytes");
    fields.push(ownerKey.length, hex(ownerKey), userKey.length, hex(userKey));
    ownerKeyBytes = ownerKey.length;
    userKeyBytes = userKey.length;
  }
  if (signal?.aborted) throw signal.reason;
  return {
    version: versionMatch[1], algorithm, revision, keyBits, permissions, encryptMetadata, documentId,
    userEntryBytes: credentialBytes, ownerEntryBytes: credentialBytes, userKeyBytes, ownerKeyBytes,
    hash: fields.join("*"),
  };
}