import type { ByteSource } from "../core/bytes/ByteSource";
import { BlobSource, toBlob } from "../core/bytes/sources";
import { readZip, zipEntryData } from "../core/archive/zip";

const MAX_ARCHIVE_BYTES = 128 * 1024 * 1024;
const MAX_EXTRACT_BYTES = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 1024 * 1024;

export interface JavaArchiveReport {
  manifest: { version: string | null; mainClass: string | null; automaticModuleName: string | null } | null;
  firstClassMajor: number | null;
  classes: number;
  signatures: string[];
  signatureVerified: false;
  entries: { path: string; bytes: number; compressedBytes: number; classFile: boolean }[];
}

function safePath(path: string): string {
  if (path.length < 1 || path.length > 1_024 || path.startsWith("/") || path.includes("\\") || path.includes("\ufffd") || /[\0-\x1f\x7f]/.test(path)) throw new Error("JAR entry path is unsafe or undecodable");
  const parts = path.split("/");
  if (parts.some((part) => part === "." || part === "..") || path.includes("//")) throw new Error("JAR entry path contains traversal segments");
  return path;
}

async function entries(source: ByteSource) {
  if (!Number.isSafeInteger(source.size) || source.size < 22 || source.size > MAX_ARCHIVE_BYTES) throw new Error("JAR archive exceeds the 128 MiB input budget");
  const files = await readZip(await toBlob(source));
  if (files.length > 10_000) throw new Error("JAR archive exceeds the 10,000-entry budget");
  const seen = new Set<string>();
  for (const file of files) {
    safePath(file.name);
    if (seen.has(file.name)) throw new Error(`JAR contains duplicate path ${file.name}`);
    seen.add(file.name);
  }
  return files;
}

function manifestFields(text: string): NonNullable<JavaArchiveReport["manifest"]> {
  const lines: string[] = [];
  for (const line of text.replace(/\r\n/g, "\n").split("\n")) {
    if (line === "") break;
    if (line.startsWith(" ")) {
      if (lines.length === 0) throw new Error("JAR manifest continuation has no field");
      lines[lines.length - 1] += line.slice(1);
    } else lines.push(line);
  }
  const values = new Map<string, string>();
  for (const line of lines) {
    const separator = line.indexOf(": ");
    if (separator < 1) throw new Error("JAR manifest field is malformed");
    const key = line.slice(0, separator).toLowerCase();
    if (values.has(key)) throw new Error(`JAR manifest repeats ${key}`);
    values.set(key, line.slice(separator + 2));
  }
  const bounded = (key: string): string | null => {
    const value = values.get(key);
    if (value === undefined) return null;
    if (value.length > 512 || /[\0-\x1f\x7f]/.test(value)) throw new Error(`JAR manifest ${key} exceeds the metadata budget`);
    return value;
  };
  return { version: bounded("manifest-version"), mainClass: bounded("main-class"), automaticModuleName: bounded("automatic-module-name") };
}

export async function inspectJavaArchive(source: ByteSource, signal?: AbortSignal): Promise<JavaArchiveReport> {
  if (signal?.aborted) throw signal.reason;
  const files = await entries(source);
  const manifestEntry = files.find((entry) => entry.name.toUpperCase() === "META-INF/MANIFEST.MF");
  let manifest: JavaArchiveReport["manifest"] = null;
  if (manifestEntry) {
    if (manifestEntry.size > MAX_MANIFEST_BYTES) throw new Error("JAR manifest exceeds the 1 MiB budget");
    const data = await zipEntryData(manifestEntry, MAX_MANIFEST_BYTES);
    manifest = manifestFields(new TextDecoder("utf-8", { fatal: true }).decode(await data.arrayBuffer()));
  }
  const firstClass = files.find((entry) => entry.name.endsWith(".class") && !entry.name.endsWith("/"));
  let firstClassMajor: number | null = null;
  if (firstClass && firstClass.size <= 2 * 1024 * 1024) {
    const data = new Uint8Array(await (await zipEntryData(firstClass, 2 * 1024 * 1024)).arrayBuffer());
    if (data.length < 8 || new DataView(data.buffer).getUint32(0, false) !== 0xcafebabe) throw new Error(`JAR class ${firstClass.name} has invalid magic`);
    firstClassMajor = new DataView(data.buffer).getUint16(6, false);
  }
  const listed = files.filter((entry) => !entry.name.endsWith("/")).map((entry) => ({
    path: entry.name, bytes: entry.size, compressedBytes: entry.compressedSize, classFile: entry.name.endsWith(".class"),
  }));
  return {
    manifest, firstClassMajor, classes: listed.filter((entry) => entry.classFile).length,
    signatures: listed.filter((entry) => /^META-INF\/[^/]+\.(SF|RSA|DSA|EC)$/i.test(entry.path)).map((entry) => entry.path),
    signatureVerified: false, entries: listed,
  };
}

export async function extractJavaEntry(source: ByteSource, path: string, signal?: AbortSignal): Promise<ByteSource> {
  if (signal?.aborted) throw signal.reason;
  const name = safePath(path);
  const file = (await entries(source)).find((entry) => entry.name === name && !entry.name.endsWith("/"));
  if (!file) throw new Error("JAR file path is missing");
  if (file.size > MAX_EXTRACT_BYTES) throw new Error("JAR file exceeds the 64 MiB extraction budget");
  return new BlobSource(await zipEntryData(file, MAX_EXTRACT_BYTES));
}