import type { ByteSource } from "../core/bytes/ByteSource";
import { BlobSource, toBlob } from "../core/bytes/sources";
import { readZip, zipEntryData } from "../core/archive/zip";

export const MAX_IPA_BYTES = 128 * 1024 * 1024;
const MAX_PLIST_BYTES = 2 * 1024 * 1024;

export interface IpaReport {
  appPath: string;
  bundleId: string;
  executable: string | null;
  displayName: string | null;
  version: string | null;
  build: string | null;
  minimumOS: string | null;
  requiredCapabilities: string[];
  usageDescriptionKeys: string[];
  otherPlistValuesReturned: false;
  binaryPlist: true;
  signatureVerified: false;
  archivedFiles: number;
}

async function entries(source: ByteSource) {
  if (!Number.isSafeInteger(source.size) || source.size < 22 || source.size > MAX_IPA_BYTES) throw new Error("IPA archive exceeds the 128 MiB budget");
  const files = await readZip(await toBlob(source));
  if (files.length > 20_000) throw new Error("IPA archive exceeds 20,000 entries");
  const seen = new Set<string>();
  for (const entry of files) {
    const path = entry.name;
    if (path.length < 1 || path.length > 1_024 || path.startsWith("/") || path.includes("\\") || /[\0-\x1f\x7f\ufffd]/.test(path) || path.split("/").some((part) => part === "." || part === "..")) throw new Error("IPA archive entry path is unsafe");
    if (seen.has(path)) throw new Error(`IPA archive repeats ${path}`);
    seen.add(path);
  }
  return files;
}

export async function inspectIpa(source: ByteSource, signal?: AbortSignal): Promise<IpaReport> {
  if (signal?.aborted) throw signal.reason;
  const files = await entries(source);
  const candidates = files.filter((entry) => /^Payload\/[^/]+\.app\/Info\.plist$/.test(entry.name));
  if (candidates.length !== 1 || candidates[0].size > MAX_PLIST_BYTES) throw new Error("IPA must have exactly one bounded top-level app Info.plist");
  const plist = await zipEntryData(candidates[0], MAX_PLIST_BYTES);
  const bytes = new Uint8Array(await plist.arrayBuffer());
  if (new TextDecoder("ascii").decode(bytes.subarray(0, 8)) !== "bplist00") throw new Error("IPA Info.plist must be a binary plist");
  const [{ Buffer }, parser] = await Promise.all([import("buffer"), import("bplist-parser")]);
  parser.setMaxObjectSize(MAX_PLIST_BYTES);
  parser.setMaxObjectCount(4_096);
  const previousBuffer = globalThis.Buffer;
  globalThis.Buffer = Buffer;
  let parsed: unknown;
  try { [parsed] = parser.parseBuffer(Buffer.from(bytes)); }
  finally { globalThis.Buffer = previousBuffer; }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("IPA Info.plist has no dictionary root");
  const info = parsed as Record<string, unknown>;
  const bounded = (field: string): string | null => {
    const value = info[field];
    return typeof value === "string" && value.length > 0 && value.length <= 512 && !/[\0-\x1f\x7f]/.test(value) ? value : null;
  };
  const bundleId = bounded("CFBundleIdentifier");
  if (!bundleId || !/^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$/.test(bundleId)) throw new Error("IPA bundle identifier is missing or invalid");
  const capabilities = info.UIRequiredDeviceCapabilities;
  const requiredCapabilities = Array.isArray(capabilities) ? capabilities.filter((item): item is string => typeof item === "string" && item.length <= 128).slice(0, 128).sort() : [];
  if (signal?.aborted) throw signal.reason;
  return {
    appPath: candidates[0].name.slice(0, -"Info.plist".length), bundleId,
    executable: bounded("CFBundleExecutable"), displayName: bounded("CFBundleDisplayName"),
    version: bounded("CFBundleShortVersionString"), build: bounded("CFBundleVersion"), minimumOS: bounded("MinimumOSVersion"),
    requiredCapabilities, usageDescriptionKeys: Object.keys(info).filter((key) => /^NS[A-Za-z]+UsageDescription$/.test(key)).sort().slice(0, 128),
    otherPlistValuesReturned: false, binaryPlist: true, signatureVerified: false,
    archivedFiles: files.filter((entry) => !entry.name.endsWith("/")).length,
  };
}

export async function extractIpaEntry(source: ByteSource, path: string, signal?: AbortSignal): Promise<ByteSource> {
  if (signal?.aborted) throw signal.reason;
  await inspectIpa(source, signal);
  const file = (await entries(source)).find((entry) => entry.name === path && !entry.name.endsWith("/"));
  if (!file) throw new Error("IPA entry path is missing");
  if (file.size > 64 * 1024 * 1024) throw new Error("IPA entry exceeds 64 MiB");
  return new BlobSource(await zipEntryData(file, 64 * 1024 * 1024));
}