import type { ByteSource } from "../core/bytes/ByteSource";
import { BlobSource, readAll, toBlob } from "../core/bytes/sources";
import { readZip, zipEntryData } from "../core/archive/zip";

export const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
export const MAX_APK_BYTES = 128 * 1024 * 1024;

export interface AndroidManifestReport {
  packageName: string;
  versionCode: string | null;
  minSdk: string | null;
  targetSdk: string | null;
  permissions: string[];
  application: { debuggable: string | null; allowBackup: string | null; usesCleartextTraffic: string | null } | null;
  exportedComponents: { kind: string; name: string }[];
  binaryXmlBytes: number;
  decodedAttributeValuesOnly: true;
}

export interface ApkReport {
  manifest: AndroidManifestReport;
  dexFiles: { path: string; bytes: number }[];
  nativeLibraries: number;
  signatureArtifacts: string[];
  signatureVerified: false;
}

export async function inspectAndroidManifest(source: ByteSource, signal?: AbortSignal): Promise<AndroidManifestReport> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < 8 || source.size > MAX_MANIFEST_BYTES) throw new Error("Android binary manifest exceeds the 4 MiB budget");
  const bytes = await readAll(source, MAX_MANIFEST_BYTES);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint16(0, true) !== 3 || view.getUint16(2, true) !== 8 || view.getUint32(4, true) !== bytes.length) throw new Error("Android binary manifest has invalid XML boundaries");
  const [{ Buffer }, { parseAxml }] = await Promise.all([import("buffer"), import("android-axml-parser")]);
  const previousBuffer = globalThis.Buffer;
  globalThis.Buffer = Buffer;
  let document: ReturnType<typeof parseAxml>;
  try { document = parseAxml(Buffer.from(bytes)); }
  finally { globalThis.Buffer = previousBuffer; }
  if (document.root?.name !== "manifest") throw new Error("Android binary XML has no manifest root");
  const root = document.root;
  const value = (node: typeof root, attribute: string): string | null => {
    const text = node.attributes.find((item) => item.name === attribute)?.value;
    if (text === undefined || text.length > 512 || /[\0-\x1f\x7f]/.test(text)) return null;
    return text;
  };
  const packageName = value(root, "package");
  if (!packageName || !/^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$/.test(packageName)) throw new Error("Android package name is missing or invalid");
  const permissions: string[] = [];
  const exportedComponents: AndroidManifestReport["exportedComponents"] = [];
  let application: AndroidManifestReport["application"] = null;
  let minSdk: string | null = null;
  let targetSdk: string | null = null;
  if (root.children.length > 4_096) throw new Error("Android manifest exceeds the element budget");
  for (const child of root.children) {
    if (signal?.aborted) throw signal.reason;
    if (child.name === "uses-permission") {
      const permission = value(child, "name");
      if (permission) permissions.push(permission);
    } else if (child.name === "uses-sdk") {
      minSdk = value(child, "minSdkVersion");
      targetSdk = value(child, "targetSdkVersion");
    } else if (child.name === "application") {
      application = { debuggable: value(child, "debuggable"), allowBackup: value(child, "allowBackup"), usesCleartextTraffic: value(child, "usesCleartextTraffic") };
      if (child.children.length > 2_048) throw new Error("Android application component count exceeds the budget");
      for (const component of child.children) {
        if (!["activity", "service", "receiver", "provider"].includes(component.name) || value(component, "exported") !== "true") continue;
        const name = value(component, "name");
        if (name) exportedComponents.push({ kind: component.name, name });
      }
    }
  }
  if (permissions.length > 512 || exportedComponents.length > 512) throw new Error("Android manifest exceeds permission or exported-component budgets");
  return { packageName, versionCode: value(root, "versionCode"), minSdk, targetSdk, permissions,
    application, exportedComponents, binaryXmlBytes: source.size, decodedAttributeValuesOnly: true };
}

async function apkEntries(source: ByteSource) {
  if (!Number.isSafeInteger(source.size) || source.size < 22 || source.size > MAX_APK_BYTES) throw new Error("APK exceeds the 128 MiB input budget");
  const files = await readZip(await toBlob(source));
  if (files.length > 20_000) throw new Error("APK exceeds the 20,000-entry budget");
  const names = new Set<string>();
  for (const entry of files) {
    const path = entry.name;
    if (path.length < 1 || path.length > 1_024 || path.startsWith("/") || path.includes("\\") || /[\0-\x1f\x7f\ufffd]/.test(path) || path.split("/").some((part) => part === "." || part === "..")) throw new Error("APK entry path is unsafe");
    if (names.has(path)) throw new Error(`APK repeats entry ${path}`);
    names.add(path);
  }
  return files;
}

export async function inspectApk(source: ByteSource, signal?: AbortSignal): Promise<ApkReport> {
  if (signal?.aborted) throw signal.reason;
  const entries = await apkEntries(source);
  const manifestEntry = entries.find((entry) => entry.name === "AndroidManifest.xml");
  if (!manifestEntry || manifestEntry.size > MAX_MANIFEST_BYTES) throw new Error("APK has no bounded AndroidManifest.xml");
  const manifest = await inspectAndroidManifest(new BlobSource(await zipEntryData(manifestEntry, MAX_MANIFEST_BYTES)), signal);
  const dexFiles = entries.filter((entry) => /^classes(?:[2-9]\d*)?\.dex$/.test(entry.name)).map((entry) => ({ path: entry.name, bytes: entry.size }));
  if (dexFiles.length > 256) throw new Error("APK contains too many DEX files");
  dexFiles.sort((first, second) => first.path.localeCompare(second.path, undefined, { numeric: true }));
  return {
    manifest, dexFiles, nativeLibraries: entries.filter((entry) => /^lib\/[^/]+\/[^/]+\.so$/.test(entry.name)).length,
    signatureArtifacts: entries.filter((entry) => /^META-INF\/[^/]+\.(SF|RSA|DSA|EC)$/i.test(entry.name)).map((entry) => entry.name),
    signatureVerified: false,
  };
}

export async function extractApkDex(source: ByteSource, index: number, signal?: AbortSignal): Promise<ByteSource> {
  const report = await inspectApk(source, signal);
  if (!Number.isSafeInteger(index) || index < 0 || index >= report.dexFiles.length) throw new Error("APK DEX index is out of range");
  const file = (await apkEntries(source)).find((entry) => entry.name === report.dexFiles[index].path)!;
  if (file.size > 64 * 1024 * 1024) throw new Error("APK DEX exceeds the 64 MiB extraction budget");
  return new BlobSource(await zipEntryData(file, 64 * 1024 * 1024));
}