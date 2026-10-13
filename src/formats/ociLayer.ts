import type { ByteSource } from "../core/bytes/ByteSource";
import { BlobSource, toBlob } from "../core/bytes/sources";
import { readArchive } from "./archive";

const MAX_LAYER_BYTES = 64 * 1024 * 1024;
const MAX_IMAGE_BYTES = 128 * 1024 * 1024;

export interface OciLayerEntry {
  path: string;
  kind: "file" | "whiteout" | "opaque";
  bytes: number;
  target: string | null;
}

export interface OciLayerReport {
  files: number;
  whiteouts: number;
  opaqueDirectories: number;
  regularFilesOnly: true;
  entries: OciLayerEntry[];
}

export interface OciStackReport {
  layers: number;
  visible: { path: string; bytes: number; layer: number }[];
  hidden: { path: string; layer: number; reason: "whiteout" | "opaque" }[];
  markers: { layer: number; kind: "whiteout" | "opaque"; target: string }[];
}

function safePath(path: string): string {
  if (path.length > 1_024 || path.startsWith("/") || path.includes("\\") || /[\0-\x1f\x7f]/.test(path)) throw new Error("OCI tar member has an unsafe path");
  const components = path.split("/").filter((part) => part !== "" && part !== ".");
  if (components.length === 0 || components.some((part) => part === "..")) throw new Error("OCI tar member has an unsafe path");
  return components.join("/");
}

export async function inspectOciLayer(source: ByteSource, signal?: AbortSignal): Promise<OciLayerReport> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < 512 || source.size > MAX_LAYER_BYTES) throw new Error("OCI tar layer exceeds the 64 MiB input budget");
  const magic = await source.read(257, 5);
  if (new TextDecoder().decode(magic) !== "ustar") throw new Error("OCI layer input must be an uncompressed ustar archive");
  const files = await readArchive(await toBlob(source));
  const entries: OciLayerEntry[] = [];
  const seen = new Set<string>();
  for (const file of files) {
    if (signal?.aborted) throw signal.reason;
    const path = safePath(file.path);
    if (seen.has(path)) throw new Error(`OCI layer contains a repeated tar path: ${path}`);
    seen.add(path);
    const parts = path.split("/");
    const name = parts.pop()!;
    const parent = parts.join("/");
    let kind: OciLayerEntry["kind"] = "file";
    let target: string | null = null;
    if (name === ".wh..wh..opq") {
      kind = "opaque";
      target = parent;
    } else if (name.startsWith(".wh.") && name.length > 4) {
      kind = "whiteout";
      target = parent ? `${parent}/${name.slice(4)}` : name.slice(4);
    }
    if (kind !== "file" && file.size !== 0) throw new Error(`OCI ${kind} marker must be empty: ${path}`);
    entries.push({ path, kind, bytes: file.size, target });
  }
  return {
    files: entries.filter((entry) => entry.kind === "file").length,
    whiteouts: entries.filter((entry) => entry.kind === "whiteout").length,
    opaqueDirectories: entries.filter((entry) => entry.kind === "opaque").length,
    regularFilesOnly: true, entries,
  };
}

export function applyOciLayers(reports: readonly OciLayerReport[]): OciStackReport {
  if (reports.length < 1 || reports.length > 32 || reports.reduce((sum, report) => sum + report.entries.length, 0) > 20_000) throw new Error("OCI layer stack exceeds the bounded manifest budget");
  const visible = new Map<string, OciStackReport["visible"][number]>();
  const hidden: OciStackReport["hidden"] = [];
  const markers: OciStackReport["markers"] = [];
  for (const [layer, report] of reports.entries()) {
    for (const entry of report.entries) {
      if (entry.kind === "file") continue;
      const target = entry.target!;
      markers.push({ layer, kind: entry.kind, target });
      for (const path of visible.keys()) {
        const matches = entry.kind === "opaque"
          ? (target === "" || path.startsWith(`${target}/`))
          : (path === target || path.startsWith(`${target}/`));
        if (matches) {
          visible.delete(path);
          hidden.push({ path, layer, reason: entry.kind });
        }
      }
    }
    for (const entry of report.entries) if (entry.kind === "file") visible.set(entry.path, { path: entry.path, bytes: entry.bytes, layer });
  }
  return { layers: reports.length, visible: [...visible.values()].sort((first, second) => first.path.localeCompare(second.path)), hidden, markers };
}

async function readOciImage(source: ByteSource, manifestIndex: number, signal?: AbortSignal): Promise<{
  report: OciStackReport & { repositoryTags: string[]; manifestIndex: number }; layers: Blob[];
}> {
  if (signal?.aborted) throw signal.reason;
  if (!Number.isSafeInteger(source.size) || source.size < 512 || source.size > MAX_IMAGE_BYTES) throw new Error("OCI image archive exceeds the 128 MiB budget");
  const magic = await source.read(257, 5);
  if (new TextDecoder().decode(magic) !== "ustar") throw new Error("OCI image input must be an uncompressed tar archive");
  const archive = await readArchive(await toBlob(source));
  const members = new Map<string, (typeof archive)[number]>();
  for (const file of archive) {
    const path = safePath(file.path);
    if (members.has(path)) throw new Error(`OCI image archive repeats member ${path}`);
    members.set(path, file);
  }
  const manifest = members.get("manifest.json");
  if (!manifest || manifest.size > 1024 * 1024) throw new Error("Docker-save manifest.json is missing or exceeds 1 MiB");
  let parsed: unknown;
  try { parsed = JSON.parse(await (await manifest.read()).text()); }
  catch { throw new Error("Docker-save manifest.json is invalid JSON"); }
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 16 ||
    !Number.isSafeInteger(manifestIndex) || manifestIndex < 0 || manifestIndex >= parsed.length) throw new Error("Docker-save image index is outside the bounded manifest");
  const item = parsed[manifestIndex];
  if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("Docker-save manifest entry must be an object");
  const image = item as Record<string, unknown>;
  if (!Array.isArray(image.Layers) || image.Layers.length < 1 || image.Layers.length > 32 || image.Layers.some((path) => typeof path !== "string")) throw new Error("Docker-save manifest must list 1 to 32 tar layers");
  if (image.RepoTags !== undefined && (!Array.isArray(image.RepoTags) || image.RepoTags.length > 32 || image.RepoTags.some((tag) => typeof tag !== "string" || tag.length > 256))) throw new Error("Docker-save repository tags are invalid");
  const reports: OciLayerReport[] = [];
  const layers: Blob[] = [];
  for (const layerPath of image.Layers as string[]) {
    if (signal?.aborted) throw signal.reason;
    const file = members.get(safePath(layerPath));
    if (!file || file.size > MAX_LAYER_BYTES) throw new Error(`Docker-save layer is missing or too large: ${layerPath}`);
    const layer = await file.read();
    layers.push(layer);
    reports.push(await inspectOciLayer(new BlobSource(layer), signal));
  }
  return { report: { ...applyOciLayers(reports), repositoryTags: image.RepoTags as string[] ?? [], manifestIndex }, layers };
}

export async function inspectOciImage(source: ByteSource, manifestIndex = 0, signal?: AbortSignal): Promise<OciStackReport & { repositoryTags: string[]; manifestIndex: number }> {
  return (await readOciImage(source, manifestIndex, signal)).report;
}

export async function extractVisibleOciFile(source: ByteSource, path: string, manifestIndex = 0, signal?: AbortSignal): Promise<ByteSource> {
  const { report, layers } = await readOciImage(source, manifestIndex, signal);
  const normalized = safePath(path);
  const entry = report.visible.find((item) => item.path === normalized);
  if (!entry) throw new Error(`OCI file is not visible after layer whiteouts: ${normalized}`);
  const files = await readArchive(layers[entry.layer]);
  const file = files.find((item) => safePath(item.path) === normalized);
  if (!file || file.size !== entry.bytes) throw new Error("OCI visible file no longer matches its layer metadata");
  return new BlobSource(await file.read());
}