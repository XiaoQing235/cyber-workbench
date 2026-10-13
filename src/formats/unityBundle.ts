import type { ByteSource, Bytes } from "../core/bytes/ByteSource";
import { readAll } from "../core/bytes/sources";

const MAX_BUNDLE_BYTES = 8 * 1024 * 1024;
const MAX_BLOCK_INFO_BYTES = 512 * 1024;
const MAX_UNPACKED_BYTES = 16 * 1024 * 1024;

export interface UnityBundleReport {
  format: "UnityFS";
  version: 7 | 8;
  unityRevision: string;
  packedBytes: number;
  unpackedBytes: number;
  files: { path: string; bytes: number }[];
  assets: { type: string; name: string; path: string | null; pathId: string; bytes: number }[];
}

function readCString(bytes: Uint8Array, offset: number): { text: string; next: number } {
  const end = bytes.indexOf(0, offset);
  if (end < offset || end > offset + 128 || end >= bytes.length) throw new Error("UnityFS version string is unterminated or too long");
  return { text: new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(offset, end)), next: end + 1 };
}

async function loadBounded(source: ByteSource, signal?: AbortSignal) {
  if (signal?.aborted) throw signal.reason;
  const bytes = await readAll(source, MAX_BUNDLE_BYTES);
  if (bytes.length < 48 || !bytes.subarray(0, 8).every((byte, index) => byte === [85, 110, 105, 116, 121, 70, 83, 0][index])) {
    throw new Error("Only standalone UnityFS bundles are supported");
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = view.getUint32(8);
  if (version !== 7 && version !== 8) throw new Error(`UnityFS format version ${version} is unsupported`);
  const unityVersion = readCString(bytes, 12);
  const revision = readCString(bytes, unityVersion.next);
  if (revision.next + 20 > bytes.length) throw new Error("UnityFS header is truncated");
  const totalBytes = view.getBigUint64(revision.next);
  const compressedInfo = view.getUint32(revision.next + 8);
  const uncompressedInfo = view.getUint32(revision.next + 12);
  const flags = view.getUint32(revision.next + 16);
  if (totalBytes !== BigInt(bytes.length) || compressedInfo < 20 || compressedInfo > MAX_BLOCK_INFO_BYTES ||
    uncompressedInfo < 20 || uncompressedInfo > MAX_BLOCK_INFO_BYTES || compressedInfo > bytes.length - revision.next - 20) {
    throw new Error("UnityFS bundle extent or blocks-info budget is invalid");
  }
  const { decompressLz4, load } = await import("unity-asset-reader");
  const infoOffset = (flags & 0x80) ? bytes.length - compressedInfo : (revision.next + 20 + 15) & ~15;
  if (infoOffset < revision.next + 20 || infoOffset + compressedInfo > bytes.length) throw new Error("UnityFS blocks-info offset is invalid");
  const encoded = bytes.subarray(infoOffset, infoOffset + compressedInfo);
  const compression = flags & 0x3f;
  const metadata = compression === 0 ? encoded : (compression === 2 || compression === 3) ? decompressLz4(encoded, uncompressedInfo) : null;
  if (!metadata || metadata.length !== uncompressedInfo) throw new Error("UnityFS blocks-info compression is unsupported or inconsistent");
  const blockView = new DataView(metadata.buffer, metadata.byteOffset, metadata.byteLength);
  const count = blockView.getUint32(16);
  if (count < 1 || count > 4_096 || 20 + count * 10 > metadata.length) throw new Error("UnityFS block count exceeds the budget");
  let unpackedBytes = 0;
  let packedBytes = 0;
  for (let index = 0; index < count; index++) {
    unpackedBytes += blockView.getUint32(20 + index * 10);
    packedBytes += blockView.getUint32(24 + index * 10);
    if (unpackedBytes > MAX_UNPACKED_BYTES || packedBytes > bytes.length) throw new Error("UnityFS decompressed blocks exceed the 16 MiB budget");
  }
  if (signal?.aborted) throw signal.reason;
  const env = load(bytes);
  return { env, revision: revision.text, version: version as 7 | 8, unpackedBytes };
}

export async function inspectUnityBundle(source: ByteSource, signal?: AbortSignal): Promise<UnityBundleReport> {
  const { env, revision, version, unpackedBytes } = await loadBounded(source, signal);
  if (env.files.length > 1_024) throw new Error("UnityFS contains too many unpacked files");
  const assets: UnityBundleReport["assets"] = [];
  for (const asset of env.assets()) {
    if (signal?.aborted) throw signal.reason;
    if (assets.length >= 4_096) throw new Error("UnityFS contains too many assets");
    assets.push({ type: asset.type, name: asset.name, path: asset.path ?? null, pathId: asset.pathId.toString(), bytes: asset.byteSize });
  }
  return { format: "UnityFS", version, unityRevision: revision, packedBytes: source.size, unpackedBytes,
    files: env.files.map((file) => ({ path: file.path, bytes: file.data.length })), assets };
}

export async function extractUnityTextAsset(source: ByteSource, path: string, signal?: AbortSignal): Promise<{ data: Bytes; name: string }> {
  if (!path || path.length > 512) throw new Error("Unity TextAsset requires a bounded project path");
  const { env } = await loadBounded(source, signal);
  const asset = [...env.assets("TextAsset")].find((entry) => entry.path === path);
  if (!asset) throw new Error(`Unity TextAsset ${path} does not exist in the bundle`);
  const bytes = asset.data.bytes;
  if (bytes.length > 1 * 1024 * 1024) throw new Error("Unity TextAsset exceeds the 1 MiB extraction budget");
  if (signal?.aborted) throw signal.reason;
  return { data: new Uint8Array(bytes), name: asset.name };
}