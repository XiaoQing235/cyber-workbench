import { BlobSource, MemorySource } from "../core/bytes/sources";
import { inflate } from "../core/compression/inflate";
import type { ArchiveFile } from "./archive";

export type GitObjectType = "commit" | "tree" | "blob" | "tag";
export interface GitObject {
  type: GitObjectType;
  content: Uint8Array;
}

export interface Commit {
  id: string;
  tree: string;
  parents: string[];
  author: string;
  time: number;
  message: string;
}

export interface TreeEntry {
  mode: string;
  name: string;
  id: string;
}

export class GitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GitError";
  }
}

const TYPES: Record<number, GitObjectType> = { 1: "commit", 2: "tree", 3: "blob", 4: "tag" };
const MAX_OBJECT = 256 * 1024 * 1024;
const hex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
const decoder = new TextDecoder();

interface Pack {
  bytes: Uint8Array;
  /** Entry offsets in ascending order; an entry's data runs to the next one. */
  offsets: number[];
  idAt: Map<number, string>;
}

type Location = { kind: "loose"; file: ArchiveFile } | { kind: "pack"; pack: Pack; offset: number };

function parseIndex(idx: Uint8Array, packSize: number): { offsets: number[]; idAt: Map<number, string> } {
  const view = new DataView(idx.buffer, idx.byteOffset, idx.byteLength);
  if (view.getUint32(0) !== 0xff744f63 || view.getUint32(4) !== 2) throw new GitError("Only version 2 pack indexes are supported");
  const count = view.getUint32(8 + 255 * 4);
  const names = 8 + 256 * 4;
  const offsetsAt = names + count * 24;
  const largeAt = offsetsAt + count * 4;
  const idAt = new Map<number, string>();
  for (let i = 0; i < count; i++) {
    let offset = view.getUint32(offsetsAt + i * 4);
    if (offset & 0x80000000) offset = Number(view.getBigUint64(largeAt + (offset & 0x7fffffff) * 8));
    idAt.set(offset, hex(idx.subarray(names + i * 20, names + i * 20 + 20)));
  }
  const offsets = [...idAt.keys()].sort((a, b) => a - b);
  if (offsets.some((offset) => offset >= packSize)) throw new GitError("The pack index does not match its pack");
  return { offsets, idAt };
}

export function applyDelta(base: Uint8Array, delta: Uint8Array): Uint8Array {
  let pos = 0;
  const varint = () => {
    let value = 0;
    let shift = 0;
    let byte: number;
    do {
      byte = delta[pos++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    } while (byte & 0x80);
    return value;
  };
  if (varint() !== base.length) throw new GitError("Delta base has the wrong size");
  const out = new Uint8Array(varint());
  let at = 0;
  while (pos < delta.length) {
    const op = delta[pos++];
    if (op & 0x80) {
      let offset = 0;
      let size = 0;
      for (let i = 0; i < 4; i++) if (op & (1 << i)) offset += delta[pos++] * 2 ** (8 * i);
      for (let i = 0; i < 3; i++) if (op & (1 << (4 + i))) size += delta[pos++] * 2 ** (8 * i);
      if (size === 0) size = 0x10000;
      out.set(base.subarray(offset, offset + size), at);
      at += size;
    } else if (op > 0) {
      out.set(delta.subarray(pos, pos + op), at);
      at += op;
      pos += op;
    } else {
      throw new GitError("Invalid delta instruction");
    }
  }
  if (at !== out.length) throw new GitError("Delta produced the wrong size");
  return out;
}

async function inflateExact(data: Uint8Array, size: number): Promise<Uint8Array> {
  // The limit is checked per output chunk before stopAfter, so leave room for one chunk past `size`.
  const result = await inflate(new MemorySource(new Uint8Array(data)), "zlib", { maxOutputBytes: size + 4 * 1024 * 1024, stopAfter: size });
  if (result.bytes.length < size) throw new GitError(`Object data is damaged (${result.error ?? "too short"})`);
  return result.bytes.subarray(0, size);
}

export class GitRepository {
  readonly files: Map<string, ArchiveFile>;
  private readonly locations = new Map<string, Location>();
  private readonly cache = new Map<string, GitObject>();
  private readonly packCache = new Map<string, GitObject>();
  packCount = 0;

  private constructor(files: Map<string, ArchiveFile>) {
    this.files = files;
  }

  /** Finds the git directory (".git/" or a bare repository) among the uploaded files. */
  static async open(all: readonly ArchiveFile[]): Promise<GitRepository> {
    const head = all.find((file) => /(^|\/)\.git\/HEAD$/.test(file.path)) ?? all.find((file) => /(^|\/)HEAD$/.test(file.path) && all.some((other) => other.path.startsWith(file.path.slice(0, -4) + "objects/")));
    if (!head) throw new GitError("No .git directory (no HEAD file) in this archive");
    const root = head.path.slice(0, -4);
    const files = new Map(all.filter((file) => file.path.startsWith(root)).map((file) => [file.path.slice(root.length), file]));
    const repository = new GitRepository(files);
    for (const [path, file] of files) {
      const loose = /^objects\/([0-9a-f]{2})\/([0-9a-f]{38})$/.exec(path);
      if (loose) repository.locations.set(loose[1] + loose[2], { kind: "loose", file });
      const pack = /^objects\/pack\/(.+)\.pack$/.exec(path);
      const index = pack && files.get(`objects/pack/${pack[1]}.idx`);
      if (pack && index) {
        const bytes = new Uint8Array(await (await file.read()).arrayBuffer());
        const { offsets, idAt } = parseIndex(new Uint8Array(await (await index.read()).arrayBuffer()), bytes.length);
        const entry: Pack = { bytes, offsets, idAt };
        for (const [offset, id] of idAt) if (!repository.locations.has(id)) repository.locations.set(id, { kind: "pack", pack: entry, offset });
        repository.packCount++;
      }
    }
    return repository;
  }

  get objectIds(): string[] {
    return [...this.locations.keys()];
  }

  /** Full id for a unique prefix of at least 4 hex digits. */
  resolve(prefix: string): string {
    const wanted = prefix.trim().toLowerCase();
    if (!/^[0-9a-f]{4,40}$/.test(wanted)) throw new GitError(`"${prefix}" is not an object id`);
    const matches = this.objectIds.filter((id) => id.startsWith(wanted));
    if (matches.length !== 1) throw new GitError(matches.length === 0 ? `No object ${prefix}` : `${prefix} is ambiguous (${matches.length} objects)`);
    return matches[0];
  }

  /** The object's type without decompressing its content (deltas follow their base). */
  async typeOf(id: string): Promise<GitObjectType> {
    const location = this.locations.get(id);
    if (!location) throw new GitError(`Object ${id} is not in this repository`);
    if (location.kind === "loose") {
      const head = await inflate(new BlobSource(await location.file.read()), "zlib", { maxOutputBytes: 1024 * 1024, stopAfter: 32 });
      const type = decoder.decode(head.bytes.subarray(0, 32)).split(" ")[0];
      if (!["commit", "tree", "blob", "tag"].includes(type)) throw new GitError(`Object ${id} has unknown type "${type}"`);
      return type as GitObjectType;
    }
    return this.packedType(location.pack, location.offset, 0);
  }

  private async packedType(pack: Pack, offset: number, depth: number): Promise<GitObjectType> {
    if (depth > 64) throw new GitError("Delta chain too long");
    const bytes = pack.bytes;
    let pos = offset;
    let byte = bytes[pos++];
    const type = (byte >> 4) & 7;
    while (byte & 0x80) byte = bytes[pos++];
    if (TYPES[type]) return TYPES[type];
    if (type === 7) return this.typeOf(hex(bytes.subarray(pos, pos + 20)));
    if (type !== 6) throw new GitError(`Unknown pack entry type ${type} at offset ${offset}`);
    byte = bytes[pos++];
    let distance = byte & 0x7f;
    while (byte & 0x80) {
      byte = bytes[pos++];
      distance = (distance + 1) * 128 + (byte & 0x7f);
    }
    return this.packedType(pack, offset - distance, depth + 1);
  }

  async read(id: string): Promise<GitObject> {
    const cached = this.cache.get(id);
    if (cached) return cached;
    const location = this.locations.get(id);
    if (!location) throw new GitError(`Object ${id} is not in this repository`);
    let object: GitObject;
    if (location.kind === "loose") {
      const inflated = await inflate(new BlobSource(await location.file.read()), "zlib", { maxOutputBytes: MAX_OBJECT });
      if (inflated.error) throw new GitError(`Loose object ${id} is damaged: ${inflated.error}`);
      const raw = inflated.bytes;
      const nul = raw.indexOf(0);
      const [type, size] = decoder.decode(raw.subarray(0, nul)).split(" ");
      if (!["commit", "tree", "blob", "tag"].includes(type)) throw new GitError(`Object ${id} has unknown type "${type}"`);
      object = { type: type as GitObjectType, content: raw.subarray(nul + 1, nul + 1 + Number(size)) };
    } else {
      object = await this.readPacked(location.pack, location.offset, 0);
    }
    this.cache.set(id, object);
    return object;
  }

  private async readPacked(pack: Pack, offset: number, depth: number): Promise<GitObject> {
    const key = `${pack.offsets[0]}:${pack.bytes.length}:${offset}`;
    const hit = this.packCache.get(key);
    if (hit) return hit;
    if (depth > 64) throw new GitError("Delta chain too long");
    const bytes = pack.bytes;
    let pos = offset;
    let byte = bytes[pos++];
    const type = (byte >> 4) & 7;
    let size = byte & 15;
    for (let shift = 4; byte & 0x80; shift += 7) {
      byte = bytes[pos++];
      size += (byte & 0x7f) * 2 ** shift;
    }
    let base: GitObject | null = null;
    if (type === 6) {
      byte = bytes[pos++];
      let distance = byte & 0x7f;
      while (byte & 0x80) {
        byte = bytes[pos++];
        distance = (distance + 1) * 128 + (byte & 0x7f);
      }
      base = await this.readPacked(pack, offset - distance, depth + 1);
    } else if (type === 7) {
      base = await this.read(hex(bytes.subarray(pos, pos + 20)));
      pos += 20;
    } else if (!TYPES[type]) {
      throw new GitError(`Unknown pack entry type ${type} at offset ${offset}`);
    }
    const next = pack.offsets.find((candidate) => candidate > offset) ?? bytes.length - 20;
    const data = await inflateExact(bytes.subarray(pos, next), size);
    const object: GitObject = base ? { type: base.type, content: applyDelta(base.content, data) } : { type: TYPES[type], content: data };
    this.packCache.set(key, object);
    return object;
  }

  async text(path: string): Promise<string | null> {
    const file = this.files.get(path);
    return file ? (await file.read()).text() : null;
  }

  /** Branches, tags, HEAD, stash and other refs, loose and packed. */
  async refs(): Promise<Map<string, string>> {
    const refs = new Map<string, string>();
    for (const line of ((await this.text("packed-refs")) ?? "").split("\n")) {
      const match = /^([0-9a-f]{40}) (\S+)/.exec(line);
      if (match) refs.set(match[2], match[1]);
    }
    for (const [path] of this.files) {
      if (!path.startsWith("refs/") && !["ORIG_HEAD", "FETCH_HEAD", "MERGE_HEAD", "CHERRY_PICK_HEAD"].includes(path)) continue;
      const match = /^([0-9a-f]{40})/.exec(((await this.text(path)) ?? "").trim());
      if (match) refs.set(path, match[1]);
    }
    const head = ((await this.text("HEAD")) ?? "").trim();
    const symbolic = /^ref: (\S+)/.exec(head);
    const target = symbolic ? refs.get(symbolic[1]) : /^[0-9a-f]{40}$/.test(head) ? head : undefined;
    if (target) refs.set("HEAD", target);
    return refs;
  }

  /** Every commit id named in any reflog (logs/HEAD, logs/refs/…), oldest first, with its message. */
  async reflog(): Promise<{ ref: string; from: string; to: string; message: string }[]> {
    const entries: { ref: string; from: string; to: string; message: string }[] = [];
    for (const [path] of this.files) {
      if (!path.startsWith("logs/")) continue;
      for (const line of ((await this.text(path)) ?? "").split("\n")) {
        const match = /^([0-9a-f]{40}) ([0-9a-f]{40}) [^\t]*\t?(.*)$/.exec(line);
        if (match) entries.push({ ref: path.slice(5), from: match[1], to: match[2], message: match[3] });
      }
    }
    return entries;
  }

  async commit(id: string): Promise<Commit> {
    const object = await this.read(id);
    if (object.type !== "commit") throw new GitError(`${id} is a ${object.type}, not a commit`);
    const text = decoder.decode(object.content);
    const split = text.indexOf("\n\n");
    const headers = text.slice(0, split < 0 ? text.length : split).split("\n");
    const field = (name: string) => headers.filter((line) => line.startsWith(`${name} `)).map((line) => line.slice(name.length + 1));
    const author = field("author")[0] ?? "";
    return {
      id,
      tree: field("tree")[0] ?? "",
      parents: field("parent"),
      author: author.replace(/ \d+ [+-]\d{4}$/, ""),
      time: Number(/ (\d+) [+-]\d{4}$/.exec(author)?.[1] ?? 0),
      message: split < 0 ? "" : text.slice(split + 2).trim(),
    };
  }

  async tree(id: string): Promise<TreeEntry[]> {
    const { type, content } = await this.read(id);
    if (type !== "tree") throw new GitError(`${id} is a ${type}, not a tree`);
    const entries: TreeEntry[] = [];
    for (let at = 0; at < content.length; ) {
      const space = content.indexOf(0x20, at);
      const nul = content.indexOf(0, space);
      entries.push({ mode: decoder.decode(content.subarray(at, space)), name: decoder.decode(content.subarray(space + 1, nul)), id: hex(content.subarray(nul + 1, nul + 21)) });
      at = nul + 21;
    }
    return entries;
  }

  /** path → blob id for every file under a tree. Missing subtrees are skipped. */
  async listFiles(treeId: string, prefix = ""): Promise<Map<string, string>> {
    const out = new Map<string, string>();
    let entries: TreeEntry[];
    try {
      entries = await this.tree(treeId);
    } catch {
      return out;
    }
    for (const entry of entries) {
      if (entry.mode === "40000") for (const [path, id] of await this.listFiles(entry.id, `${prefix}${entry.name}/`)) out.set(path, id);
      else if (entry.mode !== "160000") out.set(`${prefix}${entry.name}`, entry.id);
    }
    return out;
  }
}
