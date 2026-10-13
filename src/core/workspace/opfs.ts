import { SHA256_HEX, type BlobStore } from "./records";

function checkHash(hash: string): void {
  if (!SHA256_HEX.test(hash)) throw new Error(`Invalid content hash ${JSON.stringify(hash)}`);
}

/** Content-addressed files in the Origin Private File System, one file per SHA-256. */
export class OpfsBlobStore implements BlobStore {
  private readonly directory: FileSystemDirectoryHandle;

  private constructor(directory: FileSystemDirectoryHandle) {
    this.directory = directory;
  }

  /** Null when the browser lacks OPFS with writable streams (workspace mode is then unavailable). */
  static async open(): Promise<OpfsBlobStore | null> {
    if (typeof navigator === "undefined" || typeof navigator.storage?.getDirectory !== "function") return null;
    if (typeof FileSystemFileHandle === "undefined" || !("createWritable" in FileSystemFileHandle.prototype)) return null;
    try {
      const root = await navigator.storage.getDirectory();
      return new OpfsBlobStore(await root.getDirectoryHandle("blobs", { create: true }));
    } catch {
      return null;
    }
  }

  async has(hash: string): Promise<boolean> {
    return (await this.get(hash)) !== undefined;
  }

  async put(hash: string, data: Blob): Promise<void> {
    checkHash(hash);
    const handle = await this.directory.getFileHandle(hash, { create: true });
    // The writable commits on close, so an interrupted write never leaves a partial file.
    await data.stream().pipeTo(await handle.createWritable());
  }

  async get(hash: string): Promise<Blob | undefined> {
    checkHash(hash);
    try {
      return await (await this.directory.getFileHandle(hash)).getFile();
    } catch (error) {
      if (error instanceof DOMException && error.name === "NotFoundError") return undefined;
      throw error;
    }
  }

  async delete(hash: string): Promise<void> {
    checkHash(hash);
    try {
      await this.directory.removeEntry(hash);
    } catch (error) {
      if (!(error instanceof DOMException && error.name === "NotFoundError")) throw error;
    }
  }

  async list(): Promise<string[]> {
    const names: string[] = [];
    for await (const name of this.directory.keys()) if (SHA256_HEX.test(name)) names.push(name);
    return names;
  }
}
