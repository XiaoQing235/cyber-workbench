import { OperationError } from "../core/operation/errors";

/** Shared by all Runtime Packs (src/runtimes/<pack>/), which load only inside workers. */

type Reader = (url: string) => Promise<Uint8Array>;

async function fetchFile(url: string): Promise<Uint8Array> {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

let reader: Reader = fetchFile;

/** Tests run without a server, so they supply pack files directly. */
export function setPackFileReader(next: Reader): void {
  reader = next;
}

const unavailable = (pack: string, error: unknown) =>
  new OperationError(
    "UNAVAILABLE",
    `The ${pack} pack could not be loaded (${error instanceof Error ? error.message : String(error)}). ` +
      "If you are offline, download it under Runtime packs next time you are online.",
  );

export async function readPackFile(pack: string, url: string): Promise<Uint8Array> {
  try {
    return await reader(url);
  } catch (error) {
    throw unavailable(pack, error);
  }
}

/** Imports a pack's code; a failed download (offline, not cached) becomes UNAVAILABLE rather than INTERNAL. */
export async function importPack<T>(pack: string, load: () => Promise<T>): Promise<T> {
  try {
    return await load();
  } catch (error) {
    if (error instanceof OperationError) throw error;
    throw unavailable(pack, error);
  }
}

/** Initialises a pack once per worker; a failed attempt is retried on the next use. */
export function once<T>(load: () => Promise<T>): () => Promise<T> {
  let pending: Promise<T> | undefined;
  return () => {
    pending ??= load().catch((error: unknown) => {
      pending = undefined;
      throw error;
    });
    return pending;
  };
}
