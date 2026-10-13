/** SQLite file header and freelist, read directly (no engine needed). See https://sqlite.org/fileformat.html */

export interface SqliteHeader {
  pageSize: number;
  writeVersion: number;
  readVersion: number;
  reservedBytes: number;
  changeCounter: number;
  /** In-header database size in pages (valid only when versionValidFor equals changeCounter). */
  pageCount: number;
  firstFreelistTrunk: number;
  freelistCount: number;
  schemaCookie: number;
  schemaFormat: number;
  textEncoding: string;
  userVersion: number;
  vacuum: "none" | "full" | "incremental";
  applicationId: number;
  versionValidFor: number;
  sqliteVersion: string;
}

const MAGIC = "SQLite format 3\0";

export function isSqlite(bytes: Uint8Array): boolean {
  return bytes.length >= 100 && MAGIC.split("").every((char, i) => bytes[i] === char.charCodeAt(0));
}

export function parseSqliteHeader(bytes: Uint8Array): SqliteHeader | null {
  if (!isSqlite(bytes)) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, 100);
  const rawPageSize = view.getUint16(16);
  const version = view.getUint32(96);
  return {
    pageSize: rawPageSize === 1 ? 65536 : rawPageSize,
    writeVersion: bytes[18],
    readVersion: bytes[19],
    reservedBytes: bytes[20],
    changeCounter: view.getUint32(24),
    pageCount: view.getUint32(28),
    firstFreelistTrunk: view.getUint32(32),
    freelistCount: view.getUint32(36),
    schemaCookie: view.getUint32(40),
    schemaFormat: view.getUint32(44),
    textEncoding: ["unknown", "UTF-8", "UTF-16le", "UTF-16be"][view.getUint32(56)] ?? "unknown",
    userVersion: view.getUint32(60),
    vacuum: view.getUint32(52) === 0 ? "none" : view.getUint32(64) !== 0 ? "incremental" : "full",
    applicationId: view.getUint32(68),
    versionValidFor: view.getUint32(92),
    sqliteVersion: `${Math.floor(version / 1_000_000)}.${Math.floor(version / 1000) % 1000}.${version % 1000}`,
  };
}

/** Page numbers (1-based) of the freelist: trunk pages and the leaf pages they list. Stops on loops or bad pointers. */
export function freelistPages(bytes: Uint8Array, header: SqliteHeader, limit = 1_000_000): { pages: number[]; problem?: string } {
  const pages: number[] = [];
  const seen = new Set<number>();
  const totalPages = Math.floor(bytes.length / header.pageSize);
  const valid = (page: number) => page >= 2 && page <= totalPages && !seen.has(page);
  let trunk = header.firstFreelistTrunk;
  while (trunk !== 0) {
    if (!valid(trunk)) return { pages, problem: `freelist trunk pointer ${trunk} is invalid or repeats` };
    seen.add(trunk);
    pages.push(trunk);
    const offset = (trunk - 1) * header.pageSize;
    const view = new DataView(bytes.buffer, bytes.byteOffset + offset, header.pageSize);
    const leaves = view.getUint32(4);
    if (leaves > header.pageSize / 4 - 2) return { pages, problem: `trunk page ${trunk} claims ${leaves} leaves` };
    for (let i = 0; i < leaves; i++) {
      const leaf = view.getUint32(8 + i * 4);
      if (!valid(leaf)) return { pages, problem: `leaf pointer ${leaf} on trunk page ${trunk} is invalid or repeats` };
      seen.add(leaf);
      pages.push(leaf);
    }
    if (pages.length > limit) return { pages, problem: `more than ${limit} free pages` };
    trunk = view.getUint32(0);
  }
  return { pages };
}
