// Minimal typings for the parts of sql.js the SQLite pack uses.
declare module "sql.js" {
  export type SqlValue = number | bigint | string | Uint8Array | null;

  export interface Statement {
    step(): boolean;
    get(params?: null, config?: { useBigInt?: boolean }): SqlValue[];
    getColumnNames(): string[];
    getSQL(): string;
    free(): boolean;
  }

  export interface Database {
    iterateStatements(sql: string): IterableIterator<Statement>;
    getRowsModified(): number;
    run(sql: string, params?: SqlValue[]): Database;
    export(): Uint8Array;
    close(): void;
  }

  export interface SqlJsStatic {
    Database: new (data?: Uint8Array) => Database;
  }

  export default function initSqlJs(config?: { wasmBinary?: Uint8Array }): Promise<SqlJsStatic>;
}
