// Minimal typings for capstone.js 5 (an Emscripten module).
declare module "@alexaltea/capstone-js" {
  export interface Instruction {
    id: number;
    /** Read as a signed 64-bit value. */
    address: bigint;
    size: number;
    bytes: number[];
    mnemonic: string;
    op_str: string;
  }

  export interface Capstone {
    option(option: number, value: number): void;
    disasm(buffer: Uint8Array, address: number | bigint, max?: number): Instruction[];
    close(): void;
  }

  export type CapstoneModule = { Capstone: new (arch: number, mode: number) => Capstone } & Record<string, unknown>;

  export default function createCapstone(module?: { wasmBinary?: Uint8Array }): Promise<CapstoneModule>;
}
