export interface BkcrackModule {
  UTF8ToString(pointer: number): string;
  writeArrayToMemory(bytes: Uint8Array, pointer: number): void;
  _malloc(size: number): number;
  _free(pointer: number): void;
  _bk_error(): number;
  _bk_reset(): void;
  _bk_prepare(cipher: number, cipherSize: number, plain: number, plainSize: number, plainOffset: number): number;
  _bk_step(count: number): number;
  _bk_cursor(): number;
  _bk_key_x(): number;
  _bk_key_y(): number;
  _bk_key_z(): number;
  _bk_self_test(): number;
}

export default function createBkcrack(options: { wasmBinary: Uint8Array }): Promise<BkcrackModule>;