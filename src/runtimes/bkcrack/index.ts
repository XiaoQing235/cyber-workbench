import createBkcrack, { type BkcrackModule } from "./bkcrack.js";
import wasmUrl from "./bkcrack.wasm?url";
import { once, readPackFile } from "../files";

export interface BkcrackKeys {
  x: number;
  y: number;
  z: number;
}

export interface BkcrackSession {
  total: number;
  step(count: number): "found" | "complete" | "running";
  cursor(): number;
  keys(): BkcrackKeys | null;
  reset(): void;
}

export const loadBkcrack = once(async (): Promise<BkcrackModule> => {
  const module = await createBkcrack({ wasmBinary: await readPackFile("bkcrack", wasmUrl) });
  if (module._bk_self_test() !== 1) throw new Error(`bkcrack self-test failed: ${module.UTF8ToString(module._bk_error())}`);
  return module;
});

function copy(module: BkcrackModule, bytes: Uint8Array): number {
  const pointer = module._malloc(bytes.length);
  if (pointer === 0 && bytes.length > 0) throw new Error("bkcrack could not allocate input memory");
  module.writeArrayToMemory(bytes, pointer);
  return pointer;
}

export function prepareBkcrack(module: BkcrackModule, cipher: Uint8Array, plain: Uint8Array, plainOffset: number): BkcrackSession {
  const cipherPointer = copy(module, cipher);
  let plainPointer = 0;
  let total: number;
  try {
    plainPointer = copy(module, plain);
    try { total = module._bk_prepare(cipherPointer, cipher.length, plainPointer, plain.length, plainOffset); }
    catch (caught) { throw new Error(`bkcrack native prepare failed for ${plain.length} known bytes: ${String(caught)}`); }
  } finally {
    module._free(cipherPointer);
    module._free(plainPointer);
  }
  if (total < 0) {
    const error = module.UTF8ToString(module._bk_error());
    module._bk_reset();
    throw new Error(error);
  }
  let found = false;
  return {
    total,
    step(count) {
      let status: number;
      try { status = module._bk_step(count); }
      catch (caught) { throw new Error(`bkcrack native step failed for ${plain.length} known bytes: ${String(caught)}`); }
      if (status < 0) throw new Error(module.UTF8ToString(module._bk_error()));
      found = status === 1;
      return found ? "found" : status === 0 ? "complete" : "running";
    },
    cursor: () => module._bk_cursor(),
    keys: () => found ? { x: module._bk_key_x() >>> 0, y: module._bk_key_y() >>> 0, z: module._bk_key_z() >>> 0 } : null,
    reset: () => module._bk_reset(),
  };
}