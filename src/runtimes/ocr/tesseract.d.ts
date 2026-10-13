// Minimal typings for tesseract.js-core 6 (an Emscripten module with WebIDL bindings).
declare module "tesseract.js-core/tesseract-core-simd-lstm.js" {
  export interface TessBaseAPI {
    Init(datapath: string | null, language: string, oem: number): number;
    SetImage(pointer: number, width: number, height: number, bytesPerPixel: number, bytesPerLine: number): void;
    SetPageSegMode(mode: number): void;
    SetVariable(name: string, value: string): boolean;
    Recognize(monitor: null): number;
    GetUTF8Text(): string;
    MeanTextConf(): number;
    Clear(): void;
  }

  export interface TesseractModule {
    TessBaseAPI: new () => TessBaseAPI;
    FS: { writeFile(path: string, data: Uint8Array): void };
    HEAPU8: Uint8Array;
    _malloc(size: number): number;
    _free(pointer: number): void;
  }

  export default function createTesseract(module?: {
    wasmBinary?: Uint8Array;
    print?: (text: string) => void;
    printErr?: (text: string) => void;
  }): Promise<TesseractModule>;
}
