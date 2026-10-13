import modelUrl from "@tesseract.js-data/eng/4.0.0_best_int/eng.traineddata.gz?url";
import createTesseract from "tesseract.js-core/tesseract-core-simd-lstm.js";
import wasmUrl from "tesseract.js-core/tesseract-core-simd-lstm.wasm?url";
import { MemorySource } from "../../core/bytes/sources";
import { inflate } from "../../core/compression/inflate";
import { once, readPackFile } from "../files";

const OEM_LSTM_ONLY = 1;

export const loadOcr = once(async () => {
  const [wasm, model] = await Promise.all([readPackFile("OCR", wasmUrl), readPackFile("OCR", modelUrl)]);
  // Tesseract reports progress and resolution guesses on stdout/stderr; nothing there is needed.
  const module = await createTesseract({ wasmBinary: wasm, print: () => undefined, printErr: () => undefined });
  // A host may serve the .gz with Content-Encoding: gzip, in which case the browser has already inflated it.
  const gzipped = model[0] === 0x1f && model[1] === 0x8b;
  const bytes = gzipped ? (await inflate(new MemorySource(new Uint8Array(model)), "gzip", { maxOutputBytes: 64 * 1024 * 1024 })).bytes : model;
  module.FS.writeFile("./eng.traineddata", bytes);
  const api = new module.TessBaseAPI();
  if (api.Init(null, "eng", OEM_LSTM_ONLY) !== 0) throw new Error("Tesseract could not load the English model");
  return { module, api };
});

/** One grayscale image (one byte per pixel, row-major). */
export function recognize(ocr: Awaited<ReturnType<typeof loadOcr>>, gray: Uint8Array, width: number, height: number, pageSegMode: number, whitelist: string) {
  const { module, api } = ocr;
  const pointer = module._malloc(gray.length);
  try {
    // HEAPU8 is replaced when malloc grows memory, so read it after allocating.
    module.HEAPU8.set(gray, pointer);
    api.SetImage(pointer, width, height, 1, width);
    api.SetPageSegMode(pageSegMode);
    api.SetVariable("tessedit_char_whitelist", whitelist);
    api.Recognize(null);
    return { text: api.GetUTF8Text(), confidence: api.MeanTextConf() };
  } finally {
    api.Clear();
    module._free(pointer);
  }
}
