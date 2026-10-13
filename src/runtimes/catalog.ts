/** Runtime Pack metadata for the UI. Pack code lives in src/runtimes/<id>/ and is loaded only in workers. */

export interface PackInfo {
  id: string;
  title: string;
  description: string;
  operations: readonly string[];
  licences: readonly { component: string; licence: string; url: string }[];
}

export const PACKS: readonly PackInfo[] = [
  {
    id: "wiregasm",
    title: "Wiregasm (Wireshark)",
    description: "Wireshark 4.6 dissectors compiled to WebAssembly for bounded, filtered deep-PCAP inspection (~73 MiB).",
    operations: ["pcap.deep-inspect"],
    licences: [
      { component: "@goodtools/wiregasm 2.0.0 and Wireshark", licence: "GPL-2.0-or-later (licence text)", url: "licenses/GPL-2.0.txt" },
      { component: "@goodtools/wiregasm 2.0.0", licence: "Upstream source", url: "https://github.com/good-tools/wiregasm/tree/v2.0.0" },
    ],
  },
  {
    id: "ffmpeg",
    title: "FFmpeg (threaded)",
    description: "Threaded FFmpeg 0.12.10 WebAssembly (~32 MiB) for bounded audio extraction; requires cross-origin isolation.",
    operations: ["audio.ffmpeg.wav"],
    licences: [
      { component: "@ffmpeg/ffmpeg 0.12.15", licence: "MIT", url: "https://github.com/ffmpegwasm/ffmpeg.wasm/blob/main/LICENSE" },
      { component: "@ffmpeg/core-mt 0.12.10 (FFmpeg)", licence: "GPL-2.0-or-later (licence text)", url: "licenses/GPL-2.0.txt" },
      { component: "@ffmpeg/core-mt 0.12.10", licence: "Upstream source", url: "https://github.com/ffmpegwasm/ffmpeg.wasm/tree/71aa99d37c02a7b4c435275ca9ef50e612f6efa1/packages/core-mt" },
    ],
  },
  {
    id: "bkcrack",
    title: "bkcrack",
    description: "bkcrack 1.8.1 compiled to WebAssembly for traditional ZipCrypto known-plaintext recovery.",
    operations: ["archive.zip.known-plaintext"],
    licences: [
      { component: "bkcrack 1.8.1", licence: "Zlib", url: "https://github.com/kimci86/bkcrack/blob/v1.8.1/license.txt" },
    ],
  },
  {
    id: "sqlite",
    title: "SQLite",
    description: "sql.js (SQLite compiled to WebAssembly) for querying database files.",
    operations: ["sqlite.inspect", "sqlite.query", "sqlite.value"],
    licences: [
      { component: "sql.js 1.14.2", licence: "MIT", url: "https://github.com/sql-js/sql.js/blob/master/LICENSE" },
      { component: "SQLite", licence: "Public domain", url: "https://sqlite.org/copyright.html" },
    ],
  },
  {
    id: "capstone",
    title: "Capstone disassembler",
    description: "Capstone 5 compiled to WebAssembly: x86, ARM, ARM64, MIPS, PowerPC, RISC-V, SPARC, 68k, 6502 and more.",
    operations: ["code.disasm"],
    licences: [
      { component: "capstone.js 5.0.9", licence: "BSD-3-Clause", url: "https://github.com/AlexAltea/capstone.js" },
      { component: "Capstone", licence: "BSD-3-Clause", url: "https://github.com/capstone-engine/capstone/blob/next/LICENSE.TXT" },
    ],
  },
  {
    id: "ocr",
    title: "OCR (Tesseract, English)",
    description: "Tesseract 5 LSTM engine compiled to WebAssembly, with the English best_int model.",
    operations: ["ocr.recognize"],
    licences: [
      { component: "tesseract.js-core 6.1.2", licence: "Apache-2.0", url: "https://github.com/naptha/tesseract.js-core" },
      { component: "Tesseract", licence: "Apache-2.0", url: "https://github.com/tesseract-ocr/tesseract" },
      { component: "Leptonica", licence: "BSD-2-Clause", url: "http://leptonica.org/about-the-license.html" },
      { component: "tessdata_best eng", licence: "Apache-2.0", url: "https://github.com/tesseract-ocr/tessdata_best" },
    ],
  },
  {
    id: "python",
    title: "Python (Pyodide)",
    description: "CPython 3.14 compiled to WebAssembly, with the standard library, for your own scripts. Runs in an isolated worker.",
    operations: ["python.run"],
    licences: [
      { component: "Pyodide 314.0.7", licence: "MPL-2.0", url: "https://github.com/pyodide/pyodide/blob/main/LICENSE" },
      { component: "CPython", licence: "PSF-2.0", url: "https://docs.python.org/3/license.html" },
    ],
  },
];
