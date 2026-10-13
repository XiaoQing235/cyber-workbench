import { readFileSync } from "node:fs";
import { defineConfig } from "vitest/config";
import type { Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Dev only: preview applies public/_headers (CSP included); dev cannot, as Vite's dev client uses inline scripts.
const isolationHeaders = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
};

const MB = 1024 * 1024;
/** Each Runtime Pack (all of its JS and WASM/data files) must stay within its budget. */
const PACK_BUDGETS: Record<string, number> = { python: 15 * MB, ffmpeg: 36 * MB, wiregasm: 80 * MB };
const DEFAULT_PACK_BUDGET = 10 * MB;

const PYODIDE_DIR = new URL("./node_modules/pyodide/", import.meta.url);
const PYODIDE_VERSION = (JSON.parse(readFileSync(new URL("package.json", PYODIDE_DIR), "utf8")) as { version: string }).version;

/** Source locations of each Runtime Pack; their build outputs are named assets/pack-<id>-<hash>.<ext>. */
const PACK_SOURCES: readonly [RegExp, string][] = [
  [/\/src\/runtimes\/([a-z]+)\//, "$1"],
  [/bkcrack\.wasm$/, "bkcrack"],
  [/node_modules\/sql\.js\//, "sqlite"],
  [/node_modules\/@alexaltea\/capstone-js\//, "capstone"],
  [/node_modules\/(tesseract\.js-core|@tesseract\.js-data\/eng)\//, "ocr"],
  [/node_modules\/pyodide\//, "python"],
  [/node_modules\/@ffmpeg\/(ffmpeg|core-mt)\//, "ffmpeg"],
  [/node_modules\/@goodtools\/wiregasm\//, "wiregasm"],
  [/node_modules\/ws\/browser\.js$/, "wiregasm"],
];

function packOf(id: string): string | null {
  const path = id.replace(/\\/g, "/");
  for (const [pattern, pack] of PACK_SOURCES) {
    const match = pattern.exec(path);
    if (match) return pack.replace("$1", match[1] ?? "");
  }
  return null;
}

/** A chunk belongs to a pack only if all of its real modules do, so shared code never leaves the core cache. */
function chunkPack(moduleIds: readonly string[]): string | null {
  // Virtual modules (including Vite's stub for Node built-ins) and the shared helpers in src/runtimes/*.ts may sit in any pack's chunk.
  const neutral = (id: string) =>
    id.startsWith("\0") || id.startsWith("__vite-browser-external") || /\/src\/runtimes\/[^/]+$/.test(id.replace(/\\/g, "/"));
  const packs = new Set(moduleIds.filter((id) => !neutral(id)).map(packOf));
  return packs.size === 1 ? [...packs][0] : null;
}

const naming = {
  entryFileNames: (chunk: { moduleIds: string[] }) => {
    const pack = chunkPack(chunk.moduleIds);
    return pack ? `assets/pack-${pack}-[hash].js` : "assets/[name]-[hash].js";
  },
  chunkFileNames: (chunk: { moduleIds: string[] }) => {
    const pack = chunkPack(chunk.moduleIds);
    return pack ? `assets/pack-${pack}-[hash].js` : "assets/[name]-[hash].js";
  },
  assetFileNames: (asset: { originalFileNames: string[] }) => {
    const pack = asset.originalFileNames.map(packOf).find(Boolean);
    return pack ? `assets/pack-${pack}-[hash][extname]` : "assets/[name]-[hash][extname]";
  },
};

function fnv1a(text: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) hash = Math.imul(hash ^ text.charCodeAt(i), 0x01000193);
  return (hash >>> 0).toString(16).padStart(8, "0");
}

/**
 * Emits sw.js precaching exactly this build's core files, and packs.json listing each Runtime Pack's
 * files. Packs are never precached: they are cached on first use or by "download for offline".
 */
function offlineServiceWorker(): Plugin {
  return {
    name: "ctf-offline-service-worker",
    apply: "build",
    generateBundle(_options, bundle) {
      const packs: Record<string, { files: string[]; bytes: number }> = {};
      const core: string[] = ["index.html", "licenses/GPL-2.0.txt"];
      for (const [name, output] of Object.entries(bundle)) {
        if (name.endsWith(".map")) continue;
        const pack = /^assets\/pack-([a-z]+)-/.exec(name)?.[1];
        if (!pack) {
          core.push(name);
          continue;
        }
        // Operations are also bundled into the main thread for their specs; its copies of pack code are never loaded.
        if (output.type === "chunk") continue;
        const entry = (packs[pack] ??= { files: [], bytes: 0 });
        entry.files.push(name);
        entry.bytes += typeof output.source === "string" ? new TextEncoder().encode(output.source).byteLength : output.source.byteLength;
      }
      for (const [id, pack] of Object.entries(packs)) {
        pack.files.sort();
        const budget = PACK_BUDGETS[id] ?? DEFAULT_PACK_BUDGET;
        if (pack.bytes > budget) {
          this.error(`Runtime Pack "${id}" is ${(pack.bytes / MB).toFixed(1)} MB; its budget is ${budget / MB} MB`);
        }
      }
      const files = [...new Set(core)].sort();
      const packFiles = Object.values(packs).flatMap((pack) => pack.files);
      const cache = `ctf-workbench-${fnv1a(files.join("\n"))}`;
      this.emitFile({ type: "asset", fileName: "packs.json", source: JSON.stringify({ packs }, null, 2) });
      this.emitFile({
        type: "asset",
        fileName: "sw.js",
        source: `const CACHE = ${JSON.stringify(cache)};
const FILES = ${JSON.stringify(["./", ...files.map((name) => `./${name}`)])};
const PACKS = "ctf-packs";
const PACK_FILES = new Set(${JSON.stringify(packFiles)});

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(FILES)));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(keys.filter((key) => key.startsWith("ctf-workbench-") && key !== CACHE).map((key) => caches.delete(key)));
      // Pack files are content-addressed: drop the ones this version no longer uses.
      const packs = await caches.open(PACKS);
      for (const request of await packs.keys()) {
        if (!PACK_FILES.has(new URL(request.url).pathname.replace(/^.*?(assets\\/pack-)/, "$1"))) await packs.delete(request);
      }
      // Only reached when no older version controls a tab, so claiming cannot mix versions.
      await self.clients.claim();
    })(),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  const url = new URL(request.url);
  if (request.method !== "GET" || url.origin !== self.location.origin) return;
  if (url.pathname.includes("/assets/pack-")) {
    // Cache on first use, so a pack that has run once keeps working offline.
    event.respondWith(
      caches.open(PACKS).then(async (cache) => {
        const cached = await cache.match(request, { ignoreVary: true });
        if (cached) return cached;
        const response = await fetch(request);
        if (response.ok) await cache.put(request, response.clone());
        return response;
      }),
    );
    return;
  }
  // Precached files are content-addressed, so Vary (e.g. Origin on module scripts) must not prevent a match.
  const options = { cacheName: CACHE, ignoreVary: true };
  if (request.mode === "navigate") {
    // Network first so a new deployment is picked up; the cached shell keeps working offline.
    event.respondWith(fetch(request).catch(() => caches.match("./index.html", options)));
    return;
  }
  event.respondWith(caches.match(request, options).then((cached) => cached ?? fetch(request)));
});
`,
      });
    },
  };
}

/** Pack code mixed into a core file would be precached for everyone and missing from the pack's offline download. */
function packGuard(): Plugin {
  return {
    name: "ctf-pack-guard",
    apply: "build",
    generateBundle(_options, bundle) {
      for (const output of Object.values(bundle)) {
        const ids = output.type === "chunk" ? output.moduleIds : output.originalFileNames;
        const pack = ids.map(packOf).find(Boolean);
        if (pack && !output.fileName.startsWith(`assets/pack-${pack}-`)) {
          this.error(`${output.fileName} mixes Runtime Pack "${pack}" code with core code (modules: ${ids.join(", ")})`);
        }
      }
    },
  };
}

/** Pyodide loads these by fixed name from its index URL, so they are copied under a versioned pack folder. */
function pyodideFiles(): Plugin {
  return {
    name: "ctf-pyodide-files",
    apply: "build",
    generateBundle() {
      for (const name of ["pyodide.asm.mjs", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json"]) {
        this.emitFile({ type: "asset", fileName: `assets/pack-python-${PYODIDE_VERSION}/${name}`, source: readFileSync(new URL(name, PYODIDE_DIR)) });
      }
    },
  };
}

interface HeaderRule {
  pattern: RegExp;
  set: [string, string][];
  detach: string[];
}

/** The subset of the _headers format (Netlify / Cloudflare Pages) used here: path rules, headers and "! Name" to detach. */
function parseHeaders(text: string): HeaderRule[] {
  const rules: HeaderRule[] = [];
  for (const raw of text.split("\n")) {
    const line = raw.trimEnd();
    if (!line.trim() || line.trim().startsWith("#")) continue;
    if (!/^\s/.test(line)) {
      const source = line.trim().replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
      rules.push({ pattern: new RegExp(`^${source}$`), set: [], detach: [] });
      continue;
    }
    const rule = rules.at(-1);
    const detach = /^\s*!\s*(\S+)/.exec(line);
    const header = /^\s*([^:\s]+):\s*(.*)$/.exec(line);
    if (rule && detach) rule.detach.push(detach[1].toLowerCase());
    else if (rule && header) rule.set.push([header[1], header[2]]);
  }
  return rules;
}

/** Serves preview with the production headers, so CSP problems show up locally. */
function productionHeaders(): Plugin {
  return {
    name: "ctf-production-headers",
    configurePreviewServer(server) {
      const rules = parseHeaders(readFileSync(new URL("./public/_headers", import.meta.url), "utf8"));
      server.middlewares.use((request, response, next) => {
        const path = new URL(request.url ?? "/", "http://localhost").pathname;
        const headers = new Map<string, [string, string]>();
        for (const rule of rules.filter((item) => item.pattern.test(path))) {
          for (const name of rule.detach) headers.delete(name);
          for (const [name, value] of rule.set) headers.set(name.toLowerCase(), [name, value]);
        }
        for (const [name, value] of headers.values()) response.setHeader(name, value);
        next();
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), tailwindcss(), packGuard(), pyodideFiles(), offlineServiceWorker(), productionHeaders()],
  define: { __PYODIDE_VERSION__: JSON.stringify(PYODIDE_VERSION) },
  server: { headers: isolationHeaders },
  worker: { format: "es", plugins: () => [packGuard()], rolldownOptions: { output: naming } },
  // Test fixtures (a packed git repository, pack WASM and data) are imported as data URLs (?inline).
  assetsInclude: ["**/*.tar", "**/*.pck", "**/*.pkg", "**/*.onnx", "**/*.wasm", "**/*.traineddata.gz"],
  build: { target: "es2022", sourcemap: true, rolldownOptions: { output: naming } },
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
