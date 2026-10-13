import { useCallback, useEffect, useState } from "react";
import { formatSize } from "../../core/value";
import { PACKS } from "../../runtimes/catalog";

/** Must match the service worker's pack cache. */
const PACK_CACHE = "ctf-packs";
const BUTTON = "rounded border border-slate-300 bg-white px-2 py-0.5 text-xs hover:bg-slate-100 disabled:opacity-50";

interface Manifest {
  packs: Record<string, { files: string[]; bytes: number }>;
}

const fileUrl = (file: string) => new URL(file, new URL(import.meta.env.BASE_URL, location.href)).href;

async function cachedCount(files: readonly string[]): Promise<number> {
  const cache = await caches.open(PACK_CACHE);
  const hits = await Promise.all(files.map((file) => cache.match(fileUrl(file), { ignoreVary: true })));
  return hits.filter(Boolean).length;
}

/** Runtime Packs: what each costs, its licences, and whether it is available offline. */
export function PacksPanel() {
  const [manifest, setManifest] = useState<Manifest | null>(null);
  const [cached, setCached] = useState<Record<string, number>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const available = import.meta.env.PROD && typeof caches !== "undefined";

  const refresh = useCallback(async (current: Manifest) => {
    const entries = await Promise.all(Object.entries(current.packs).map(async ([id, pack]) => [id, await cachedCount(pack.files)] as const));
    setCached(Object.fromEntries(entries));
  }, []);

  useEffect(() => {
    if (!available) return;
    let cancelled = false;
    void fetch(fileUrl("packs.json"))
      .then((response) => (response.ok ? (response.json() as Promise<Manifest>) : null))
      .then((loaded) => {
        if (cancelled || !loaded) return;
        setManifest(loaded);
        void refresh(loaded);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [available, refresh]);

  const download = async (id: string) => {
    if (!manifest) return;
    setBusy(id);
    setProblem(null);
    try {
      const cache = await caches.open(PACK_CACHE);
      for (const file of manifest.packs[id].files) {
        if (!(await cache.match(fileUrl(file), { ignoreVary: true }))) await cache.add(fileUrl(file));
      }
    } catch (error) {
      setProblem(`Download failed: ${error instanceof Error ? error.message : String(error)}`);
    } finally {
      setBusy(null);
      await refresh(manifest);
    }
  };

  const remove = async (id: string) => {
    if (!manifest) return;
    const cache = await caches.open(PACK_CACHE);
    await Promise.all(manifest.packs[id].files.map((file) => cache.delete(fileUrl(file), { ignoreVary: true })));
    await refresh(manifest);
  };

  return (
    // Packs are also cached on first use, so re-check whenever the panel is opened.
    <details className="text-sm" onToggle={(event) => event.currentTarget.open && manifest && void refresh(manifest)}>
      <summary className="cursor-pointer font-semibold">Runtime packs</summary>
      <p className="mt-1 text-xs text-slate-500">
        Heavy engines download on first use and are then kept for offline work. Nothing here runs until an operation needs it.
      </p>
      <ul className="mt-2 flex flex-col gap-2">
        {PACKS.map((pack) => {
          const files = manifest?.packs[pack.id];
          const have = cached[pack.id] ?? 0;
          const complete = files !== undefined && have === files.files.length;
          return (
            <li key={pack.id} className="rounded border border-slate-200 p-2">
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-medium">{pack.title}</span>
                {files && <span className="text-xs text-slate-500">{formatSize(files.bytes)}</span>}
              </div>
              <p className="text-xs text-slate-600">{pack.description}</p>
              <details className="text-xs text-slate-500">
                <summary className="cursor-pointer">Licences</summary>
                <ul>
                  {pack.licences.map((item) => (
                    <li key={item.component}>
                      {item.component}:{" "}
                      <a className="text-sky-700 hover:underline" href={item.url} target="_blank" rel="noreferrer">
                        {item.licence}
                      </a>
                    </li>
                  ))}
                </ul>
              </details>
              {files ? (
                <div className="mt-1 flex items-center gap-2 text-xs">
                  <span className={complete ? "text-emerald-700" : "text-slate-500"}>
                    {complete ? "Available offline" : have > 0 ? `${have} of ${files.files.length} files kept` : "Not downloaded"}
                  </span>
                  <span className="ml-auto flex gap-1">
                    {!complete && (
                      <button className={BUTTON} disabled={busy !== null} onClick={() => void download(pack.id)}>
                        {busy === pack.id ? "Downloading…" : "Download for offline"}
                      </button>
                    )}
                    {have > 0 && (
                      <button className={BUTTON} disabled={busy !== null} onClick={() => void remove(pack.id)}>
                        Remove
                      </button>
                    )}
                  </span>
                </div>
              ) : (
                <p className="mt-1 text-xs text-slate-500">{available ? "Loading…" : "Served by the dev server; offline download is in production builds."}</p>
              )}
            </li>
          );
        })}
      </ul>
      {problem && <p className="mt-1 text-xs text-red-700">{problem}</p>}
    </details>
  );
}
