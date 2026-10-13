import { useRef, useSyncExternalStore } from "react";
import { formatSize } from "../../core/value";
import { downloadBlob } from "../download";
import { workspace } from "../workspace";

const BUTTON = "rounded border border-slate-300 bg-white px-2 py-0.5 text-xs hover:bg-slate-100 disabled:opacity-50";

export function WorkspaceBar() {
  const state = useSyncExternalStore(workspace.subscribe, workspace.getState);
  const importRef = useRef<HTMLInputElement>(null);
  const saved = state.mode === "saved";
  const busy = state.busy !== null;

  const exportFile = async (includeFiles: boolean) => {
    const result = await workspace.exportFile(includeFiles);
    if (result) downloadBlob(result.blob, result.name);
  };

  const toggleSaving = () => {
    if (!saved) {
      void workspace.enableSaving();
    } else if (confirm("Stop saving and delete the copy saved in this browser? The open session stays until you reload.")) {
      void workspace.disableSaving();
    }
  };

  const status = state.busy
    ? state.busy
    : saved
      ? `Saved in this browser${state.pendingWrites > 0 ? " (writing…)" : ""}${state.usage ? ` · ${formatSize(state.usage.used)} used` : ""}`
      : "Temporary: lost on reload";

  return (
    <div className="flex flex-wrap items-center justify-end gap-2 text-xs text-slate-600">
      <label
        className="flex items-center gap-1"
        title="Saved workspaces live in this browser's private storage. Clearing site data or using a private window loses them; export a .ctfwork file as a backup."
      >
        <input type="checkbox" checked={saved} disabled={busy} onChange={toggleSaving} />
        Save in this browser
      </label>
      <span className={saved ? "text-emerald-700" : "text-amber-700"}>{status}</span>
      {saved && state.usage && !state.usage.persisted && (
        <span title="The browser may delete this data under storage pressure.">(not protected from eviction)</span>
      )}
      <button className={BUTTON} disabled={busy} onClick={() => void exportFile(true)} title="Download everything as a .ctfwork file">
        Export
      </button>
      <button
        className={BUTTON}
        disabled={busy}
        onClick={() => void exportFile(false)}
        title="History and recipes only; file contents are left out"
      >
        Export without files
      </button>
      <button className={BUTTON} disabled={busy} onClick={() => importRef.current?.click()}>
        Import…
      </button>
      <input
        ref={importRef}
        type="file"
        accept=".ctfwork,.zip"
        className="hidden"
        onChange={(event) => {
          const file = event.target.files?.[0];
          event.target.value = "";
          if (file) void workspace.importFile(file);
        }}
      />
      {saved && (
        <button className={BUTTON} disabled={busy} onClick={() => void workspace.freeSpace()}>
          Free space
        </button>
      )}
      <button
        className={BUTTON}
        disabled={busy}
        onClick={() => {
          if (confirm(saved ? "Delete every artifact, run and recipe, including the saved copy?" : "Delete every artifact, run and recipe?")) {
            workspace.clear();
          }
        }}
      >
        Clear
      </button>
      {(state.error ?? state.message) && (
        <span className={`basis-full text-right ${state.error ? "text-red-700" : "text-slate-500"}`}>{state.error ?? state.message}</span>
      )}
    </div>
  );
}
