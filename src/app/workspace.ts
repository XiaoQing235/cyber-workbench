import { exportCtfwork, importCtfwork } from "../core/workspace/ctfwork";
import { IdbMetaStore } from "../core/workspace/idb";
import { OpfsBlobStore } from "../core/workspace/opfs";
import { WorkspacePersistence } from "../core/workspace/persistence";
import { formatSize } from "../core/value";
import { store } from "./services";

const SAVE_KEY = "ctf-workbench.save";
const APP = "CTF Workbench 0.1.0";

export interface WorkspaceState {
  mode: "temporary" | "saved";
  busy: string | null;
  message: string | null;
  error: string | null;
  pendingWrites: number;
  usage: { used: number; quota: number; persisted: boolean } | null;
}

const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? "" : "s"}`;

/** Owns the choice between a temporary session and a workspace saved in this browser. */
class WorkspaceController {
  private state: WorkspaceState = { mode: "temporary", busy: null, message: null, error: null, pendingWrites: 0, usage: null };
  private readonly listeners = new Set<() => void>();
  private opening: Promise<WorkspacePersistence | null> | null = null;
  private started = false;

  readonly subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  };

  readonly getState = (): WorkspaceState => this.state;

  /** Restores the saved workspace, if the user chose to save. Safe to call more than once. */
  start(): Promise<void> {
    if (this.started || localStorage.getItem(SAVE_KEY) !== "1") return Promise.resolve();
    this.started = true;
    return this.act("Restoring the saved workspace…", async () => {
      const persistence = await this.open();
      if (!persistence) {
        localStorage.removeItem(SAVE_KEY);
        throw new Error("This browser cannot save workspaces (no Origin Private File System), so this session is temporary");
      }
      const summary = await persistence.restore();
      this.set({ mode: "saved" });
      const problems = [
        summary.missingFiles > 0 ? `${plural(summary.missingFiles, "file")} missing` : "",
        summary.orphans > 0 ? `${plural(summary.orphans, "record")} without their source skipped` : "",
      ].filter(Boolean);
      return `Restored ${plural(summary.artifacts, "artifact")}${problems.length ? ` (${problems.join("; ")})` : ""}.`;
    });
  }

  enableSaving(): Promise<void> {
    return this.act("Saving the workspace…", async () => {
      const persistence = await this.open();
      if (!persistence) throw new Error("This browser cannot save workspaces (no Origin Private File System)");
      await navigator.storage.persist?.().catch(() => false);
      await persistence.enable();
      localStorage.setItem(SAVE_KEY, "1");
      this.set({ mode: "saved" });
      return "Saved. The workspace now survives reloads.";
    });
  }

  disableSaving(): Promise<void> {
    return this.act("Deleting the saved copy…", async () => {
      await (await this.open())?.disable();
      localStorage.removeItem(SAVE_KEY);
      this.set({ mode: "temporary" });
      return "No longer saving. The saved copy was deleted; this session stays open until you reload.";
    });
  }

  exportFile(includeFiles: boolean): Promise<{ blob: Blob; name: string } | null> {
    let result: { blob: Blob; name: string } | null = null;
    return this.act("Exporting…", async () => {
      const blob = await exportCtfwork(store, { includeFiles, app: APP });
      const date = new Date().toISOString().slice(0, 10);
      result = { blob, name: `workspace-${date}${includeFiles ? "" : "-no-files"}.ctfwork` };
      return `Exported ${formatSize(blob.size)}${includeFiles ? "" : " (history and recipes only)"}.`;
    }).then(() => result);
  }

  importFile(file: File): Promise<void> {
    return this.act(`Importing ${file.name}…`, async () => {
      const summary = await importCtfwork(store, file);
      const notes = [
        summary.skipped > 0 ? `${summary.skipped} already present` : "",
        summary.missingFiles > 0 ? `${plural(summary.missingFiles, "file")} not included` : "",
        summary.orphans > 0 ? `${plural(summary.orphans, "record")} without their source skipped` : "",
      ].filter(Boolean);
      return `Imported ${plural(summary.artifacts, "artifact")} and ${plural(summary.recipes, "recipe")}${notes.length ? ` (${notes.join("; ")})` : ""}.`;
    });
  }

  freeSpace(): Promise<void> {
    return this.act("Looking for unused files…", async () => {
      const persistence = await this.open();
      if (!persistence?.active) return "Nothing is saved in this browser.";
      const freed = await persistence.collectGarbage();
      return freed.files === 0 ? "No unused files." : `Deleted ${plural(freed.files, "unused file")} (${formatSize(freed.bytes)}).`;
    });
  }

  /** Empties the workspace; when saving, the saved copy is emptied too. */
  clear(): void {
    store.clear();
    this.set({ message: "Workspace cleared.", error: null });
    void this.refreshUsage();
  }

  async refreshUsage(): Promise<void> {
    if (!navigator.storage?.estimate) return;
    const [estimate, persisted] = await Promise.all([
      navigator.storage.estimate(),
      navigator.storage.persisted?.() ?? Promise.resolve(false),
    ]);
    this.set({ usage: { used: estimate.usage ?? 0, quota: estimate.quota ?? 0, persisted } });
  }

  private async act(busy: string, work: () => Promise<string>): Promise<void> {
    this.set({ busy, message: null, error: null });
    try {
      this.set({ busy: null, message: await work() });
    } catch (error) {
      this.set({ busy: null, error: error instanceof Error ? error.message : String(error) });
    }
    await this.refreshUsage().catch(() => undefined);
  }

  private open(): Promise<WorkspacePersistence | null> {
    this.opening ??= (async () => {
      const blobs = await OpfsBlobStore.open();
      if (!blobs || typeof indexedDB === "undefined") return null;
      const persistence = new WorkspacePersistence(store, await IdbMetaStore.open(), blobs);
      persistence.subscribe(() => {
        const status = persistence.getStatus();
        this.set({ pendingWrites: status.pending, ...(status.error ? { error: status.error } : {}) });
      });
      return persistence;
    })();
    return this.opening;
  }

  private set(update: Partial<WorkspaceState>): void {
    this.state = { ...this.state, ...update };
    for (const listener of this.listeners) listener();
  }
}

export const workspace = new WorkspaceController();
