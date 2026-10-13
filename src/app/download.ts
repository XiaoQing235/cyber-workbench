import type { Artifact } from "../core/artifact/store";
import { toBlob } from "../core/bytes/sources";
import type { Value } from "../core/value";

async function toDownloadBlob(value: Value): Promise<Blob> {
  switch (value.type) {
    case "bytes":
      return toBlob(value.source);
    case "text":
      return new Blob([value.text], { type: "text/plain;charset=utf-8" });
    case "number":
      return new Blob([value.value.toString()], { type: "text/plain" });
    case "structured":
      return new Blob(
        [JSON.stringify(value.data, (_key, item: unknown) => (typeof item === "bigint" ? item.toString() : item), 2)],
        { type: "application/json" },
      );
  }
}

function fileName(artifact: Artifact): string {
  const base = artifact.name.replace(/[^\w.-]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 80) || "artifact";
  if (/\.\w{1,8}$/.test(base)) return base;
  const extension = { bytes: ".bin", text: ".txt", number: ".txt", structured: ".json" }[artifact.value.type];
  return base + extension;
}

/** Saves a blob through a temporary object URL; nothing leaves the browser. */
export function downloadBlob(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

export async function downloadArtifact(artifact: Artifact): Promise<void> {
  downloadBlob(await toDownloadBlob(artifact.value), fileName(artifact));
}
