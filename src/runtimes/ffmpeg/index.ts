import { FFmpeg } from "@ffmpeg/ffmpeg";
import classWorkerURL from "@ffmpeg/ffmpeg/worker?worker&url";
import coreURL from "@ffmpeg/core-mt?url";
import wasmURL from "@ffmpeg/core-mt/wasm?url";
import pthreadSource from "@ffmpeg/core-mt/worker?raw";
import { OperationError } from "../../core/operation/errors";

export async function loadFFmpeg(signal?: AbortSignal): Promise<{ ffmpeg: FFmpeg; dispose: () => void }> {
  if (!globalThis.crossOriginIsolated || typeof SharedArrayBuffer === "undefined") {
    throw new OperationError("UNAVAILABLE", "Threaded FFmpeg needs cross-origin isolation (COOP/COEP) and SharedArrayBuffer");
  }
  const ffmpeg = new FFmpeg();
  const workerURL = URL.createObjectURL(new Blob([pthreadSource], { type: "text/javascript" }));
  const dispose = () => {
    ffmpeg.terminate();
    URL.revokeObjectURL(workerURL);
  };
  try {
    await ffmpeg.load({ classWorkerURL, coreURL: new URL(coreURL, import.meta.url).href, wasmURL: new URL(wasmURL, import.meta.url).href, workerURL }, { signal });
    return { ffmpeg, dispose };
  } catch (error) {
    dispose();
    throw error;
  }
}